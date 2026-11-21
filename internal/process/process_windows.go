//go:build windows

// Package process runs hidden children in kill-on-close Windows jobs. The job
// attribute is applied atomically at process creation, leaving no orphan window.
package process

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Child struct {
	mu          sync.Mutex
	job, handle windows.Handle
	done        chan struct{}
	err         error
	pid         uint32
}

func Start(exe string, args []string, line func(string)) (*Child, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			windows.CloseHandle(job)
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, err
	}
	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	const jobListAttribute = 0x0002000D // PROC_THREAD_ATTRIBUTE_JOB_LIST (Windows 10+)
	if err = attrs.Update(jobListAttribute, unsafe.Pointer(&job), unsafe.Sizeof(job)); err != nil {
		return nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer w.Close()
	defer func() {
		if !success {
			r.Close()
		}
	}()
	nul, err := os.Open(os.DevNull)
	if err != nil {
		return nil, err
	}
	defer nul.Close()
	handles := []windows.Handle{windows.Handle(w.Fd()), windows.Handle(nul.Fd())}
	for _, h := range handles {
		if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return nil, err
		}
	}
	if err = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return nil, err
	}
	si := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{
		Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW,
		StdInput: handles[1], StdOutput: handles[0], StdErr: handles[0],
	}, ProcThreadAttributeList: attrs.List()}
	command, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{exe}, args...)))
	if err != nil {
		return nil, err
	}
	executable, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return nil, err
	}
	dir, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return nil, err
	}
	var pi windows.ProcessInformation
	// A hidden private console permits CTRL_C for graceful Tor/sing-box
	// shutdown. No console is shared with the user's terminal or the tray app.
	err = windows.CreateProcess(executable, command, nil, nil, true, windows.CREATE_NEW_CONSOLE|windows.EXTENDED_STARTUPINFO_PRESENT, nil, dir, &si.StartupInfo, &pi)
	if err != nil {
		return nil, err
	}
	windows.CloseHandle(pi.Thread)
	c := &Child{job: job, handle: pi.Process, pid: pi.ProcessId, done: make(chan struct{})}
	success = true
	w.Close()
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		defer r.Close()
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			if line != nil {
				line(scanner.Text())
			}
		}
	}()
	go func() {
		_, waitErr := windows.WaitForSingleObject(pi.Process, windows.INFINITE)
		var code uint32
		codeErr := windows.GetExitCodeProcess(pi.Process, &code)
		c.mu.Lock()
		windows.CloseHandle(c.job) // Also terminates any descendants holding the pipe.
		windows.CloseHandle(c.handle)
		c.job, c.handle = 0, 0
		c.err = errors.Join(waitErr, codeErr)
		if code != 0 {
			c.err = errors.Join(c.err, fmt.Errorf("%s exited with code %d", filepath.Base(exe), code))
		}
		c.mu.Unlock()
		<-outputDone
		close(c.done)
	}()
	return c, nil
}

func (c *Child) Done() <-chan struct{} { return c.done }
func (c *Child) Wait() error           { <-c.done; return c.err }
func (c *Child) Stop() error {
	c.mu.Lock()
	var err error
	if c.job != 0 {
		err = windows.TerminateJobObject(c.job, 1)
	}
	c.mu.Unlock()
	<-c.done
	return err
}

// StopGracefully lets the child restore interface options and persist Tor's
// guard state. The job remains the crash/timeout fallback.
func (c *Child) StopGracefully() error {
	select {
	case <-c.done:
		return nil
	default:
	}
	exe, err := os.Executable()
	if err != nil {
		return errors.Join(err, c.Stop())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	helper := exec.CommandContext(ctx, exe, "--torinator-internal-interrupt", strconv.FormatUint(uint64(c.pid), 10))
	helper.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if output, err := helper.CombinedOutput(); err != nil {
		select {
		case <-c.done:
			return nil
		default:
		}
		return errors.Join(fmt.Errorf("signal child for cleanup: %w: %s", err, output), c.Stop())
	}
	select {
	case <-c.done:
		return c.Wait()
	case <-time.After(10 * time.Second):
		return errors.Join(fmt.Errorf("child cleanup timed out"), c.Stop())
	}
}

// InterruptHelper runs before flag parsing in the application (and test binary).
// Attaching in a short-lived helper leaves the caller's console untouched.
func InterruptHelper() (bool, error) {
	if len(os.Args) != 3 || os.Args[1] != "--torinator-internal-interrupt" {
		return false, nil
	}
	pid, err := strconv.ParseUint(os.Args[2], 10, 32)
	if err != nil || pid == 0 {
		return true, fmt.Errorf("invalid child process ID")
	}
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	kernel.NewProc("FreeConsole").Call()
	if r, _, err := kernel.NewProc("AttachConsole").Call(uintptr(pid)); r == 0 {
		return true, fmt.Errorf("AttachConsole: %w", err)
	}
	defer kernel.NewProc("FreeConsole").Call()
	// New-console children have a private console, but no explicit process
	// group. Target that console and shield this short-lived helper from Ctrl+C.
	received := make(chan struct{}, 1)
	handler := syscall.NewCallback(func(uint32) uintptr {
		select {
		case received <- struct{}{}:
		default:
		}
		return 1
	})
	if r, _, err := kernel.NewProc("SetConsoleCtrlHandler").Call(handler, 1); r == 0 {
		return true, err
	}
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_C_EVENT, 0); err != nil {
		return true, err
	}
	// GenerateConsoleCtrlEvent queues delivery; do not detach/reset handlers
	// while our own Ctrl+C event is still pending.
	select {
	case <-received:
		return true, nil
	case <-time.After(time.Second):
		return true, fmt.Errorf("console interrupt delivery timed out")
	}
}
