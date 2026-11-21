//go:build windows

package process

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestMain(m *testing.M) {
	if handled, err := InterruptHelper(); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestProcessHelper(t *testing.T) {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "torinator-test-tree":
		cmd := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$", "--", "torinator-test-wait")
		if err := cmd.Start(); err != nil {
			os.Exit(2)
		}
		fmt.Printf("grandchild:%d\n", cmd.Process.Pid)
		cmd.Wait()
		os.Exit(0)
	case "torinator-test-wait":
		time.Sleep(time.Minute)
		os.Exit(0)
	case "torinator-test-exit":
		fmt.Println("runtime output")
		os.Exit(7)
	case "torinator-test-graceful":
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)
		fmt.Println("ready")
		<-interrupt
		fmt.Println("cleaned up")
		os.Exit(0)
	}
}

func TestGracefulStopAllowsCleanup(t *testing.T) {
	exe, _ := os.Executable()
	ready := make(chan struct{})
	var output []string
	child, err := Start(exe, []string{"-test.run=^TestProcessHelper$", "--", "torinator-test-graceful"}, func(line string) {
		output = append(output, line)
		if line == "ready" {
			close(ready)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer child.Stop()
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("child not ready")
	}
	if err := child.StopGracefully(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(output, ",") != "ready,cleaned up" {
		t.Fatal(output)
	}
}
func TestStopKillsTheWholeProcessTree(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pid := make(chan uint32, 1)
	child, err := Start(exe, []string{"-test.run=^TestProcessHelper$", "--", "torinator-test-tree"}, func(line string) {
		if strings.HasPrefix(line, "grandchild:") {
			n, _ := strconv.ParseUint(strings.TrimPrefix(line, "grandchild:"), 10, 32)
			pid <- uint32(n)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer child.Stop()
	var grandchild uint32
	select {
	case grandchild = <-pid:
	case <-time.After(10 * time.Second):
		t.Fatal("child did not start")
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, grandchild)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := child.Stop(); err != nil {
		t.Fatal(err)
	}
	status, err := windows.WaitForSingleObject(h, 5000)
	if err != nil || status != windows.WAIT_OBJECT_0 {
		t.Fatalf("grandchild survived: status=%d err=%v", status, err)
	}
}
func TestExitCodeAndOutputArePreserved(t *testing.T) {
	exe, _ := os.Executable()
	var output []string
	child, err := Start(exe, []string{"-test.run=^TestProcessHelper$", "--", "torinator-test-exit"}, func(line string) { output = append(output, line) })
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil || !strings.Contains(err.Error(), "code 7") {
		t.Fatalf("exit error=%v", err)
	}
	if len(output) != 1 || output[0] != "runtime output" {
		t.Fatal(output)
	}
}
