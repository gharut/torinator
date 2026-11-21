//go:build windows

// Package tray provides a native Windows notification icon without CGO.
package tray

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/gharut/torinator/internal/app"
	"github.com/gharut/torinator/internal/buildinfo"
	"github.com/gharut/torinator/internal/platform"
	"golang.org/x/sys/windows"
)

var (
	user                = windows.NewLazySystemDLL("user32.dll")
	shell               = windows.NewLazySystemDLL("shell32.dll")
	registerClass       = user.NewProc("RegisterClassExW")
	createWindow        = user.NewProc("CreateWindowExW")
	defWindowProc       = user.NewProc("DefWindowProcW")
	destroyWindow       = user.NewProc("DestroyWindow")
	getMessage          = user.NewProc("GetMessageW")
	translateMessage    = user.NewProc("TranslateMessage")
	dispatchMessage     = user.NewProc("DispatchMessageW")
	postMessage         = user.NewProc("PostMessageW")
	postQuitMessage     = user.NewProc("PostQuitMessage")
	createPopupMenu     = user.NewProc("CreatePopupMenu")
	appendMenu          = user.NewProc("AppendMenuW")
	destroyMenu         = user.NewProc("DestroyMenu")
	trackPopupMenu      = user.NewProc("TrackPopupMenu")
	getCursorPos        = user.NewProc("GetCursorPos")
	setForegroundWindow = user.NewProc("SetForegroundWindow")
	notifyIcon          = shell.NewProc("Shell_NotifyIconW")
	createIcon          = user.NewProc("CreateIcon")
	destroyIcon         = user.NewProc("DestroyIcon")
	setTimer            = user.NewProc("SetTimer")
	killTimer           = user.NewProc("KillTimer")
	registerMessage     = user.NewProc("RegisterWindowMessageW")
	messageBox          = user.NewProc("MessageBoxW")
)

const (
	wmDestroy    = 0x0002
	wmClose      = 0x0010
	wmEndSession = 0x0016
	wmTimer      = 0x0113
	wmTray       = 0x8001
	wmQuitReady  = 0x8002
)

type point struct{ X, Y int32 }
type message struct {
	HWnd           uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Pt             point
	Private        uint32
}
type windowClass struct {
	Size, Style                        uint32
	WndProc                            uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	MenuName, ClassName                *uint16
	SmallIcon                          uintptr
}
type notifyData struct {
	Size                uint32
	Window              uintptr
	ID, Flags, Callback uint32
	Icon                uintptr
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	Version             uint32
	InfoTitle           [64]uint16
	InfoFlags           uint32
	GUID                windows.GUID
	BalloonIcon         uintptr
}
type ui struct {
	controller      *app.Controller
	logPath         string
	window          uintptr
	icons           map[app.State]uintptr
	taskbarCreated  uint32
	last            app.Status
	added, quitting bool
	quitDone        chan error
	quitErr         error
	preferences     *settingsWindow
}

func Run(controller *app.Controller, logPath string) error {
	return run(controller, logPath, nil)
}

func run(controller *app.Controller, logPath string, ready func(uintptr)) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	u := &ui{controller: controller, logPath: logPath, icons: make(map[app.State]uintptr), quitDone: make(chan error, 1)}
	defer func() {
		for _, i := range u.icons {
			destroyIcon.Call(i)
		}
	}()
	for state, color := range map[app.State][3]byte{
		app.Disconnected: {130, 139, 151}, app.Connecting: {236, 172, 46}, app.Connected: {42, 188, 120}, app.Failed: {224, 74, 86},
		app.Protected: {42, 188, 120}, app.Blocked: {224, 74, 86},
	} {
		icon, err := makeIcon(color)
		if err != nil {
			return err
		}
		u.icons[state] = icon
	}
	className := windows.StringToUTF16Ptr("TorinatorTrayWindow")
	callback := syscall.NewCallback(u.windowProc)
	var instance windows.Handle
	err := windows.GetModuleHandleEx(0, nil, &instance)
	if err != nil {
		return err
	}
	wc := windowClass{WndProc: callback, Instance: uintptr(instance), ClassName: className, Background: 16}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, err := registerClass.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return fmt.Errorf("register tray window: %w", err)
	}
	unregister := user.NewProc("UnregisterClassW")
	defer unregister.Call(uintptr(unsafe.Pointer(className)), uintptr(instance))
	u.window, _, err = createWindow.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("Torinator"))), 0, 0, 0, 0, 0, 0, 0, uintptr(instance), 0)
	if u.window == 0 {
		return fmt.Errorf("create tray window: %w", err)
	}
	defer destroyWindow.Call(u.window)
	taskbar, _, _ := registerMessage.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("TaskbarCreated"))))
	u.taskbarCreated = uint32(taskbar)
	if err := u.refresh(true); err != nil {
		return err
	}
	defer u.remove()
	if r, _, err := setTimer.Call(u.window, 1, 250, 0); r == 0 {
		return fmt.Errorf("tray timer: %w", err)
	}
	defer killTimer.Call(u.window, 1)
	if ready != nil {
		ready(u.window)
	}
	var msg message
	for {
		r, _, err := getMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) == -1 {
			return fmt.Errorf("tray message loop: %w", err)
		}
		if r == 0 {
			return u.quitErr
		}
		if u.preferences != nil {
			if handled, _, _ := isDialogMessage.Call(u.preferences.window, uintptr(unsafe.Pointer(&msg))); handled != 0 {
				continue
			}
		}
		translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func (u *ui) windowProc(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	if u.preferences != nil && hwnd == u.preferences.window {
		return u.preferences.handle(hwnd, msg, wparam, lparam)
	}
	if msg == u.taskbarCreated && u.taskbarCreated != 0 {
		u.added = false
		_ = u.refresh(true)
		return 0
	}
	switch msg {
	case wmCommand:
		if wparam&0xffff == 7 {
			if err := u.showSettings(); err != nil {
				Alert("Settings", err.Error())
			}
		}
		return 0
	case wmTray:
		if lparam == 0x0202 || lparam == 0x0205 || lparam == 0x007b {
			u.menu()
		}
		return 0
	case wmTimer:
		_ = u.refresh(false)
		return 0
	case wmClose:
		u.quit()
		return 0
	case wmQuitReady:
		u.quitErr = <-u.quitDone
		if u.quitErr != nil {
			Alert("Torinator cleanup", u.quitErr.Error())
		}
		u.remove()
		destroyWindow.Call(hwnd)
		return 0
	case wmEndSession:
		if wparam != 0 {
			u.remove()
			postQuitMessage.Call(0)
		}
		return 0
	case wmDestroy:
		postQuitMessage.Call(0)
		return 0
	}
	r, _, _ := defWindowProc.Call(hwnd, uintptr(msg), wparam, lparam)
	return r
}

func (u *ui) refresh(force bool) error {
	s := u.controller.Status()
	if !force && s == u.last && u.added {
		return nil
	}
	u.last = s
	icon := u.icons[s.State]
	if icon == 0 {
		icon = u.icons[app.Connecting]
	}
	n := notifyData{Window: u.window, ID: 1, Flags: 1 | 2 | 4, Callback: wmTray, Icon: icon}
	n.Size = uint32(unsafe.Sizeof(n))
	tip := windows.StringToUTF16("Torinator — " + string(s.State) + "\n" + s.Detail)
	copy(n.Tip[:len(n.Tip)-1], tip[:len(tip)-1])
	op := uintptr(1)
	if !u.added {
		op = 0
	}
	if r, _, err := notifyIcon.Call(op, uintptr(unsafe.Pointer(&n))); r == 0 {
		u.added = false
		return fmt.Errorf("update tray icon: %w", err)
	}
	u.added = true
	return nil
}
func (u *ui) remove() {
	if !u.added {
		return
	}
	n := notifyData{Window: u.window, ID: 1}
	n.Size = uint32(unsafe.Sizeof(n))
	notifyIcon.Call(2, uintptr(unsafe.Pointer(&n)))
	u.added = false
}
func (u *ui) quit() {
	if u.quitting {
		return
	}
	u.quitting = true
	if u.preferences != nil {
		destroyWindow.Call(u.preferences.window)
	}
	go func() { u.quitDone <- u.controller.Close(); postMessage.Call(u.window, wmQuitReady, 0, 0) }()
}
func (u *ui) menu() {
	menu, _, _ := createPopupMenu.Call()
	if menu == 0 {
		return
	}
	defer destroyMenu.Call(menu)
	item := func(id uintptr, label string, disabled bool) {
		flags := uintptr(0)
		if disabled {
			flags = 1
		}
		appendMenu.Call(menu, flags, id, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(label))))
	}
	s := u.controller.Status()
	item(0, "Torinator "+buildinfo.Version+"  ·  "+string(s.State), true)
	appendMenu.Call(menu, 0x0800, 0, 0)
	busy := s.State == app.Disconnecting || s.State == app.Resetting || u.quitting
	active := s.State == app.Connected || s.State == app.Protected || s.State == app.Degraded || s.State == app.Connecting
	item(1, "Connect", busy || u.preferences != nil || active)
	item(2, "Disconnect", busy || s.State == app.Disconnected)
	item(3, "Reset network changes", busy)
	item(7, "Settings…", busy || active)
	appendMenu.Call(menu, 0x0800, 0, 0)
	item(4, "Show status…", false)
	item(5, "Open log", false)
	exitLabel := "Exit"
	if s.State != app.Disconnected {
		exitLabel = "Exit (keep protection armed)"
	}
	item(6, exitLabel, u.quitting)
	var p point
	getCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	setForegroundWindow.Call(u.window)
	id, _, _ := trackPopupMenu.Call(menu, 0x0100|0x0002, uintptr(p.X), uintptr(p.Y), 0, u.window, 0)
	postMessage.Call(u.window, 0, 0, 0)
	switch id {
	case 1:
		u.controller.Connect()
	case 2:
		u.controller.Disconnect(false)
	case 3:
		u.controller.Disconnect(true)
	case 4:
		Alert("Torinator — "+string(s.State), s.Detail+"\n\n"+strings.Join([]string{
			"Protected: Windows enforcement and direct TCP/UDP denial probes passed, and the proxy is reachable.", "Amber: connecting, cleaning up, or connectivity check failed.", "Grey: normal Windows routing.", "Blocked: direct access remains blocked; the tunnel is stopped. Red errors may require Reset.",
			"", "Tor supports TCP. Custom SOCKS5 supports TCP and UDP relay when the proxy provides it. ICMP/ping is blocked.",
			"A crash or Exit keeps protection armed. Disconnect or Reset explicitly restores normal networking.",
		}, "\n"))
	case 5:
		if err := platform.OpenFile(u.logPath); err != nil {
			Alert("Open log", err.Error())
		}
	case 6:
		u.quit()
	case 7:
		if err := u.showSettings(); err != nil {
			Alert("Settings", err.Error())
		}
	}
}
func Alert(title, text string) {
	messageBox.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(text))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(title))), 0x40)
}
func makeIcon(color [3]byte) (uintptr, error) {
	const size = 32
	mask := make([]byte, size*size/8)
	pixels := make([]byte, size*size*4)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			i := ((size-1-y)*size + x) * 4
			dx, dy := x-15, y-15
			if dx*dx+dy*dy > 225 {
				mask[y*4+x/8] |= 0x80 >> uint(x%8)
				continue
			}
			pixels[i], pixels[i+1], pixels[i+2], pixels[i+3] = color[2], color[1], color[0], 255
			if (y >= 8 && y <= 11 && x >= 8 && x <= 23) || (x >= 14 && x <= 17 && y >= 10 && y <= 24) {
				pixels[i], pixels[i+1], pixels[i+2] = 255, 255, 255
			}
		}
	}
	icon, _, err := createIcon.Call(0, size, size, 1, 32, uintptr(unsafe.Pointer(&mask[0])), uintptr(unsafe.Pointer(&pixels[0])))
	if icon == 0 {
		return 0, fmt.Errorf("create tray icon: %w", err)
	}
	return icon, nil
}
