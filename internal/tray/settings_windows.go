//go:build windows

package tray

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/gharut/torinator/internal/settings"
	"golang.org/x/sys/windows"
)

const (
	idTor      = 100
	idSOCKS    = 101
	idHost     = 102
	idPort     = 103
	idUsername = 104
	idPassword = 105
	wmCommand  = 0x0111
)

var (
	sendMessage     = user.NewProc("SendMessageW")
	getWindowText   = user.NewProc("GetWindowTextW")
	setWindowText   = user.NewProc("SetWindowTextW")
	enableWindow    = user.NewProc("EnableWindow")
	setFocus        = user.NewProc("SetFocus")
	showWindow      = user.NewProc("ShowWindow")
	isDialogMessage = user.NewProc("IsDialogMessageW")
	gdi             = windows.NewLazySystemDLL("gdi32.dll")
)

type settingsWindow struct {
	owner        *ui
	window, font uintptr
	controls     map[int]uintptr
	fields       []uintptr
}

func (u *ui) showSettings() error {
	if u.preferences != nil {
		setForegroundWindow.Call(u.preferences.window)
		return nil
	}
	s := &settingsWindow{owner: u, controls: make(map[int]uintptr)}
	u.preferences = s
	ok := false
	defer func() {
		if !ok {
			if s.window != 0 {
				destroyWindow.Call(s.window)
			}
			u.preferences = nil
			if s.font != 0 {
				gdi.NewProc("DeleteObject").Call(s.font)
			}
		}
	}()
	const style = 0x00c80000 // caption and system menu, fixed-size owned window
	rect := struct{ Left, Top, Right, Bottom int32 }{Right: 500, Bottom: 434}
	user.NewProc("AdjustWindowRectEx").Call(uintptr(unsafe.Pointer(&rect)), style, 0, 0x10001)
	width, height := rect.Right-rect.Left, rect.Bottom-rect.Top
	screenW, _, _ := user.NewProc("GetSystemMetrics").Call(0)
	screenH, _, _ := user.NewProc("GetSystemMetrics").Call(1)
	var instance windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &instance); err != nil {
		return err
	}
	hwnd, _, err := createWindow.Call(0x10001, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("TorinatorTrayWindow"))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("Torinator Settings"))), style,
		uintptr((int32(screenW)-width)/2), uintptr((int32(screenH)-height)/2), uintptr(width), uintptr(height), u.window, 0, uintptr(instance), 0)
	if hwnd == 0 {
		return fmt.Errorf("create settings window: %w", err)
	}
	s.window = hwnd
	heightFont := int32(-16)
	s.font, _, _ = gdi.NewProc("CreateFontW").Call(uintptr(heightFont), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 0, 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("Segoe UI"))))
	control := func(class, text string, style uintptr, id, x, y, w, h int) (uintptr, error) {
		ex := uintptr(0)
		if class == "EDIT" {
			ex = 0x200
		}
		child, _, err := createWindow.Call(ex, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(class))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(text))), 0x50000000|style, uintptr(x), uintptr(y), uintptr(w), uintptr(h), s.window, uintptr(id), uintptr(instance), 0)
		if child == 0 {
			return 0, fmt.Errorf("create settings control: %w", err)
		}
		if s.font != 0 {
			sendMessage.Call(child, 0x0030, s.font, 1)
		}
		if id != 0 {
			s.controls[id] = child
		}
		return child, nil
	}
	config := u.controller.Settings()
	for _, spec := range []struct {
		class, text    string
		style          uintptr
		id, x, y, w, h int
	}{
		{"STATIC", "Route internet traffic through", 0, 0, 20, 16, 460, 24},
		{"BUTTON", "Tor — embedded (default)", 0x00020000 | 0x00010000 | 9, idTor, 20, 46, 460, 26},
		{"BUTTON", "Custom SOCKS5 proxy", 0x00010000 | 9, idSOCKS, 20, 75, 460, 26},
		{"STATIC", "Persistent kill switch is always enabled when connecting.", 0, 0, 20, 108, 460, 24},
		{"STATIC", "Proxy host / IP", 0, 0, 20, 145, 332, 22},
		{"STATIC", "Port", 0, 0, 370, 145, 110, 22},
		{"EDIT", config.Proxy.Host, 0x00010000 | 0x0080, idHost, 20, 168, 332, 27},
		{"EDIT", strconv.Itoa(config.Proxy.Port), 0x00010000 | 0x2000 | 0x0080, idPort, 370, 168, 110, 27},
		{"STATIC", "Username (optional)", 0, 0, 20, 210, 460, 22},
		{"EDIT", config.Proxy.Username, 0x00010000 | 0x0080, idUsername, 20, 233, 460, 27},
		{"STATIC", "Password (optional)", 0, 0, 20, 275, 460, 22},
		{"EDIT", config.Proxy.Password, 0x00010000 | 0x0080 | 0x0020, idPassword, 20, 298, 460, 27},
		{"STATIC", "Custom SOCKS5 routes TCP, UDP and DNS through your proxy.\r\nUDP requires proxy relay support. ICMP/ping is not supported.", 0, 0, 20, 341, 460, 44},
		{"BUTTON", "Save", 0x00010000 | 1, 1, 292, 396, 88, 28},
		{"BUTTON", "Cancel", 0x00010000, 2, 392, 396, 88, 28},
	} {
		h, err := control(spec.class, spec.text, spec.style, spec.id, spec.x, spec.y, spec.w, spec.h)
		if err != nil {
			return err
		}
		if spec.id >= idHost && spec.id <= idPassword {
			s.fields = append(s.fields, h)
		}
	}
	sendMessage.Call(s.controls[idHost], 0x1501, 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("proxy.example.com or an IP address"))))
	sendMessage.Call(s.controls[idHost], 0x00c5, 253, 0) // EM_SETLIMITTEXT
	sendMessage.Call(s.controls[idPort], 0x00c5, 5, 0)
	sendMessage.Call(s.controls[idUsername], 0x00c5, 255, 0)
	sendMessage.Call(s.controls[idPassword], 0x00c5, 255, 0)
	s.selectMode(config.Mode == settings.SOCKS5)
	showWindow.Call(hwnd, 5)
	setForegroundWindow.Call(hwnd)
	if config.Mode == settings.SOCKS5 {
		setFocus.Call(s.controls[idHost])
	} else {
		setFocus.Call(s.controls[idTor])
	}
	ok = true
	return nil
}

func (s *settingsWindow) selectMode(custom bool) {
	check := func(id int, checked bool) {
		v := uintptr(0)
		if checked {
			v = 1
		}
		sendMessage.Call(s.controls[id], 0x00f1, v, 0)
	}
	check(idTor, !custom)
	check(idSOCKS, custom)
	enabled := uintptr(0)
	if custom {
		enabled = 1
	}
	for _, h := range s.fields {
		enableWindow.Call(h, enabled)
	}
}
func (s *settingsWindow) text(id int) string {
	buf := make([]uint16, 1024)
	getWindowText.Call(s.controls[id], uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf)
}
func (s *settingsWindow) save() error {
	config := s.owner.controller.Settings()
	checked, _, _ := sendMessage.Call(s.controls[idSOCKS], 0x00f0, 0, 0)
	config.Mode = settings.Tor
	if checked != 0 {
		config.Mode = settings.SOCKS5
	}
	config.Proxy.Host = s.text(idHost)
	port, err := strconv.Atoi(strings.TrimSpace(s.text(idPort)))
	if err != nil && config.Mode == settings.SOCKS5 {
		return fmt.Errorf("enter a numeric proxy port")
	}
	if err == nil {
		config.Proxy.Port = port
	}
	config.Proxy.Username = s.text(idUsername)
	config.Proxy.Password = s.text(idPassword)
	return s.owner.controller.SaveSettings(config)
}
func (s *settingsWindow) handle(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	switch msg {
	case wmCommand:
		switch int(wparam & 0xffff) {
		case idTor:
			s.selectMode(false)
		case idSOCKS:
			s.selectMode(true)
		case 1:
			if err := s.save(); err != nil {
				messageBox.Call(s.window, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(err.Error()))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("Proxy settings"))), 0x30)
				return 0
			}
			destroyWindow.Call(hwnd)
		case 2:
			destroyWindow.Call(hwnd)
		}
		return 0
	case 0x0400:
		return 0x534b0001 // DM_GETDEFID: Save is the default button.
	case wmClose:
		destroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		s.owner.preferences = nil
		if s.font != 0 {
			gdi.NewProc("DeleteObject").Call(s.font)
			s.font = 0
		}
		return 0
	}
	r, _, _ := defWindowProc.Call(hwnd, uintptr(msg), wparam, lparam)
	return r
}
