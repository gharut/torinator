//go:build windows

package tray

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/gharut/torinator/internal/app"
	"github.com/gharut/torinator/internal/settings"
	"golang.org/x/sys/windows"
)

type offlineBackend struct{ connects, resets atomic.Int32 }

func (b *offlineBackend) Connect(context.Context, func(string)) (app.Connection, error) {
	b.connects.Add(1)
	return nil, fmt.Errorf("offline test must not connect")
}

func TestNativeSettingsSaveCancelAndTorDefault(t *testing.T) {
	if os.Getenv("TORINATOR_TRAY_TEST") != "1" {
		t.Skip("requires an interactive Windows desktop")
	}
	store, err := settings.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b := &offlineBackend{}
	c := app.NewWithSettings(b, store, nil)
	var problem error
	err = run(c, "", func(hwnd uintptr) {
		defer postMessage.Call(hwnd, wmClose, 0, 0)
		getDialog := func() uintptr {
			sendMessage.Call(hwnd, wmCommand, 7, 0)
			dialog, _, _ := user.NewProc("GetWindow").Call(hwnd, 6)
			return dialog
		}
		control := func(dialog uintptr, id int) uintptr {
			h, _, _ := user.NewProc("GetDlgItem").Call(dialog, uintptr(id))
			return h
		}
		write := func(dialog uintptr, id int, value string) {
			setWindowText.Call(control(dialog, id), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(value))))
		}
		dialog := getDialog()
		if dialog == 0 || dialog == hwnd {
			problem = fmt.Errorf("settings window did not open")
			return
		}
		checked, _, _ := sendMessage.Call(control(dialog, idTor), 0x00f0, 0, 0)
		enabled, _, _ := user.NewProc("IsWindowEnabled").Call(control(dialog, idHost))
		if checked != 1 || enabled != 0 {
			problem = fmt.Errorf("Tor must be the default, with proxy inputs disabled")
			return
		}
		sendMessage.Call(dialog, wmCommand, idSOCKS, 0)
		write(dialog, idHost, "203.0.113.5")
		write(dialog, idPort, "1081")
		write(dialog, idUsername, "offline-test")
		write(dialog, idPassword, "offline-test-password")
		sendMessage.Call(dialog, wmCommand, 1, 0)
		if saved := c.Settings(); saved.Mode != settings.SOCKS5 || saved.Proxy.Host != "203.0.113.5" || saved.Proxy.Port != 1081 || saved.Proxy.Password != "offline-test-password" {
			problem = fmt.Errorf("settings controls failed to save")
			return
		}
		dialog = getDialog()
		sendMessage.Call(dialog, wmCommand, idTor, 0)
		sendMessage.Call(dialog, wmCommand, 2, 0)
		if c.Settings().Mode != settings.SOCKS5 {
			problem = fmt.Errorf("Cancel changed the selected provider")
			return
		}
		dialog = getDialog()
		sendMessage.Call(dialog, wmCommand, idTor, 0)
		sendMessage.Call(dialog, wmCommand, 1, 0)
		if c.Settings().Mode != settings.Tor {
			problem = fmt.Errorf("could not switch back to Tor")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if problem != nil {
		t.Fatal(problem)
	}
	if b.connects.Load() != 0 {
		t.Fatal("settings window started network routing")
	}
}
func (b *offlineBackend) Reset() error { b.resets.Add(1); return nil }

// This opt-in test exercises real Win32 callbacks, notification data layout,
// icon creation, message delivery, and exit without admin/network operations.
func TestNativeTrayLifecycle(t *testing.T) {
	if os.Getenv("TORINATOR_TRAY_TEST") != "1" {
		t.Skip("requires an interactive Windows desktop")
	}
	b := &offlineBackend{}
	c := app.New(b, nil)
	err := run(c, "", func(hwnd uintptr) { postMessage.Call(hwnd, wmClose, 0, 0) })
	if err != nil {
		t.Fatal(err)
	}
	if b.connects.Load() != 0 || b.resets.Load() != 1 {
		t.Fatalf("connects=%d resets=%d", b.connects.Load(), b.resets.Load())
	}
}
