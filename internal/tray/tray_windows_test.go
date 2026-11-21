//go:build windows

package tray

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/gharut/torinator/internal/app"
)

type offlineBackend struct{ connects, resets atomic.Int32 }

func (b *offlineBackend) Connect(context.Context, func(string)) (app.Connection, error) {
	b.connects.Add(1)
	return nil, fmt.Errorf("offline test must not connect")
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
