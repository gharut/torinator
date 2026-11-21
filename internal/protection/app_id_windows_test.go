//go:build windows && amd64

package protection

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// GitHub's Windows TEMP uses RUNNER~1. The filter API accepts that spelling,
// but it must identify the same image as the full path reported by ALE.
func TestApplicationIDCanonicalizesShortPath(t *testing.T) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(t.TempDir(), "application identity.exe")
	if err := os.WriteFile(temp, []byte("identity fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	checked := false
	for _, path := range []string{temp, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")} {
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		shortBuf, longBuf := make([]uint16, 32768), make([]uint16, 32768)
		n, err := windows.GetShortPathName(name, &shortBuf[0], uint32(len(shortBuf)))
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 || n >= uint32(len(shortBuf)) {
			t.Fatal("invalid short path length")
		}
		short := windows.UTF16ToString(shortBuf[:n])
		n, err = windows.GetLongPathName(name, &longBuf[0], uint32(len(longBuf)))
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 || n >= uint32(len(longBuf)) {
			t.Fatal("invalid long path length")
		}
		long := windows.UTF16ToString(longBuf[:n])
		if strings.EqualFold(long, short) {
			continue
		}
		checked = true
		want, err := nativeAppID(long)
		if err != nil {
			t.Fatal(err)
		}
		got, err := nativeAppID(short)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("short path %q and full path %q identify different WFP applications", short, long)
		}
		t.Logf("same application identity through %q and %q", short, long)
	}
	if !checked {
		t.Skip("8.3 aliases are unavailable on this Windows volume")
	}
}
