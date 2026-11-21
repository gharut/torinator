//go:build windows

package platform

import (
	"net"
	"os"
	"strings"
	"testing"
)

func TestIdentifyLocalProxyProcess(t *testing.T) {
	if os.Getenv("TORINATOR_PLATFORM_TEST") != "1" {
		t.Skip("requires Windows CIM network access")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	path, err := LocalProxyProcess("127.0.0.1", listener.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(path, exe) {
		t.Fatal("local proxy exception identified the wrong executable")
	}
	path, err = LocalProxyProcess("203.0.113.8", 1080)
	if err != nil || path != "" {
		t.Fatal("remote proxies must not receive a direct process exception")
	}
}
