//go:build windows

package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gharut/torinator/internal/settings"
)

func TestCustomProxyNeverStartsTor(t *testing.T) {
	for _, host := range []string{"203.0.113.9", "2001:db8::9", "127.0.0.1"} {
		c := settings.Config{Mode: settings.SOCKS5, Proxy: settings.Proxy{Host: host, Port: 1080}}
		server, port, err := selectProxy(context.Background(), c, func() (string, int, error) { t.Fatal("Tor was started in custom proxy mode"); return "", 0, nil })
		if err != nil || server != host || port != 1080 {
			t.Fatalf("%s:%d %v", server, port, err)
		}
	}
}

func TestExitVerificationRespectsSelectedMode(t *testing.T) {
	ordinary := `{"IsTor":false,"IP":"203.0.113.5"}`
	if err := verifyExit(settings.SOCKS5, strings.NewReader(ordinary)); err != nil {
		t.Fatal("custom proxy must accept a non-Tor exit:", err)
	}
	if err := verifyExit(settings.Tor, strings.NewReader(ordinary)); err == nil {
		t.Fatal("Tor mode accepted a non-Tor exit")
	}
	if err := verifyExit(settings.Tor, strings.NewReader(`{"IsTor":true,"IP":"203.0.113.5"}`)); err != nil {
		t.Fatal(err)
	}
	if err := verifyExit(settings.SOCKS5, strings.NewReader(`{"IsTor":false,"IP":"invalid"}`)); err == nil {
		t.Fatal("accepted an invalid connectivity result")
	}
}
func TestTorRemainsDefaultAndCancellationPreventsStartup(t *testing.T) {
	called := 0
	start := func() (string, int, error) { called++; return "127.0.0.1", 12345, nil }
	_, port, err := selectProxy(context.Background(), settings.Default(), start)
	if err != nil || called != 1 || port != 12345 {
		t.Fatal("default mode did not start Tor")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = selectProxy(ctx, settings.Default(), start)
	if !errors.Is(err, context.Canceled) || called != 1 {
		t.Fatal("canceled startup launched a process")
	}
}
