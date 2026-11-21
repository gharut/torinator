//go:build windows

package protection

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// VerifyNoDirect runs from the UI executable, which is deliberately not a
// transport exception. Only WSAEACCES counts as denial; an offline interface,
// missing route, timeout, or refused remote endpoint is inconclusive.
func VerifyNoDirect(ctx context.Context, sources []netip.Addr) error {
	if len(sources) == 0 {
		return fmt.Errorf("no direct-connect probe sources")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	app, err := nativeAppID(exe)
	if err != nil {
		return err
	}
	s, err := openNative(false)
	if err != nil {
		return err
	}
	defer s.close()
	for _, ip := range sources {
		target := "1.1.1.1"
		network := "tcp4"
		udpNetwork := "udp4"
		if ip.Is6() {
			target = "2606:4700:4700::1111"
			network = "tcp6"
			udpNetwork = "udp6"
		}
		dialer := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(ip.AsSlice())}}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(target, "443"))
		if conn != nil {
			conn.Close()
			return fmt.Errorf("direct TCP bypass probe succeeded from %s", ip)
		}
		if !errors.Is(err, windows.WSAEACCES) {
			return fmt.Errorf("cannot confirm direct TCP blocking from %s: %w", ip, err)
		}
		udp, err := net.DialUDP(udpNetwork, &net.UDPAddr{IP: net.IP(ip.AsSlice())}, &net.UDPAddr{IP: net.ParseIP(target), Port: 53})
		var port uint16
		since := time.Now()
		if err == nil {
			port = uint16(udp.LocalAddr().(*net.UDPAddr).Port)
			udp.SetWriteDeadline(time.Now().Add(3 * time.Second))
			// A fixed, non-user DNS root query; it must never leave the PC.
			_, err = udp.Write([]byte{0x54, 0x49, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1})
			udp.Close()
		}
		if err == nil {
			// Windows can queue a UDP send successfully and silently drop it.
			// A timeout alone is not evidence; attribute its actual kernel drop.
			if err := s.waitForDrop(ctx, app, port, since); err != nil {
				return err
			}
		} else if !errors.Is(err, windows.WSAEACCES) {
			return fmt.Errorf("cannot confirm direct UDP/DNS blocking from %s (a successful write is unsafe): %v", ip, err)
		}
	}
	return nil
}
