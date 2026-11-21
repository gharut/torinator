//go:build windows

package engine

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gharut/torinator/internal/assets"
	"github.com/gharut/torinator/internal/process"
	"github.com/gharut/torinator/internal/routing"
	"github.com/gharut/torinator/internal/settings"
)

// End-to-end authentication and UDP relay through the actual embedded router,
// with SOCKS inbounds replacing TUN. All endpoints are loopback: this test never
// changes routes/adapters and never contacts the internet.
func TestCustomProxyTCPAndUDPRelay(t *testing.T) {
	if os.Getenv("TORINATOR_PROXY_TEST") != "1" {
		t.Skip("requires loopback network access")
	}
	dir := t.TempDir()
	r, err := assets.ExtractForMode(filepath.Join(dir, "runtime"), false)
	if err != nil {
		t.Fatal(err)
	}
	tcpEcho, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	go func() {
		c, err := tcpEcho.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	udpEcho, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := udpEcho.ReadFrom(buf)
			if err != nil {
				return
			}
			udpEcho.WriteTo(buf[:n], addr)
		}
	}()
	proxyPort := freePort(t)
	server := map[string]any{
		"log":       map[string]any{"level": "info", "disabled": false},
		"inbounds":  []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": proxyPort, "users": []any{map[string]any{"username": "offline-user", "password": "offline-password"}}}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	}
	startTestRouter(t, r.SingBox, filepath.Join(dir, "server.json"), server)
	c := settings.Config{Mode: settings.SOCKS5, Proxy: settings.Proxy{Host: "127.0.0.1", Port: proxyPort, Username: "offline-user", Password: "offline-password"}}
	data, err := routing.ForSettings(c, "", "127.0.0.1", proxyPort)
	if err != nil {
		t.Fatal(err)
	}
	var client map[string]any
	if err := json.Unmarshal(data, &client); err != nil {
		t.Fatal(err)
	}
	clientPort := freePort(t)
	client["inbounds"] = []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": clientPort}}
	startTestRouter(t, r.SingBox, filepath.Join(dir, "client.json"), client)

	stream, _ := socksRequest(t, clientPort, 1, tcpEcho.Addr().(*net.TCPAddr).Port)
	defer stream.Close()
	message := []byte("Torinator custom SOCKS5 TCP")
	if _, err := stream.Write(message); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(message))
	if _, err := io.ReadFull(stream, reply); err != nil || string(reply) != string(message) {
		t.Fatalf("TCP relay failed: %v", err)
	}

	control, relayPort := socksRequest(t, clientPort, 3, 0)
	defer control.Close()
	udp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relayPort})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(10 * time.Second))
	packet := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(packet[8:], uint16(udpEcho.LocalAddr().(*net.UDPAddr).Port))
	packet = append(packet, []byte("Torinator custom SOCKS5 UDP")...)
	if _, err := udp.Write(packet); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := udp.Read(buf)
	if err != nil || n < 10 || string(buf[10:n]) != "Torinator custom SOCKS5 UDP" {
		t.Fatalf("UDP relay failed: bytes=%d err=%v", n, err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
func startTestRouter(t *testing.T, exe, path string, config any) {
	t.Helper()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{}, 1)
	child, err := process.Start(exe, []string{"run", "-c", path}, func(line string) {
		if strings.Contains(line, "sing-box started") {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Stop() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := await(ctx, ready, child); err != nil {
		t.Fatalf("start test router: %v", err)
	}
}
func socksRequest(t *testing.T, proxyPort int, command byte, targetPort int) (net.Conn, int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", proxyPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header[:2]); err != nil || header[0] != 5 || header[1] != 0 {
		conn.Close()
		t.Fatalf("SOCKS greeting failed: %v", err)
	}
	req := []byte{5, command, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(req[8:], uint16(targetPort))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, header); err != nil || header[1] != 0 {
		conn.Close()
		t.Fatalf("SOCKS command failed: %v status=%d", err, header[1])
	}
	addressLength := 0
	switch header[3] {
	case 1:
		addressLength = 4
	case 4:
		addressLength = 16
	case 3:
		if _, err := io.ReadFull(conn, header[:1]); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		addressLength = int(header[0])
	default:
		conn.Close()
		t.Fatal("invalid SOCKS address type")
	}
	address := make([]byte, addressLength+2)
	if _, err := io.ReadFull(conn, address); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	return conn, int(binary.BigEndian.Uint16(address[addressLength:]))
}
