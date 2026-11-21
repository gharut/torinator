//go:build windows

// Package engine coordinates embedded Tor and the system-wide TUN router.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gharut/torinator/internal/app"
	"github.com/gharut/torinator/internal/assets"
	"github.com/gharut/torinator/internal/platform"
	"github.com/gharut/torinator/internal/process"
	"github.com/gharut/torinator/internal/protection"
	"github.com/gharut/torinator/internal/routing"
	"github.com/gharut/torinator/internal/settings"
)

type Backend struct {
	Dir        string
	Log        *log.Logger
	Settings   *settings.Store
	Protection *protection.Manager
}
type connection struct {
	tor, router *process.Child
	done        chan struct{}
	err         error
	once        sync.Once
	stopErr     error
	dir         string
	health      chan error
	config      settings.Config
	policy      protection.Plan
	protection  *protection.Manager
	lease       *protection.Lease
	failOnce    sync.Once
}

func (s *connection) Done() <-chan struct{}    { return s.done }
func (s *connection) Err() error               { <-s.done; return s.err }
func (s *connection) Health() <-chan error     { return s.health }
func (s *connection) ProtectionVerified() bool { return s.lease != nil }
func (s *connection) Description() string {
	if s.config.Mode == settings.Tor {
		return "TCP and DNS through Tor; other UDP blocked"
	}
	return s.config.Label() + "; TCP/DNS verified; UDP requires proxy relay support"
}
func (s *connection) Stop() error {
	s.once.Do(func() {
		// Close the temporary interface permission before removing the TUN.
		// The persistent deny policy intentionally remains on every failure/Exit.
		if s.lease != nil {
			s.stopErr = errors.Join(s.stopErr, s.lease.Close())
		}
		if s.router != nil {
			s.stopErr = errors.Join(s.stopErr, s.router.StopGracefully())
		}
		if s.tor != nil {
			s.stopErr = errors.Join(s.stopErr, s.tor.StopGracefully())
		}
		s.stopErr = errors.Join(s.stopErr, platform.RemoveAdapter(), platform.RestoreInterfaces(s.dir), platform.FlushDNS())
		if err := os.Remove(filepath.Join(s.dir, "runtime", "sing-box.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.stopErr = errors.Join(s.stopErr, err)
		}
	})
	return s.stopErr
}

func (b *Backend) Connect(ctx context.Context, progress func(string)) (result app.Connection, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	c := settings.Default()
	if b.Settings != nil {
		c = b.Settings.Current()
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if b.Protection == nil {
		return nil, fmt.Errorf("kill-switch manager is unavailable")
	}
	s := &connection{done: make(chan struct{}), dir: b.Dir, health: make(chan error, 1), config: c, protection: b.Protection}
	defer func() {
		if err != nil {
			if cleanupErr := s.Stop(); cleanupErr != nil {
				// Cancellation must not hide a rollback failure from the tray.
				err = fmt.Errorf("%v; rollback failed: %w", err, cleanupErr)
			}
		}
	}()
	if err = platform.RemoveAdapter(); err != nil {
		return nil, err
	}
	if err = platform.RestoreInterfaces(b.Dir); err != nil {
		return nil, err
	}
	armed, err := b.Protection.Active()
	if err != nil {
		return nil, fmt.Errorf("inspect protection: %w", err)
	}
	sources, err := platform.EgressSources()
	if err != nil {
		return nil, err
	}
	runtimeDir := filepath.Join(b.Dir, "runtime")
	if err = os.RemoveAll(runtimeDir); err != nil {
		return nil, err
	}
	r, err := assets.ExtractForMode(runtimeDir, c.Mode == settings.Tor)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	server, port := "127.0.0.1", 0
	bypassPath := r.Tor.Binary
	if c.Mode == settings.SOCKS5 {
		if _, parseErr := netip.ParseAddr(c.Proxy.Host); armed && parseErr != nil {
			cached, cacheErr := b.Protection.CachedEndpoint(c.Proxy.Host)
			if cacheErr != nil {
				return nil, fmt.Errorf("protection remains armed: %w", cacheErr)
			}
			server, port = cached.String(), c.Proxy.Port
		} else {
			server, port, err = selectProxy(ctx, c, nil)
			if err != nil {
				return nil, err
			}
		}
		bypassPath, err = platform.LocalProxyProcess(server, port)
		if err != nil {
			return nil, err
		}
	}
	s.policy = protection.Plan{Mode: c.Mode, Host: c.Proxy.Host, Endpoint: netip.MustParseAddr(server), Port: uint16(port), TorPath: r.Tor.Binary, RouterPath: r.SingBox}
	if c.Mode == settings.SOCKS5 {
		s.policy.LocalProxyPath = bypassPath
	}
	progress("Arming persistent Windows protection")
	if err := b.Protection.Arm(s.policy); err != nil {
		return nil, fmt.Errorf("arm protection: %w", err)
	}
	if c.Mode == settings.Tor {
		server, port, err = selectProxy(ctx, c, func() (string, int, error) {
			var torPort int
			s.tor, torPort, err = b.startTor(ctx, r, progress)
			return "127.0.0.1", torPort, err
		})
		if err != nil {
			return nil, err
		}
	}
	config, err := routing.ForSettings(c, bypassPath, server, port)
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(runtimeDir, "sing-box.json")
	if err = os.WriteFile(configPath, config, 0600); err != nil {
		return nil, err
	}
	check, err := process.Start(r.SingBox, []string{"check", "-c", configPath}, func(line string) { b.Log.Printf("[check] %s", line) })
	if err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		check.Stop()
		return nil, ctx.Err()
	case <-check.Done():
		if err = check.Wait(); err != nil {
			return nil, fmt.Errorf("routing configuration: %w", err)
		}
	}
	progress("Creating Torinator adapter")
	if err = platform.SnapshotInterfaces(b.Dir); err != nil {
		return nil, err
	}
	routerReady := make(chan struct{}, 1)
	s.router, err = process.Start(r.SingBox, []string{"run", "-c", configPath}, func(line string) {
		b.Log.Printf("[routing] %s", line)
		if strings.Contains(line, "sing-box started") {
			select {
			case routerReady <- struct{}{}:
			default:
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if err = await(ctx, routerReady, s.router); err != nil {
		return nil, fmt.Errorf("TUN startup: %w", err)
	}
	luid, err := platform.TunnelLUID()
	if err != nil {
		return nil, err
	}
	s.lease, err = b.Protection.OpenTunnel(luid)
	if err != nil {
		return nil, fmt.Errorf("permit protected tunnel: %w", err)
	}
	progress("Checking Windows enforcement and direct-access denial")
	if err := b.Protection.Verify(s.policy, s.lease); err != nil {
		return nil, err
	}
	if err := protection.VerifyNoDirect(ctx, sources); err != nil {
		return nil, err
	}
	progress("Verifying system routing through " + c.Label())
	// Explicitly ignore application proxy settings. DNS and TCP must use the TUN.
	if err = Verify(ctx, c.Mode); err != nil {
		return nil, fmt.Errorf("system routing verification: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	healthCtx, stopHealth := context.WithCancel(context.Background())
	go func() {
		defer stopHealth()
		var torDone <-chan struct{}
		if s.tor != nil {
			torDone = s.tor.Done()
		}
		select {
		case <-torDone:
			s.fail(fmt.Errorf("Tor stopped: %v", s.tor.Wait()))
		case <-s.router.Done():
			s.fail(fmt.Errorf("sing-box stopped: %v", s.router.Wait()))
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		policyTicker := time.NewTicker(2 * time.Second)
		defer policyTicker.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-policyTicker.C:
				actualLUID, err := platform.TunnelLUID()
				if err == nil && actualLUID != luid {
					err = fmt.Errorf("tunnel interface changed")
				}
				if err == nil {
					err = b.Protection.Verify(s.policy, s.lease)
				}
				if err != nil {
					s.fail(fmt.Errorf("protection could not be verified: %w", err))
					return
				}
			case <-ticker.C:
				err := Verify(healthCtx, c.Mode)
				select {
				case s.health <- err:
				case <-s.done:
					return
				}
			}
		}
	}()
	return s, nil
}

func (s *connection) fail(err error) { s.failOnce.Do(func() { s.err = err; close(s.done) }) }
func (b *Backend) ProtectionState() (bool, error) {
	if b.Protection == nil {
		return false, fmt.Errorf("protection is unavailable")
	}
	return b.Protection.Active()
}

func await(ctx context.Context, ready <-chan struct{}, child *process.Child) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-child.Done():
		return fmt.Errorf("process stopped before ready: %v", child.Wait())
	case <-ready:
		return ctx.Err()
	}
}

func Verify(ctx context.Context, mode settings.Mode) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 25 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", addr)
	}, ForceAttemptHTTP2: false}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://check.torproject.org/api/ip", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("connectivity check returned HTTP %d", resp.StatusCode)
	}
	return verifyExit(mode, resp.Body)
}

func verifyExit(mode settings.Mode, body io.Reader) error {
	var result struct {
		IsTor bool
		IP    string
	}
	if err := json.NewDecoder(io.LimitReader(body, 4096)).Decode(&result); err != nil {
		return err
	}
	if _, err := netip.ParseAddr(result.IP); err != nil {
		return fmt.Errorf("connectivity check did not return a valid exit IP")
	}
	if mode == settings.Tor && !result.IsTor {
		return fmt.Errorf("Tor check detected a non-Tor exit")
	}
	return nil
}

// Reset is scoped to our GUID and protected directory. It never resets the
// physical adapters, global proxy, Winsock, or somebody else's firewall rules.
func (b *Backend) Reset() error {
	err := errors.Join(platform.RemoveAdapter(), platform.RestoreInterfaces(b.Dir), platform.FlushDNS(), os.RemoveAll(filepath.Join(b.Dir, "runtime")))
	if err != nil {
		return fmt.Errorf("cleanup failed; protection was retained: %w", err)
	}
	if b.Protection == nil {
		return fmt.Errorf("cannot release protection: manager is unavailable")
	}
	return b.Protection.Release()
}

// selectProxy deliberately never invokes startTor for a custom proxy. Resolve
// only the proxy's own hostname before the TUN is installed; destination DNS
// subsequently stays inside the selected proxy.
func selectProxy(ctx context.Context, c settings.Config, startTor func() (string, int, error)) (string, int, error) {
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	if c.Mode == settings.Tor {
		return startTor()
	}
	if ip, err := netip.ParseAddr(c.Proxy.Host); err == nil {
		return ip.String(), c.Proxy.Port, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", c.Proxy.Host)
	if err != nil {
		return "", 0, fmt.Errorf("resolve proxy host: %w", err)
	}
	if len(addresses) == 0 {
		return "", 0, fmt.Errorf("proxy hostname has no IP addresses")
	}
	// Prefer IPv4 where both families are available. A literal IPv6 endpoint
	// remains available for IPv6-only proxies.
	chosen := addresses[0]
	for _, ip := range addresses {
		if ip.Is4() {
			chosen = ip
			break
		}
	}
	return chosen.String(), c.Proxy.Port, nil
}

func (b *Backend) startTor(ctx context.Context, r assets.Runtime, progress func(string)) (*process.Child, int, error) {
	dataDir := filepath.Join(b.Dir, "data")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, 0, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	torrc := filepath.Join(r.Directory, "torrc")
	if err := os.WriteFile(torrc, nil, 0600); err != nil {
		return nil, 0, err
	}
	ready := make(chan struct{}, 1)
	bootstrap := regexp.MustCompile(`Bootstrapped (\d+)%`)
	progress("Starting Tor")
	child, err := process.Start(r.Tor.Binary, []string{
		"-f", torrc, "--DataDirectory", dataDir, "--SocksPort", "127.0.0.1:" + strconv.Itoa(port),
		"--GeoIPFile", r.Tor.GeoIP, "--GeoIPv6File", r.Tor.GeoIPv6, "--ClientOnly", "1",
		"--Log", "notice stdout", "--__OwningControllerProcess", strconv.Itoa(os.Getpid()),
	}, func(line string) {
		b.Log.Printf("[tor] %s", line)
		if m := bootstrap.FindStringSubmatch(line); m != nil {
			progress("Tor bootstrap " + m[1] + "%")
			if m[1] == "100" {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}
	})
	if err != nil {
		return nil, 0, err
	}
	if err := await(ctx, ready, child); err != nil {
		return child, port, fmt.Errorf("Tor startup: %w", err)
	}
	return child, port, nil
}
