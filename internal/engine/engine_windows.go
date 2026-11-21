//go:build windows

// Package engine coordinates embedded Tor and the system-wide TUN router.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
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
	"github.com/gharut/torinator/internal/routing"
)

type Backend struct {
	Dir string
	Log *log.Logger
}
type connection struct {
	tor, router *process.Child
	done        chan struct{}
	err         error
	once        sync.Once
	stopErr     error
	dir         string
	health      chan error
}

func (s *connection) Done() <-chan struct{} { return s.done }
func (s *connection) Err() error            { <-s.done; return s.err }
func (s *connection) Health() <-chan error  { return s.health }
func (s *connection) Stop() error {
	s.once.Do(func() {
		if s.router != nil {
			s.stopErr = errors.Join(s.stopErr, s.router.StopGracefully())
		}
		if s.tor != nil {
			s.stopErr = errors.Join(s.stopErr, s.tor.StopGracefully())
		}
		s.stopErr = errors.Join(s.stopErr, platform.RemoveAdapter(), platform.RestoreInterfaces(s.dir), platform.FlushDNS())
	})
	return s.stopErr
}

func (b *Backend) Connect(ctx context.Context, progress func(string)) (result app.Connection, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	s := &connection{done: make(chan struct{}), dir: b.Dir, health: make(chan error, 1)}
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
	runtimeDir := filepath.Join(b.Dir, "runtime")
	if err = os.RemoveAll(runtimeDir); err != nil {
		return nil, err
	}
	r, err := assets.Extract(runtimeDir)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	dataDir := filepath.Join(b.Dir, "data")
	if err = os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	torrc := filepath.Join(runtimeDir, "torrc")
	if err = os.WriteFile(torrc, nil, 0600); err != nil {
		return nil, err
	}
	ready := make(chan struct{}, 1)
	bootstrap := regexp.MustCompile(`Bootstrapped (\d+)%`)
	progress("Starting Tor")
	s.tor, err = process.Start(r.Tor.Binary, []string{
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
		return nil, err
	}
	if err = await(ctx, ready, s.tor); err != nil {
		return nil, fmt.Errorf("Tor startup: %w", err)
	}
	config, err := routing.Config(r.Tor.Binary, port)
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
	progress("Verifying system routing through Tor")
	// Explicitly ignore application proxy settings. DNS and TCP must use the TUN.
	if err = Verify(ctx); err != nil {
		return nil, fmt.Errorf("system routing verification: %w", err)
	}
	healthCtx, stopHealth := context.WithCancel(context.Background())
	go func() {
		defer stopHealth()
		select {
		case <-s.tor.Done():
			s.err = fmt.Errorf("Tor stopped: %v", s.tor.Wait())
		case <-s.router.Done():
			s.err = fmt.Errorf("sing-box stopped: %v", s.router.Wait())
		}
		close(s.done)
	}()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				err := Verify(healthCtx)
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

func Verify(ctx context.Context) error {
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
	var result struct{ IsTor bool }
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Tor check returned HTTP %d", resp.StatusCode)
	}
	if err = json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 4096)).Decode(&result); err != nil {
		return err
	}
	if !result.IsTor {
		return fmt.Errorf("Tor check detected a non-Tor exit")
	}
	return nil
}

// Reset is scoped to our GUID and protected directory. It never resets the
// physical adapters, global proxy, Winsock, or somebody else's firewall rules.
func (b *Backend) Reset() error {
	return errors.Join(platform.RemoveAdapter(), platform.RestoreInterfaces(b.Dir), platform.FlushDNS(), os.RemoveAll(filepath.Join(b.Dir, "runtime")))
}
