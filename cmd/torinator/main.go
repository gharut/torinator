//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gharut/torinator/internal/app"
	"github.com/gharut/torinator/internal/assets"
	"github.com/gharut/torinator/internal/buildinfo"
	"github.com/gharut/torinator/internal/engine"
	"github.com/gharut/torinator/internal/platform"
	"github.com/gharut/torinator/internal/process"
	"github.com/gharut/torinator/internal/protection"
	"github.com/gharut/torinator/internal/routing"
	"github.com/gharut/torinator/internal/settings"
	"github.com/gharut/torinator/internal/tray"
	"golang.org/x/sys/windows"
)

func run() error {
	appVersion := flag.Bool("version", false, "print application version and source revision")
	selfTest := flag.Bool("self-test", false, "check embedded runtimes/configuration offline without elevation or network changes")
	version := flag.Bool("tor-version", false, "print embedded runtime versions and exit")
	licenses := flag.Bool("licenses", false, "print bundled software notices and source links")
	resetNetwork := flag.Bool("reset-network", false, "remove Torinator protection and restore normal networking, then exit")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *licenses {
		fmt.Print(assets.Notices)
		return nil
	}
	if *appVersion {
		fmt.Println(buildinfo.String())
		return nil
	}
	if *selfTest {
		return checkRuntimes()
	}
	if *version {
		fmt.Println(assets.Versions)
		return nil
	}
	if launched, err := platform.Elevate(); err != nil || launched {
		return err
	}
	release, err := platform.SingleInstance()
	if err != nil {
		return err
	}
	defer release()
	dir, err := platform.Store()
	if err != nil {
		return err
	}
	logPath := filepath.Join(dir, "torinator.log")
	if info, err := os.Stat(logPath); err == nil && info.Size() > 2<<20 {
		os.Remove(logPath + ".old")
		os.Rename(logPath, logPath+".old")
	}
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	logger := log.New(file, "", log.LstdFlags)
	logger.Printf("Starting %s; %s", buildinfo.String(), assets.Versions)
	guard := &protection.Manager{Dir: dir}
	if *resetNetwork {
		backend := &engine.Backend{Dir: dir, Log: logger, Protection: guard}
		if err := backend.Reset(); err != nil {
			tray.Alert("Torinator recovery", err.Error())
			return err
		}
		tray.Alert("Torinator recovery", "Protection removed. Normal Windows networking is restored.")
		return nil
	}
	preferences, err := settings.Open(dir)
	if err != nil {
		return err
	}
	backend := &engine.Backend{Dir: dir, Log: logger, Settings: preferences, Protection: guard}
	c := app.NewWithSettings(backend, preferences, func(s app.Status) { logger.Printf("%s: %s", s.State, s.Detail) })
	defer c.Close()
	return tray.Run(c, logPath)
}

func checkRuntimes() error {
	dir, err := os.MkdirTemp("", "torinator-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	r, err := assets.Extract(dir)
	if err != nil {
		return err
	}
	dll, err := windows.LoadLibraryEx(r.Wintun, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return fmt.Errorf("load embedded Wintun: %w", err)
	}
	_, procErr := windows.GetProcAddress(dll, "WintunCreateAdapter")
	windows.FreeLibrary(dll)
	if procErr != nil {
		return procErr
	}
	config, err := routing.Config(r.Tor.Binary, 9050)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "check.json")
	if err := os.WriteFile(path, config, 0600); err != nil {
		return err
	}
	custom := settings.Config{Mode: settings.SOCKS5, Proxy: settings.Proxy{Host: "203.0.113.8", Port: 1080, Username: "offline-test", Password: "offline-test"}}
	customData, err := routing.ForSettings(custom, "", "203.0.113.8", 1080)
	if err != nil {
		return err
	}
	customPath := filepath.Join(dir, "custom-check.json")
	if err := os.WriteFile(customPath, customData, 0600); err != nil {
		return err
	}
	for _, test := range []struct {
		exe  string
		args []string
	}{
		{r.Tor.Binary, []string{"--version"}}, {r.SingBox, []string{"version"}}, {r.SingBox, []string{"check", "-c", path}},
		{r.SingBox, []string{"check", "-c", customPath}},
	} {
		child, err := process.Start(test.exe, test.args, func(line string) { fmt.Println(line) })
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		select {
		case <-ctx.Done():
			child.Stop()
			cancel()
			return fmt.Errorf("runtime check timed out")
		case <-child.Done():
			cancel()
			if err := child.Wait(); err != nil {
				return err
			}
		}
	}
	// Exercise Tor's actual shutdown handler with networking explicitly disabled.
	// This protects persisted guard state during ordinary Disconnect/Exit.
	torrc := filepath.Join(dir, "offline-torrc")
	if err := os.WriteFile(torrc, nil, 0600); err != nil {
		return err
	}
	ready := make(chan struct{}, 1)
	child, err := process.Start(r.Tor.Binary, []string{"-f", torrc, "--DisableNetwork", "1", "--SocksPort", "0", "--ClientOnly", "1", "--DataDirectory", filepath.Join(dir, "offline-data"), "--GeoIPFile", r.Tor.GeoIP, "--GeoIPv6File", r.Tor.GeoIPv6, "--Log", "notice stdout"}, func(line string) {
		fmt.Println(line)
		if strings.Contains(line, "Bootstrapped 0%") {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	})
	if err != nil {
		return err
	}
	select {
	case <-ready:
		if err := child.StopGracefully(); err != nil {
			return fmt.Errorf("offline Tor shutdown: %w", err)
		}
	case <-child.Done():
		return fmt.Errorf("offline Tor stopped before ready: %v", child.Wait())
	case <-time.After(20 * time.Second):
		child.Stop()
		return fmt.Errorf("offline Tor startup timed out")
	}
	fmt.Println("Embedded runtime and routing configuration checks passed; no networking changed.")
	return nil
}
func main() {
	if handled, err := process.InterruptHelper(); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "torinator:", err)
		if len(os.Args) == 1 {
			tray.Alert("Torinator", err.Error())
		}
		os.Exit(1)
	}
}
