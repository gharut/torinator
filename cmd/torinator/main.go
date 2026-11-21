package main

import (
	"bytes"
	"context"
	_ "embed"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"

	"github.com/gharut/torinator/internal/tor"
)

//go:embed bundle.tar.gz
var bundle []byte

func run() error {
	port := flag.Int("port", 9050, "loopback SOCKS5 port")
	version := flag.Bool("tor-version", false, "print bundled Tor version and exit")
	flag.Parse()
	if *port < 1 || *port > 65535 || flag.NArg() != 0 {
		return fmt.Errorf("expected a port between 1 and 65535 and no positional arguments")
	}
	dir, err := os.MkdirTemp("", "torinator-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	files, err := tor.Unpack(bytes.NewReader(bundle), dir)
	if err != nil {
		return err
	}
	args := []string{"--version"}
	if !*version {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		data := filepath.Join(base, "Torinator", "data")
		if err := os.MkdirAll(data, 0700); err != nil {
			return err
		}
		config := filepath.Join(dir, "torinator.conf")
		if err := os.WriteFile(config, nil, 0600); err != nil {
			return err
		}
		args = []string{"-f", config, "--DataDirectory", data, "--SocksPort", "127.0.0.1:" + strconv.Itoa(*port), "--GeoIPFile", files.GeoIP, "--GeoIPv6File", files.GeoIPv6, "--ClientOnly", "1", "--Log", "notice stdout", "--__OwningControllerProcess", strconv.Itoa(os.Getpid())}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cmd := exec.CommandContext(ctx, files.Binary, args...)
	cmd.Dir = filepath.Dir(files.Binary)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "torinator:", err)
		os.Exit(1)
	}
}
