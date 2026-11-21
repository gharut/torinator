// Package assets owns the checksum-pinned, build-time embedded Windows runtimes.
package assets

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gharut/torinator/internal/tor"
)

//go:embed tor.tar.gz
var torArchive []byte

//go:embed sing-box.zip
var singArchive []byte

//go:embed wintun.zip
var wintunArchive []byte

//go:embed THIRD_PARTY_NOTICES.md
var Notices string

const Versions = "Tor expert bundle 16.0.1; sing-box 1.14.4; Wintun 0.14.1"

type Runtime struct {
	Tor                        tor.Files
	SingBox, Wintun, Directory string
}

// Extract requires an empty private directory. No downloads occur at runtime.
func Extract(dir string) (Runtime, error) {
	r := Runtime{Directory: dir}
	var err error
	r.Tor, err = tor.Unpack(bytes.NewReader(torArchive), filepath.Join(dir, "tor"))
	if err != nil {
		return r, fmt.Errorf("extract Tor: %w", err)
	}
	if err = extractZIP(singArchive, filepath.Join(dir, "sing-box"), map[string]string{
		"sing-box-1.14.4-windows-amd64/sing-box.exe":  "sing-box.exe",
		"sing-box-1.14.4-windows-amd64/libcronet.dll": "libcronet.dll",
		"sing-box-1.14.4-windows-amd64/LICENSE":       "LICENSE",
	}); err != nil {
		return r, err
	}
	if err = extractZIP(wintunArchive, filepath.Join(dir, "sing-box"), map[string]string{
		"wintun/bin/amd64/wintun.dll": "wintun.dll",
		"wintun/LICENSE.txt":          "WINTUN-LICENSE.txt",
	}); err != nil {
		return r, err
	}
	r.SingBox = filepath.Join(dir, "sing-box", "sing-box.exe")
	r.Wintun = filepath.Join(dir, "sing-box", "wintun.dll")
	return r, nil
}

func extractZIP(data []byte, dir string, allow map[string]string) error {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	found := make(map[string]bool)
	for _, f := range z.File {
		name, ok := allow[f.Name]
		if !ok {
			continue
		}
		if found[f.Name] || !filepath.IsLocal(name) || f.Mode()&os.ModeType != 0 || f.UncompressedSize64 > 256<<20 {
			return fmt.Errorf("invalid ZIP entry %q", f.Name)
		}
		src, err := f.Open()
		if err != nil {
			return err
		}
		err = copyFile(filepath.Join(dir, name), src)
		src.Close()
		if err != nil {
			return err
		}
		found[f.Name] = true
	}
	if len(found) != len(allow) {
		return fmt.Errorf("incomplete runtime ZIP")
	}
	return nil
}

func copyFile(path string, src io.Reader) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, src)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
