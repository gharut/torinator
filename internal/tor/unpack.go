package tor

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Files struct{ Binary, GeoIP, GeoIPv6 string }

// Unpack expands a checksum-pinned expert bundle into a fresh private directory.
func Unpack(src io.Reader, dir string) (Files, error) {
	var files Files
	gz, err := gzip.NewReader(src)
	if err != nil {
		return files, err
	}
	defer gz.Close()
	r := tar.NewReader(gz)
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return files, err
		}
		name := filepath.FromSlash(h.Name)
		if !filepath.IsLocal(name) || strings.ContainsAny(h.Name, "\\:") {
			return files, fmt.Errorf("unsafe archive path %q", h.Name)
		}
		dest := filepath.Join(dir, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, 0700); err != nil {
				return files, err
			}
		case tar.TypeReg:
			if err := writeFile(dest, r); err != nil {
				return files, err
			}
			switch filepath.Base(dest) {
			case "tor.exe":
				files.Binary = dest
			case "geoip":
				files.GeoIP = dest
			case "geoip6":
				files.GeoIPv6 = dest
			}
		default:
			return files, fmt.Errorf("unsupported archive entry %q", h.Name)
		}
	}
	if files.Binary == "" || files.GeoIP == "" || files.GeoIPv6 == "" {
		return files, fmt.Errorf("incomplete Tor expert bundle")
	}
	return files, nil
}

func writeFile(dest string, src io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, src)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
