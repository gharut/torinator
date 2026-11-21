package tor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"testing"
)

func archive(t *testing.T, names ...string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0600, Size: 1}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func TestExtractRuntime(t *testing.T) {
	files, err := Unpack(archive(t, "./tor/tor.exe", "data/geoip", "data/geoip6", "tor/lib.dll"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{files.Binary, files.GeoIP, files.GeoIPv6} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "x" {
			t.Fatalf("read %q: %q, %v", path, data, err)
		}
	}
}

func TestRejectInvalidBundle(t *testing.T) {
	for _, name := range []string{"../outside", "/outside", "tor/tor.exe"} {
		if _, err := Unpack(archive(t, name), t.TempDir()); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
}
