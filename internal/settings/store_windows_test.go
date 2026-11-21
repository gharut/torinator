//go:build windows

package settings

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistModeAndProtectPassword(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if store.Current().Mode != Tor {
		t.Fatal("first run must select Tor")
	}
	c := Config{Mode: SOCKS5, Proxy: Proxy{Host: "proxy.example.com", Port: 1080, Username: "alice", Password: "never-store-this-plaintext"}}
	if err := store.Save(c); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(c.Proxy.Password)) || !bytes.Contains(data, []byte("protected_password")) {
		t.Fatal("saved password is not protected")
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Current() != c {
		t.Fatal("saved settings did not round trip")
	}
	bad := c
	bad.Proxy.Port = 0
	if err := store.Save(bad); err == nil {
		t.Fatal("accepted invalid settings")
	}
	if store.Current() != c {
		t.Fatal("failed save changed the active profile")
	}
	c.Mode = Tor
	if err := store.Save(c); err != nil {
		t.Fatal(err)
	}
	reopened, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Current() != c {
		t.Fatal("Tor selection or inactive proxy details were lost")
	}
}
func TestCorruptSettingsCannotSilentlySwitchToTor(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"mode":"socks5","proxy":{"host":"host","port":0}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("must not use default Tor after corrupt saved settings")
	}
}
