package assets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCustomProxyExtractionOmitsTor(t *testing.T) {
	dir := t.TempDir()
	r, err := ExtractForMode(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if r.Tor.Binary != "" {
		t.Fatal("custom mode supplied a Tor executable")
	}
	if _, err := os.Stat(filepath.Join(dir, "tor")); !os.IsNotExist(err) {
		t.Fatal("custom mode extracted Tor")
	}
	for _, file := range []string{r.SingBox, r.Wintun} {
		if _, err := os.Stat(file); err != nil {
			t.Fatal(err)
		}
	}
}
