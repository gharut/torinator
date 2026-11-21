//go:build windows

package platform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRejectInvalidRecoveryJournal(t *testing.T) {
	for _, data := range []string{`[{"GUID":"not-a-guid","Family":"IPv4"}]`, `[{"GUID":"{00112233-4455-6677-8899-aabbccddeeff}","Family":"bogus"}]`, `{}`} {
		if _, err := decodeInterfaces([]byte(data)); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}

// Snapshot only reads interface settings; Restore is deliberately not exercised
// against the developer's real adapters.
func TestReadOnlyInterfaceSnapshot(t *testing.T) {
	if os.Getenv("TORINATOR_PLATFORM_TEST") != "1" {
		t.Skip("requires Windows CIM network access")
	}
	dir := t.TempDir()
	if err := SnapshotInterfaces(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "interfaces.json"))
	if err != nil {
		t.Fatal(err)
	}
	var records []interfaceState
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatal(err)
	}
	if err := SnapshotInterfaces(dir); err == nil {
		t.Fatal("must not overwrite pending recovery data")
	}
}
