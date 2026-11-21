//go:build windows

package platform

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/gharut/torinator/internal/process"
	"golang.org/x/sys/windows"
)

type interfaceState struct {
	GUID   string
	Family string
}

// sing-tun may temporarily disable WeakHostSend on existing interfaces. Keep a
// durable, GUID-scoped journal before allowing it to run, so Reset can recover
// those settings even if the router or tray process was forcibly terminated.
func SnapshotInterfaces(dir string) error {
	path := filepath.Join(dir, "interfaces.json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("interface recovery must finish before reconnecting")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := powershell(`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module (Join-Path $PSHOME 'Modules\NetAdapter\NetAdapter.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\NetTCPIP\NetTCPIP.psd1') -ErrorAction Stop
$adapters = @(Get-NetAdapter -IncludeHidden)
$items = @(foreach ($entry in (Get-NetIPInterface)) {
    if ([string]$entry.WeakHostSend -ne 'Enabled') { continue }
    $adapter = $adapters | Where-Object { $_.ifIndex -eq $entry.InterfaceIndex } | Select-Object -First 1
    if ($adapter -and $adapter.InterfaceGuid) {
        @{ GUID = $adapter.InterfaceGuid.ToString(); Family = [string]$entry.AddressFamily }
    }
})
ConvertTo-Json -InputObject $items -Compress
`)
	if err != nil {
		return fmt.Errorf("snapshot interface settings: %w", err)
	}
	states, err := decodeInterfaces(data)
	if err != nil {
		return err
	}
	data, err = json.Marshal(states)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func RestoreInterfaces(dir string) error {
	path := filepath.Join(dir, "interfaces.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	states, err := decodeInterfaces(data)
	if err != nil {
		return err
	}
	if len(states) > 0 {
		// Transport JSON as base64 data, never as executable PowerShell text.
		encoded := base64.StdEncoding.EncodeToString(data)
		_, err = powershell(`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module (Join-Path $PSHOME 'Modules\NetAdapter\NetAdapter.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\NetTCPIP\NetTCPIP.psd1') -ErrorAction Stop
$items = @([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + encoded + `')) | ConvertFrom-Json)
$adapters = @(Get-NetAdapter -IncludeHidden)
foreach ($entry in $items) {
    $adapter = $adapters | Where-Object { [string]$_.InterfaceGuid -eq $entry.GUID } | Select-Object -First 1
    if (!$adapter) { continue }
    $current = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily $entry.Family
    if ([string]$current.WeakHostSend -eq 'Disabled') {
        Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily $entry.Family -WeakHostSend Enabled -PolicyStore ActiveStore
    }
}
`)
		if err != nil {
			return fmt.Errorf("restore interface settings (journal retained): %w", err)
		}
	}
	return os.Remove(path)
}

func decodeInterfaces(data []byte) ([]interfaceState, error) {
	var states []interfaceState
	if err := json.Unmarshal(data, &states); err != nil {
		return nil, fmt.Errorf("invalid interface journal: %w", err)
	}
	if len(states) > 4096 {
		return nil, fmt.Errorf("interface journal too large")
	}
	for _, s := range states {
		id := s.GUID
		if !strings.HasPrefix(id, "{") {
			id = "{" + id + "}"
		}
		if _, err := windows.GUIDFromString(id); err != nil {
			return nil, fmt.Errorf("invalid interface GUID")
		}
		if s.Family != "IPv4" && s.Family != "IPv6" {
			return nil, fmt.Errorf("invalid interface family")
		}
	}
	return states, nil
}

func powershell(script string) ([]byte, error) {
	script = "try {\n" + script + "\n} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	words := utf16.Encode([]rune(script))
	data := make([]byte, len(words)*2)
	for i, w := range words {
		binary.LittleEndian.PutUint16(data[i*2:], w)
	}
	var output []string
	child, err := process.Start(filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), []string{
		"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(data),
	}, func(line string) { output = append(output, line) })
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
		child.Stop()
		return nil, fmt.Errorf("interface query/restore timed out")
	case <-child.Done():
		if err := child.Wait(); err != nil {
			return nil, fmt.Errorf("%w: %s", err, strings.Join(output, "\n"))
		}
		return []byte(strings.Join(output, "\n")), nil
	}
}
