//go:build windows

package platform

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// A local SOCKS daemon needs its own path-scoped exception; otherwise its
// upstream connections would re-enter the TUN and loop back into itself.
// Remote proxy transport is bound to the physical interface by sing-box.
func LocalProxyProcess(server string, port int) (string, error) {
	ip, err := netip.ParseAddr(server)
	if err != nil {
		return "", err
	}
	local := ip.IsLoopback()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, a := range addresses {
		if p, e := netip.ParsePrefix(a.String()); e == nil && p.Addr().Unmap() == ip.Unmap() {
			local = true
		}
	}
	if !local {
		return "", nil
	}
	anyAddress := "0.0.0.0"
	if ip.Is6() {
		anyAddress = "::"
	}
	data, err := powershell(`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module (Join-Path $PSHOME 'Modules\NetTCPIP\NetTCPIP.psd1') -ErrorAction Stop
$connections = @(Get-NetTCPConnection -State Listen -LocalPort ` + strconv.Itoa(port) + ` -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -eq '` + ip.String() + `' -or $_.LocalAddress -eq '` + anyAddress + `' })
$owners = @($connections | Select-Object -ExpandProperty OwningProcess -Unique)
if ($owners.Count -ne 1) { throw 'Start your local SOCKS5 proxy first; its listening process must be identifiable.' }
$process = Get-Process -Id $owners[0] -ErrorAction Stop
if (!$process.Path) { throw 'Cannot identify the local proxy executable path.' }
ConvertTo-Json -InputObject ([string]$process.Path) -Compress
`)
	if err != nil {
		return "", fmt.Errorf("identify local proxy: %w", err)
	}
	var path string
	if err := json.Unmarshal(data, &path); err != nil || path == "" {
		return "", fmt.Errorf("cannot identify local proxy executable")
	}
	return path, nil
}
