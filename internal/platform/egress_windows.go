//go:build windows

package platform

import (
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")

func TunnelLUID() (uint64, error) {
	id := AdapterGUID()
	var luid uint64
	r, _, _ := ipHelper.NewProc("ConvertInterfaceGuidToLuid").Call(uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&luid)))
	if r != 0 {
		return 0, fmt.Errorf("identify Torinator adapter: %w", windows.Errno(r))
	}
	return luid, nil
}

// Capture sources of the pre-TUN default routes for direct-connect denial
// probes. Down/unrouted virtual adapters must not count as successful blocking.
func EgressSources() ([]netip.Addr, error) {
	var ret []netip.Addr
	for _, v6 := range []bool{false, true} {
		var index uint32
		var r uintptr
		if v6 {
			a := windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: netip.MustParseAddr("2606:4700:4700::1111").As16()}
			r, _, _ = ipHelper.NewProc("GetBestInterfaceEx").Call(uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(&index)))
		} else {
			a := windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: [4]byte{1, 1, 1, 1}}
			r, _, _ = ipHelper.NewProc("GetBestInterfaceEx").Call(uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(&index)))
		}
		if r != 0 {
			continue
		}
		iface, err := net.InterfaceByIndex(int(index))
		if err != nil {
			return nil, err
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addresses {
			p, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := p.Addr().Unmap()
			if ip.Is6() != v6 || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			ret = append(ret, ip)
			break
		}
	}
	if len(ret) == 0 {
		return nil, fmt.Errorf("no usable pre-tunnel default route to test")
	}
	return ret, nil
}
