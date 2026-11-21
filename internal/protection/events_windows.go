//go:build windows && amd64

package protection

import (
	"context"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FWPM_NET_EVENT0 is sufficient for packet-drop attribution and has no later
// SDK header unions. Only events matching this app and fresh probe port are read.
type eventHeader0 struct {
	Time                  windows.Filetime
	Flags, IPVersion      uint32
	Protocol              uint8
	_                     [3]byte // alignment of the SDK's UINT32/IPv6 union
	Local, Remote         [16]byte
	LocalPort, RemotePort uint16
	Scope                 uint32
	App                   blob
	User                  *windows.SID
}
type classifyDrop0 struct {
	FilterID uint64
	LayerID  uint16
}
type netEvent0 struct {
	Header eventHeader0
	Type   uint32
	Drop   *classifyDrop0
}
type eventTemplate struct {
	Start, End windows.Filetime
	Count      uint32
	Conditions *nativeCondition
}

func (s *nativeSession) probeWasDropped(app []byte, port uint16, since time.Time) (bool, error) {
	var keep []any
	cond := nativeCondition{Field: appID, Value: marshalValue(value{Kind: kindBlob, Data: app}, &keep)}
	tpl := eventTemplate{Start: windows.NsecToFiletime(since.Add(-time.Second).UnixNano()), End: windows.NsecToFiletime(time.Now().Add(time.Second).UnixNano()), Count: 1, Conditions: &cond}
	var enum windows.Handle
	err := call("FwpmNetEventCreateEnumHandle0", uintptr(s.handle), uintptr(unsafe.Pointer(&tpl)), uintptr(unsafe.Pointer(&enum)))
	runtime.KeepAlive(keep)
	if err != nil {
		return false, err
	}
	defer call("FwpmNetEventDestroyEnumHandle0", uintptr(s.handle), uintptr(enum))
	for {
		var entries **netEvent0
		var count uint32
		if err := call("FwpmNetEventEnum0", uintptr(s.handle), uintptr(enum), 128, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&count))); err != nil {
			return false, err
		}
		if count == 0 {
			return false, nil
		}
		found, err := func() (bool, error) {
			defer free(unsafe.Pointer(&entries))
			for _, e := range unsafe.Slice(entries, int(count)) {
				if e.Type != 3 || e.Drop == nil || e.Header.Protocol != 17 || e.Header.LocalPort != port {
					continue
				}
				var filter *nativeFilter
				if err := call("FwpmFilterGetById0", uintptr(s.handle), uintptr(e.Drop.FilterID), uintptr(unsafe.Pointer(&filter))); err != nil {
					return false, err
				}
				owned := filter.Provider != nil && *filter.Provider == s.provider && filter.Sublayer == s.sublayer && filter.Action.Type == actionBlock
				free(unsafe.Pointer(&filter))
				if owned {
					return true, nil
				}
			}
			return false, nil
		}()
		if found || err != nil {
			return found, err
		}
	}
}
func (s *nativeSession) waitForDrop(ctx context.Context, app []byte, port uint16, since time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for {
		ok, err := s.probeWasDropped(app, port, since)
		if err != nil {
			return fmt.Errorf("cannot confirm UDP denial in WFP drop events (event collection must be enabled): %w", err)
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no Torinator WFP drop event confirmed the UDP probe")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func init() {
	if unsafe.Sizeof(eventHeader0{}) != 88 || unsafe.Offsetof(eventHeader0{}.LocalPort) != 52 || unsafe.Offsetof(netEvent0{}.Drop) != 96 {
		panic("unsupported WFP event layout")
	}
}
