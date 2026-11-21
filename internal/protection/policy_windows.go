//go:build windows

// Package protection owns Torinator's fail-closed Windows Filtering Platform
// policy. Persistent deny rules survive the UI and its child processes. TUN
// permissions are dynamic and disappear with the owning process/session.
package protection

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"

	"github.com/gharut/torinator/internal/settings"
	"golang.org/x/sys/windows"
)

var (
	providerID     = guid("{c930be74-7dde-4772-9075-7e6b45302426}")
	sublayerID     = guid("{a60fbc98-30ef-4615-9fb6-26c0ef538efd}")
	connect4       = guid("{c38d57d1-05a7-4c33-904f-7fbceee60e82}")
	connect6       = guid("{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}")
	receive4       = guid("{e1cd9fe7-f4b5-4273-96c0-592e487b8650}")
	receive6       = guid("{a3b42c97-9f04-4672-b87e-cee9c483257f}")
	forward4       = guid("{a82acc24-4ee1-4ee1-b465-fd1d25cb10a4}")
	forward6       = guid("{7b964818-19c7-493a-b71f-832c3684d28c}")
	appID          = guid("{d78e1e87-8644-4ea5-9437-d809ecefc971}")
	protocol       = guid("{3971ef2b-623e-4f9a-8cb1-6e79b806b9a7}")
	localIP        = guid("{d9ee00de-c1ef-4617-bfe3-ffd8f5a08957}")
	remoteIP       = guid("{b235ae9a-1d64-49b8-a44c-5ff3d9095045}")
	localPort      = guid("{0c1ba1af-5765-453f-af22-a8f791ac775b}")
	remotePort     = guid("{c35a604d-d22b-4e1a-91b4-68f674ee674b}")
	localInterface = guid("{4cd62a49-59c3-4969-b7f3-bda5d32890a4}")
)

const (
	actionBlock    = 0x1001
	actionPermit   = 0x1002
	flagPersistent = 1
	flagBoot       = 2
	flagHard       = 8
	flagDisabled   = 32
	kind8          = 1
	kind16         = 2
	kind32         = 3
	kind64         = 4
	kindArray16    = 11
	kindBlob       = 12
	kindV4         = 256
	kindV6         = 257
)

type value struct {
	Kind   uint32
	Number uint64
	Data   []byte
}
type condition struct {
	Field windows.GUID
	Op    uint32
	Value value
}
type rule struct {
	ID         windows.GUID
	Name       string
	Layer      windows.GUID
	Flags      uint32
	Weight     uint64
	Action     uint32
	Conditions []condition
}
type Plan struct {
	Mode           settings.Mode `json:"mode"`
	Host           string        `json:"host,omitempty"`
	Endpoint       netip.Addr    `json:"endpoint"`
	Port           uint16        `json:"port"`
	TorPath        string        `json:"tor_path,omitempty"`
	RouterPath     string        `json:"router_path"`
	LocalProxyPath string        `json:"local_proxy_path,omitempty"`
}

func guid(s string) windows.GUID {
	g, err := windows.GUIDFromString(s)
	if err != nil {
		panic(err)
	}
	return g
}
func ruleID(namespace windows.GUID, name string) windows.GUID {
	h := sha256.Sum256([]byte(namespace.String() + "/" + name))
	return windows.GUID{Data1: binary.BigEndian.Uint32(h[:4]), Data2: binary.BigEndian.Uint16(h[4:6]), Data3: binary.BigEndian.Uint16(h[6:8]), Data4: [8]byte(h[8:16])}
}
func number(field windows.GUID, kind uint32, n uint64) condition {
	return condition{Field: field, Value: value{Kind: kind, Number: n}}
}
func address(field windows.GUID, prefix string) condition {
	p := netip.MustParsePrefix(prefix).Masked()
	if p.Addr().Is4() {
		a := p.Addr().As4()
		b := make([]byte, 8)
		binary.LittleEndian.PutUint32(b, binary.BigEndian.Uint32(a[:]))
		var mask uint32
		if p.Bits() != 0 {
			mask = ^uint32(0) << (32 - p.Bits())
		}
		binary.LittleEndian.PutUint32(b[4:], mask)
		return condition{Field: field, Value: value{Kind: kindV4, Data: b}}
	}
	a := p.Addr().As16()
	data := append([]byte(nil), a[:]...)
	data = append(data, byte(p.Bits()))
	return condition{Field: field, Value: value{Kind: kindV6, Data: data}}
}
func application(path string) (condition, error) {
	data, err := nativeAppID(path)
	return condition{Field: appID, Value: value{Kind: kindBlob, Data: data}}, err
}

func baseRules(p Plan, namespace windows.GUID) ([]rule, error) {
	var rules []rule
	add := func(name string, layer windows.GUID, action uint32, weight uint64, conds ...condition) {
		rules = append(rules, rule{ID: ruleID(namespace, name), Name: name, Layer: layer, Action: action, Weight: weight, Flags: flagPersistent, Conditions: conds})
	}
	layers := []struct {
		name string
		id   windows.GUID
		v6   bool
	}{{"out4", connect4, false}, {"out6", connect6, true}, {"in4", receive4, false}, {"in6", receive6, true}}
	var tor, router, local, dhcp condition
	var err error
	if p.Mode == settings.Tor {
		tor, err = application(p.TorPath)
		if err != nil {
			return nil, err
		}
	} else if p.Mode != settings.SOCKS5 {
		return nil, fmt.Errorf("invalid protection mode")
	}
	if p.RouterPath == "" {
		return nil, fmt.Errorf("router path is required")
	}
	router, err = application(p.RouterPath)
	if err != nil {
		return nil, err
	}
	if p.LocalProxyPath != "" {
		local, err = application(p.LocalProxyPath)
		if err != nil {
			return nil, err
		}
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	dhcp, err = application(filepath.Join(system, "svchost.exe"))
	if err != nil {
		return nil, err
	}
	for _, layer := range layers {
		add("deny/"+layer.name, layer.id, actionBlock, 1)
		loop := "127.0.0.0/8"
		if layer.v6 {
			loop = "::1/128"
		}
		add("loopback/"+layer.name, layer.id, actionPermit, 100, address(remoteIP, loop))
		lp, rp := uint64(68), uint64(67)
		if layer.v6 {
			lp, rp = 546, 547
		}
		add("dhcp/"+layer.name, layer.id, actionPermit, 100, dhcp, number(protocol, kind8, 17), number(localPort, kind16, lp), number(remotePort, kind16, rp))
		if layer.v6 {
			for _, typ := range []uint64{133, 134, 135, 136} {
				for _, prefix := range []string{"fe80::/10", "ff02::/16"} {
					add(fmt.Sprintf("ndp/%s/%d/%s", layer.name, typ, prefix), layer.id, actionPermit, 100, number(protocol, kind8, 58), number(localPort, kind16, typ), address(remoteIP, prefix))
				}
			}
		}
		if p.Mode == settings.Tor {
			add("tor/"+layer.name, layer.id, actionPermit, 200, tor, number(protocol, kind8, 6))
		} else if p.LocalProxyPath != "" {
			for _, proto := range []uint64{6, 17} {
				add(fmt.Sprintf("local-proxy/%s/%d", layer.name, proto), layer.id, actionPermit, 200, local, number(protocol, kind8, proto))
			}
		} else {
			if !p.Endpoint.IsValid() || p.Endpoint.IsUnspecified() || p.Port == 0 {
				return nil, fmt.Errorf("a resolved SOCKS5 endpoint is required")
			}
			if p.Endpoint.Is6() == layer.v6 {
				bits := 32
				if layer.v6 {
					bits = 128
				}
				add("socks-control/"+layer.name, layer.id, actionPermit, 200, router, number(protocol, kind8, 6), address(remoteIP, netip.PrefixFrom(p.Endpoint, bits).String()), number(remotePort, kind16, uint64(p.Port)))
			}
			// SOCKS5 can delegate UDP to a different relay address/port on each
			// association. Only our protected router executable gets this permit.
			add("socks-relay/"+layer.name, layer.id, actionPermit, 200, router, number(protocol, kind8, 17))
		}
		boot := rule{ID: ruleID(namespace, "boot/"+layer.name), Name: "boot/" + layer.name, Layer: layer.id, Action: actionBlock, Weight: 1, Flags: flagBoot}
		rules = append(rules, boot)
	}
	for _, f := range []struct {
		name string
		id   windows.GUID
	}{{"forward4", forward4}, {"forward6", forward6}} {
		add("deny/"+f.name, f.id, actionBlock, 1)
		rules = append(rules, rule{ID: ruleID(namespace, "boot/"+f.name), Name: "boot/" + f.name, Layer: f.id, Action: actionBlock, Weight: 1, Flags: flagBoot})
	}
	return rules, nil
}
func tunnelRules(namespace windows.GUID, luid uint64) []rule {
	var rules []rule
	for _, l := range []struct {
		name string
		id   windows.GUID
		ip   string
	}{{"out4", connect4, "172.29.255.1/32"}, {"in4", receive4, "172.29.255.1/32"}, {"out6", connect6, "fdfe:dcba:9876::1/128"}, {"in6", receive6, "fdfe:dcba:9876::1/128"}} {
		rules = append(rules, rule{ID: ruleID(namespace, "tun/"+l.name), Name: "tun/" + l.name, Layer: l.id, Action: actionPermit, Weight: 300, Conditions: []condition{number(localInterface, kind64, luid), address(localIP, l.ip)}})
	}
	return rules
}

type Manager struct {
	Dir string
	mu  sync.Mutex
}
type Lease struct {
	mu      sync.Mutex
	session *nativeSession
	rules   []rule
	manager *Manager
}

// Arm atomically replaces only Torinator's base policy. It never removes the
// previous deny rules in a separate transaction or on an installation failure.
func (m *Manager) Arm(p Plan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rules, err := baseRules(p, providerID)
	if err != nil {
		return err
	}
	s, err := openNative(false)
	if err != nil {
		return err
	}
	defer s.close()
	if err := s.replace(rules); err != nil {
		return err
	}
	// A journal aids reconnection but is not the enforcement source of truth.
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.Dir, "protection.json"), data, 0600); err != nil {
		return fmt.Errorf("protection is armed but its recovery journal could not be saved: %w", err)
	}
	return s.verify(rules)
}
func (m *Manager) Active() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := openNative(false)
	if err != nil {
		return false, err
	}
	defer s.close()
	rules, err := s.rules()
	if missing(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(rules) == 0 {
		return false, nil
	}
	if err := s.checkObjects(); err != nil {
		return true, err
	}
	for _, layer := range []struct {
		name string
		id   windows.GUID
	}{{"out4", connect4}, {"out6", connect6}, {"in4", receive4}, {"in6", receive6}, {"forward4", forward4}, {"forward6", forward6}} {
		found := false
		for _, r := range rules {
			if r.ID == ruleID(providerID, "deny/"+layer.name) && r.Layer == layer.id && r.Weight == 1 && r.Action == actionBlock && r.Flags&flagPersistent != 0 && r.Flags&flagDisabled == 0 && len(r.Conditions) == 0 {
				found = true
			}
		}
		if !found {
			return true, fmt.Errorf("protection is incomplete; its %s deny rule is missing or changed", layer.name)
		}
	}
	return true, s.checkConflicts()
}
func (m *Manager) CachedEndpoint(host string) (netip.Addr, error) {
	data, err := os.ReadFile(filepath.Join(m.Dir, "protection.json"))
	if err != nil {
		return netip.Addr{}, err
	}
	var p Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return netip.Addr{}, err
	}
	if p.Mode != settings.SOCKS5 || p.Host != host || !p.Endpoint.IsValid() {
		return netip.Addr{}, fmt.Errorf("use a proxy IP address, or explicitly Disconnect before resolving a new proxy hostname")
	}
	return p.Endpoint, nil
}
func (m *Manager) OpenTunnel(luid uint64) (*Lease, error) {
	if luid == 0 {
		return nil, fmt.Errorf("invalid tunnel LUID")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := openNative(true)
	if err != nil {
		return nil, err
	}
	rules := tunnelRules(providerID, luid)
	if err := s.addDynamic(rules); err != nil {
		s.close()
		return nil, err
	}
	return &Lease{session: s, rules: rules, manager: m}, nil
}
func (l *Lease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.session == nil {
		return nil
	}
	err := l.session.close()
	if err == nil {
		l.session = nil
	}
	return err
}
func (m *Manager) Verify(p Plan, l *Lease) error {
	if l == nil {
		return fmt.Errorf("no protected tunnel permission")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	base, err := baseRules(p, providerID)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.session == nil {
		return fmt.Errorf("tunnel permission is not active")
	}
	return l.session.verify(append(base, l.rules...))
}
func (m *Manager) Release() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := openNative(false)
	if err != nil {
		return err
	}
	defer s.close()
	if err := s.remove(); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(m.Dir, "protection.json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func sameRule(a, b rule) bool {
	a.Name = ""
	b.Name = ""
	a.Flags &= flagPersistent | flagBoot | flagHard | flagDisabled
	b.Flags &= flagPersistent | flagBoot | flagHard | flagDisabled
	canonical := func(r *rule) {
		if len(r.Conditions) == 0 {
			r.Conditions = nil
			return
		}
		r.Conditions = append([]condition(nil), r.Conditions...)
		sort.Slice(r.Conditions, func(i, j int) bool {
			x, _ := json.Marshal(r.Conditions[i])
			y, _ := json.Marshal(r.Conditions[j])
			return string(x) < string(y)
		})
	}
	canonical(&a)
	canonical(&b)
	return reflect.DeepEqual(a, b)
}
