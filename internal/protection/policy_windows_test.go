//go:build windows

package protection

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"sort"
	"testing"

	"github.com/gharut/torinator/internal/settings"
	"golang.org/x/sys/windows"
)

type packet struct {
	app                 []byte
	proto, lp, rp, luid uint64
	local, remote       netip.Addr
}

func matches(c condition, p packet) bool {
	if c.Field == appID {
		return bytes.Equal(c.Value.Data, p.app)
	}
	if c.Field == protocol {
		return c.Value.Number == p.proto
	}
	if c.Field == localPort {
		return c.Value.Number == p.lp
	}
	if c.Field == remotePort {
		return c.Value.Number == p.rp
	}
	if c.Field == localInterface {
		return c.Value.Number == p.luid
	}
	ip := p.remote
	if c.Field == localIP {
		ip = p.local
	}
	if c.Value.Kind == kindV4 {
		if !ip.Is4() {
			return false
		}
		a := ip.As4()
		mask := binary.LittleEndian.Uint32(c.Value.Data[4:])
		return binary.BigEndian.Uint32(a[:])&mask == binary.LittleEndian.Uint32(c.Value.Data)
	}
	if c.Value.Kind == kindV6 {
		if !ip.Is6() {
			return false
		}
		a := [16]byte(c.Value.Data[:16])
		return netip.PrefixFrom(netip.AddrFrom16(a), int(c.Value.Data[16])).Contains(ip)
	}
	return false
}
func verdict(rules []rule, layer windows.GUID, p packet) uint32 {
	rules = append([]rule(nil), rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].Weight > rules[j].Weight })
	for _, r := range rules {
		if r.Layer != layer || r.Flags&flagBoot != 0 {
			continue
		}
		ok := true
		for _, c := range r.Conditions {
			if !matches(c, p) {
				ok = false
				break
			}
		}
		if ok {
			return r.Action
		}
	}
	return 0
}
func TestFailClosedPolicyMatrix(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	transport, err := nativeAppID(exe)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []settings.Mode{settings.Tor, settings.SOCKS5} {
		t.Run(string(mode), func(t *testing.T) {
			p := Plan{Mode: mode, TorPath: exe, RouterPath: exe, Endpoint: netip.MustParseAddr("203.0.113.8"), Port: 1080}
			rules, err := baseRules(p, providerID)
			if err != nil {
				t.Fatal(err)
			}
			ordinary := packet{app: []byte("untrusted application"), proto: 6, rp: 443, local: netip.MustParseAddr("192.0.2.5"), remote: netip.MustParseAddr("1.1.1.1"), luid: 77}
			for _, layer := range []windows.GUID{connect4, receive4} {
				if verdict(rules, layer, ordinary) != actionBlock {
					t.Fatal("ordinary TCP bypass was allowed")
				}
			}
			ordinary.proto = 17
			ordinary.rp = 53
			if verdict(rules, connect4, ordinary) != actionBlock {
				t.Fatal("direct UDP/DNS bypass was allowed")
			}
			ordinary.local = netip.MustParseAddr("2001:db8::5")
			ordinary.remote = netip.MustParseAddr("2606:4700:4700::1111")
			if verdict(rules, connect6, ordinary) != actionBlock || verdict(rules, receive6, ordinary) != actionBlock {
				t.Fatal("IPv6 bypass was allowed")
			}
			tunneled := packet{app: []byte("ordinary"), proto: 6, rp: 443, local: netip.MustParseAddr("172.29.255.1"), remote: netip.MustParseAddr("1.1.1.1"), luid: 900}
			if verdict(rules, connect4, tunneled) != actionBlock {
				t.Fatal("tunnel traffic allowed without a live permission lease")
			}
			withTunnel := append(append([]rule(nil), rules...), tunnelRules(providerID, 900)...)
			if verdict(withTunnel, connect4, tunneled) != actionPermit {
				t.Fatal("live tunnel denied")
			}
			tunneled.luid = 901
			if verdict(withTunnel, connect4, tunneled) != actionBlock {
				t.Fatal("binding another interface bypassed protection")
			}
			tunneled.luid = 900
			tunneled.local = netip.MustParseAddr("192.0.2.5")
			if verdict(withTunnel, connect4, tunneled) != actionBlock {
				t.Fatal("weak-host source address bypassed protection")
			}
			legit := packet{app: transport, proto: 6, rp: 1080, local: netip.MustParseAddr("192.0.2.5"), remote: p.Endpoint}
			if verdict(rules, connect4, legit) != actionPermit {
				t.Fatal("selected proxy transport is blocked")
			}
			legit.remote = netip.MustParseAddr("198.51.100.9")
			if mode == settings.SOCKS5 && verdict(rules, connect4, legit) != actionBlock {
				t.Fatal("router TCP escaped the selected SOCKS endpoint")
			}
			legit.proto = 17
			want := uint32(actionBlock)
			if mode == settings.SOCKS5 {
				want = actionPermit
			}
			if verdict(rules, connect4, legit) != want {
				t.Fatal("incorrect proxy UDP transport permission")
			}
			boots := 0
			for _, r := range rules {
				if r.Flags&flagBoot != 0 {
					boots++
					if r.Action != actionBlock || len(r.Conditions) != 0 {
						t.Fatal("boot-time traffic is not fail-closed")
					}
				}
			}
			if boots != 6 {
				t.Fatal("boot-time IPv4/IPv6 host and forwarding coverage is incomplete")
			}
		})
	}
}
func TestRuleComparisonDetectsPolicyChanges(t *testing.T) {
	r := tunnelRules(providerID, 123)[0]
	if !sameRule(r, r) {
		t.Fatal("identical policy differs")
	}
	changed := r
	changed.Conditions = append([]condition(nil), r.Conditions...)
	changed.Conditions[0].Value.Number = 999
	if sameRule(r, changed) {
		t.Fatal("changed interface permission was accepted")
	}
	changed = r
	changed.Flags |= flagDisabled
	if sameRule(r, changed) {
		t.Fatal("disabled policy was accepted")
	}
	changed = r
	changed.Flags |= flagHard
	if sameRule(r, changed) {
		t.Fatal("hard-permit policy change was accepted")
	}
}
