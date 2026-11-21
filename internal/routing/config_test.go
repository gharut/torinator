package routing

import (
	"encoding/json"
	"github.com/gharut/torinator/internal/settings"
	"testing"
)

func TestTorOnlyPolicy(t *testing.T) {
	const exe = `C:\ProgramData\Torinator\tor\tor.exe`
	data, err := Config(exe, 49123)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		DNS      struct{ Servers []struct{ Detour string } }
		Inbounds []struct {
			Address     []string
			AutoRoute   bool `json:"auto_route"`
			StrictRoute bool `json:"strict_route"`
		}
		Route struct{ Rules []map[string]any }
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 || len(config.Inbounds[0].Address) != 2 || !config.Inbounds[0].AutoRoute || config.Inbounds[0].StrictRoute {
		t.Fatal("IPv4/IPv6 TUN routing must use our WFP policy, without competing sing-box hard permits")
	}
	if len(config.DNS.Servers) != 1 || config.DNS.Servers[0].Detour != "tor" {
		t.Fatal("DNS must have no direct fallback")
	}
	rules := config.Route.Rules
	if len(rules) != 4 {
		t.Fatal("unexpected routing exceptions")
	}
	if rules[0]["outbound"] != "tor-relays" || rules[0]["network"] != "tcp" || rules[0]["process_path"].([]any)[0] != exe {
		t.Fatal("direct access must be scoped to the exact embedded Tor path")
	}
	if rules[1]["action"] != "hijack-dns" || rules[1]["port"] != float64(53) {
		t.Fatal("capture DNS before rejecting UDP")
	}
	if rules[2]["network"] != "tcp" || rules[2]["outbound"] != "tor" || rules[3]["action"] != "reject" {
		t.Fatal("only TCP may leave through Tor; other protocols must be rejected")
	}
}

func TestCustomProxyRoutesTCPUDPAndDNSWithoutDirectFallback(t *testing.T) {
	c := settings.Config{Mode: settings.SOCKS5, Proxy: settings.Proxy{Host: "proxy.example.com", Port: 1080, Username: "alice", Password: `a"b\\c`}}
	data, err := ForSettings(c, "", "203.0.113.8", 1080)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		DNS       struct{ Servers []struct{ Detour string } }
		Outbounds []map[string]any
		Route     struct {
			Rules []map[string]any
			Final string
		}
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Outbounds) != 1 || cfg.Outbounds[0]["type"] != "socks" || cfg.Outbounds[0]["server"] != "203.0.113.8" {
		t.Fatal("custom proxy must have no Tor/direct fallback")
	}
	o := cfg.Outbounds[0]
	if o["username"] != "alice" || o["password"] != c.Proxy.Password || o["network"] != nil {
		t.Fatal("credentials or UDP support were lost")
	}
	if cfg.DNS.Servers[0].Detour != "proxy" || cfg.Route.Final != "proxy" {
		t.Fatal("DNS and final routing must use the selected proxy")
	}
	rules := cfg.Route.Rules
	if len(rules) != 3 || rules[0]["action"] != "hijack-dns" || rules[2]["action"] != "reject" {
		t.Fatal("unexpected routing exception")
	}
	networks := rules[1]["network"].([]any)
	if len(networks) != 2 || networks[0] != "tcp" || networks[1] != "udp" || rules[1]["outbound"] != "proxy" {
		t.Fatal("TCP and UDP must both use the proxy")
	}
}
