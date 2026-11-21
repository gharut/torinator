package routing

import (
	"encoding/json"
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
	if len(config.Inbounds) != 1 || len(config.Inbounds[0].Address) != 2 || !config.Inbounds[0].AutoRoute || !config.Inbounds[0].StrictRoute {
		t.Fatal("IPv4/IPv6 strict TUN routing is required")
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
