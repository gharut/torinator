// Package routing generates a TUN policy with a single selected proxy outbound.
package routing

import (
	"encoding/json"
	"github.com/gharut/torinator/internal/settings"
)

const AdapterName = "Torinator"

func Config(torPath string, port int) ([]byte, error) {
	return ForSettings(settings.Default(), torPath, "127.0.0.1", port)
}

// server is an already resolved proxy endpoint, avoiding bootstrap DNS loops.
func ForSettings(c settings.Config, torPath, server string, port int) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	type object = map[string]any
	tag := "tor"
	if c.Mode == settings.SOCKS5 {
		tag = "proxy"
	}
	socks := object{"type": "socks", "tag": tag, "server": server, "server_port": port, "version": "5"}
	outbounds := []object{socks}
	rules := []object{}
	if c.Mode == settings.Tor {
		socks["network"] = "tcp"
		outbounds = append(outbounds, object{"type": "direct", "tag": "tor-relays"})
		rules = append(rules, object{"process_path": []string{torPath}, "network": "tcp", "action": "route", "outbound": "tor-relays"})
	} else {
		if c.Proxy.Username != "" {
			socks["username"] = c.Proxy.Username
			socks["password"] = c.Proxy.Password
		}
		if torPath != "" {
			outbounds = append(outbounds, object{"type": "direct", "tag": "proxy-process"})
			rules = append(rules, object{"process_path": []string{torPath}, "network": []string{"tcp", "udp"}, "action": "route", "outbound": "proxy-process"})
		}
	}
	rules = append(rules, object{"port": 53, "action": "hijack-dns"})
	var networks any = "tcp"
	if c.Mode == settings.SOCKS5 {
		networks = []string{"tcp", "udp"}
	}
	rules = append(rules, object{"network": networks, "action": "route", "outbound": tag}, object{"action": "reject"})
	return json.MarshalIndent(object{
		"log": object{"level": "info", "timestamp": true},
		"dns": object{
			"servers": []object{{"type": "https", "tag": "dns-via-proxy", "server": "1.1.1.1", "detour": tag}},
			"final":   "dns-via-proxy",
		},
		"inbounds": []object{{"type": "tun", "tag": "windows-tun", "interface_name": AdapterName,
			"address": []string{"172.29.255.1/30", "fdfe:dcba:9876::1/126"},
			// The persistent protection manager owns WFP enforcement. sing-box's
			// separate highest-priority hard permits would conflict with it.
			"auto_route": true, "strict_route": false, "stack": "gvisor", "mtu": 1500}},
		"outbounds": outbounds,
		"route": object{
			"auto_detect_interface": true,
			"rules":                 rules,
			"final":                 tag,
		},
	}, "", "  ")
}
