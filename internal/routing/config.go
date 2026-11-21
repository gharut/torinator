// Package routing generates the deliberately small Tor-only routing policy.
package routing

import "encoding/json"

const AdapterName = "Torinator"

func Config(torPath string, port int) ([]byte, error) {
	type object = map[string]any
	return json.MarshalIndent(object{
		"log": object{"level": "info", "timestamp": true},
		"dns": object{
			"servers": []object{{"type": "https", "tag": "dns-via-tor", "server": "1.1.1.1", "detour": "tor"}},
			"final":   "dns-via-tor",
		},
		"inbounds": []object{{"type": "tun", "tag": "windows-tun", "interface_name": AdapterName,
			"address":    []string{"172.29.255.1/30", "fdfe:dcba:9876::1/126"},
			"auto_route": true, "strict_route": true, "stack": "gvisor", "mtu": 1500}},
		"outbounds": []object{
			{"type": "socks", "tag": "tor", "server": "127.0.0.1", "server_port": port, "version": "5", "network": "tcp"},
			{"type": "direct", "tag": "tor-relays"},
		},
		"route": object{
			"auto_detect_interface": true,
			"rules": []object{
				{"process_path": []string{torPath}, "network": "tcp", "action": "route", "outbound": "tor-relays"},
				{"port": 53, "action": "hijack-dns"},
				{"network": "tcp", "action": "route", "outbound": "tor"},
				{"action": "reject"},
			},
			"final": "tor",
		},
	}, "", "  ")
}
