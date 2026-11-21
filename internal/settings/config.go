// Package settings holds the selected routing provider and proxy preferences.
package settings

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

type Mode string

const (
	Tor    Mode = "tor"
	SOCKS5 Mode = "socks5"
)

type Proxy struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"-"`
}
type Config struct {
	Mode  Mode  `json:"mode"`
	Proxy Proxy `json:"proxy"`
}

func Default() Config { return Config{Mode: Tor, Proxy: Proxy{Port: 1080}} }
func (c Config) Normalized() Config {
	c.Proxy.Host = strings.TrimSpace(c.Proxy.Host)
	if strings.HasPrefix(c.Proxy.Host, "[") && strings.HasSuffix(c.Proxy.Host, "]") {
		c.Proxy.Host = strings.Trim(c.Proxy.Host, "[]")
	}
	return c
}
func (c Config) Validate() error {
	if c.Mode == Tor {
		return nil
	}
	if c.Mode != SOCKS5 {
		return fmt.Errorf("select Tor or a custom SOCKS5 proxy")
	}
	if !validHost(c.Proxy.Host) {
		return fmt.Errorf("enter a proxy IP address or DNS hostname, without a URL scheme or port")
	}
	if c.Proxy.Port < 1 || c.Proxy.Port > 65535 {
		return fmt.Errorf("proxy port must be between 1 and 65535")
	}
	if len(c.Proxy.Username) > 255 || len(c.Proxy.Password) > 255 {
		return fmt.Errorf("SOCKS5 username and password must each fit in 255 UTF-8 bytes")
	}
	if strings.ContainsRune(c.Proxy.Username, 0) || strings.ContainsRune(c.Proxy.Password, 0) {
		return fmt.Errorf("credentials cannot contain NUL characters")
	}
	if c.Proxy.Password != "" && c.Proxy.Username == "" {
		return fmt.Errorf("enter a username when using a password")
	}
	return nil
}
func validHost(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == "" && !addr.IsUnspecified() && !addr.IsMulticast()
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
func (c Config) Label() string {
	if c.Mode == Tor {
		return "Tor"
	}
	return "SOCKS5 " + net.JoinHostPort(c.Proxy.Host, fmt.Sprint(c.Proxy.Port))
}
