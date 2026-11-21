package settings

import "testing"

func TestValidateProxy(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"203.0.113.8", "proxy.example.com", "localhost", "::1", "2001:db8::1"} {
		c := Config{Mode: SOCKS5, Proxy: Proxy{Host: host, Port: 1080}}
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: %v", host, err)
		}
	}
	for _, p := range []Proxy{
		{Host: "socks5://proxy.example.com", Port: 1080}, {Host: "host:1080", Port: 1080}, {Host: "", Port: 1080},
		{Host: "host", Port: 0}, {Host: "host", Port: 65536}, {Host: "0.0.0.0", Port: 1080},
		{Host: "host", Port: 1080, Password: "secret"}, {Host: "host", Port: 1080, Username: "bad\x00value"},
	} {
		if err := (Config{Mode: SOCKS5, Proxy: p}).Validate(); err == nil {
			t.Fatalf("accepted invalid proxy host=%q port=%d", p.Host, p.Port)
		}
	}
}

func TestNormalizeIPv6AndKeepPasswordExact(t *testing.T) {
	c := Config{Mode: SOCKS5, Proxy: Proxy{Host: " [::1] ", Port: 1080, Username: "user", Password: " secret "}}.Normalized()
	if c.Proxy.Host != "::1" || c.Proxy.Password != " secret " {
		t.Fatal("normalization corrupted proxy settings")
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
