package scanner

import (
	"net/netip"
	"testing"
)

func TestIPPDescriptionURL(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.19")
	v6 := netip.MustParseAddr("fe80::19%en0")
	for _, test := range []struct {
		name string
		peer netip.Addr
		ad   Advertisement
		want string
	}{
		{"IPP path", v4, Advertisement{Protocol: "mdns", Service: "_ipp._tcp", Port: 631, Properties: map[string]string{"rp": "ipp/print"}}, "http://192.0.2.19:631/ipp/print"},
		{"IPPS leading slash and space", v4, Advertisement{Protocol: "mdns", Service: "_IPPS._TCP", Port: 443, Properties: map[string]string{"rp": "/queue/Office Printer"}}, "https://192.0.2.19:443/queue/Office%20Printer"},
		{"scoped IPv6", v6, Advertisement{Protocol: "mdns", Service: "_ipp._tcp", Port: 631, Properties: map[string]string{"rp": "/ipp/print"}}, "http://[fe80::19%25en0]:631/ipp/print"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ippDescriptionURL(test.peer, test.ad); got != test.want {
				t.Fatalf("ippDescriptionURL() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestIPPDescriptionURLRejectsUntrustedEndpointParts(t *testing.T) {
	peer := netip.MustParseAddr("192.0.2.19")
	base := Advertisement{Protocol: "mdns", Service: "_ipp._tcp", Port: 631, Properties: map[string]string{"rp": "/ipp/print"}}
	bad := []func(*Advertisement){
		func(a *Advertisement) { a.Protocol = "ssdp" },
		func(a *Advertisement) { a.Service = "_ipp-backup._tcp" },
		func(a *Advertisement) { a.Port = 0 },
		func(a *Advertisement) { delete(a.Properties, "rp") },
		func(a *Advertisement) { a.Properties["rp"] = "https://other.invalid/ipp" },
		func(a *Advertisement) { a.Properties["rp"] = "//other.invalid/ipp" },
		func(a *Advertisement) { a.Properties["rp"] = "/ipp/../admin" },
		func(a *Advertisement) { a.Properties["rp"] = "/ipp/%2e%2e/admin" },
		func(a *Advertisement) { a.Properties["rp"] = "/ipp/%252e%252e/admin" },
		func(a *Advertisement) { a.Properties["rp"] = "/ipp/%25252525252e%25252525252e/admin" },
		func(a *Advertisement) { a.Properties["rp"] = "/ipp\\admin" },
		func(a *Advertisement) { a.Properties["rp"] = "/ipp/%5cadmin" },
		func(a *Advertisement) { a.Properties["rp"] = "/ipp/print?x=1" },
		func(a *Advertisement) { a.Properties["rp"] = "/ipp/print#part" },
		func(a *Advertisement) { a.Properties["rp"] = "/ipp/\x1bprint" },
	}
	for _, mutate := range bad {
		ad := base
		ad.Properties = map[string]string{"rp": base.Properties["rp"]}
		mutate(&ad)
		if got := ippDescriptionURL(peer, ad); got != "" {
			t.Fatalf("ippDescriptionURL(%+v) = %q, want rejection", ad, got)
		}
	}
}

func TestIPPURLPinsPeerAndEndpoint(t *testing.T) {
	peer := netip.MustParseAddr("192.0.2.19")
	for _, raw := range []string{
		"http://192.0.2.20:631/ipp/print",
		"http://example.invalid:631/ipp/print",
		"ftp://192.0.2.19/ipp/print",
		"http://u:p@192.0.2.19/ipp/print",
		"http://192.0.2.19/ipp/print?x=1",
		"http://192.0.2.19/ipp/../admin",
		"http://192.0.2.19/%2e%2e/admin",
		"http://192.0.2.19/%252e%252e/admin",
		"http://192.0.2.19/%5cadmin",
		"http://192.0.2.19/ipp/print#fragment",
		"http://192.0.2.19/ipp/print#",
		"http://192.0.2.19/ipp/print?",
	} {
		if _, err := ippURL(raw, peer); err == nil {
			t.Fatalf("ippURL(%q) unexpectedly succeeded", raw)
		}
	}
	ad := Advertisement{Protocol: "mdns", Service: "_ipp._tcp", Port: 631, Properties: map[string]string{"rp": "ipp/print"}}
	for _, invalid := range []netip.Addr{netip.Addr{}, netip.IPv4Unspecified(), netip.MustParseAddr("224.0.0.1")} {
		if ippDescriptionURL(invalid, ad) != "" {
			t.Fatalf("ippDescriptionURL accepted invalid peer %v", invalid)
		}
		if _, err := ippURL("http://192.0.2.19:631/ipp/print", invalid); err == nil {
			t.Fatalf("ippURL accepted invalid peer %v", invalid)
		}
	}
}
