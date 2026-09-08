package vendors

import (
	"fmt"
	"strings"
	"testing"
)

func TestVirtualMACRanges(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
		first, last  int
		mac          func(int) string
	}{
		{"VRRP/CARP", "00:00:5e:00:01:00/40", 1, 255, func(n int) string { return fmt.Sprintf("00:00:5e:00:01:%02x", n) }},
		{"VRRP IPv6", "00:00:5e:00:02:00/40", 1, 255, func(n int) string { return fmt.Sprintf("00:00:5e:00:02:%02x", n) }},
		{"HSRP v1", "00:00:0c:07:ac:00/40", 0, 255, func(n int) string { return fmt.Sprintf("00:00:0c:07:ac:%02x", n) }},
		{"HSRP v2 IPv4", "00:00:0c:9f:f0:00/36", 0, 4095, func(n int) string { return fmt.Sprintf("00:00:0c:9f:%02x:%02x", 0xf0+n/256, n%256) }},
		{"HSRP v2 IPv6", "00:05:73:a0:00:00/36", 0, 4095, func(n int) string { return fmt.Sprintf("00:05:73:a0:%02x:%02x", n/256, n%256) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for n := tc.first; n <= tc.last; n++ {
				m, err := Lookup(tc.mac(n))
				role := m.AddressRole
				if err != nil || role == nil || !strings.HasPrefix(role.Name, tc.name) || role.Prefix != tc.prefix || role.Identifier != uint16(n) || len(role.References) == 0 || m.Name == "" || m.Private || m.Multicast {
					t.Fatalf("%s: %+v %+v %v", tc.mac(n), m, role, err)
				}
			}
		})
	}
}

func TestVirtualMACBoundariesAndOwnership(t *testing.T) {
	for _, mac := range []string{"00:00:5e:00:01:00", "00:00:5e:00:02:00", "00:00:5e:00:00:ff", "00:00:5e:00:03:01",
		"00:00:0c:07:ab:ff", "00:00:0c:07:ad:00", "00:00:0c:9f:ef:ff", "00:00:0c:a0:00:00",
		"00:05:73:9f:ff:ff", "00:05:73:a0:10:00", "01:00:5e:00:01:01", "02:00:5e:00:01:01",
		"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "00:00:0c:12:34:56"} {
		if m, err := Lookup(mac); err != nil || m.AddressRole != nil {
			t.Fatal("unrelated/reserved MAC acquired a role", mac, m, err)
		}
	}
	for _, mac := range []string{"not-a-mac", "00:00:5e:00:01:01:00:00"} {
		if _, err := Lookup(mac); err == nil {
			t.Fatal("invalid/EUI-64 input accepted", mac)
		}
	}
	first, _ := Lookup("00-00-5E-00-01-2A")
	if len(first.AddressRole.References) != 2 || !strings.Contains(first.AddressRole.Name, "CARP") || first.AddressRole.Identifier != 42 {
		t.Fatal("shared VRRP/CARP range lost ambiguity", first)
	}
	first.AddressRole.Name = "mutated"
	first.AddressRole.References[0] = "mutated"
	next, _ := Lookup("0000.5e00.012a")
	if next.AddressRole.Name == "mutated" || next.AddressRole.References[0] != vrrpReference || next.Name != first.Name {
		t.Fatal("lookup result aliases another result or changed registrant", next)
	}
}

func BenchmarkVirtualMACLookup(b *testing.B) {
	Count()
	b.ReportAllocs()
	for range b.N {
		Lookup("00:00:5e:00:01:2a")
	}
}
