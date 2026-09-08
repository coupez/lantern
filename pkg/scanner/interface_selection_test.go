package scanner

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
)

func TestAutoIPv4KeepsDefaultRouteInterfaceOnOverlappingNetworks(t *testing.T) {
	a := Network{Interface: "virtual0", Address: "192.0.2.1", CIDR: "192.0.2.0/24"}
	b := Network{Interface: "ethernet0", Address: "192.0.2.2", CIDR: "192.0.2.0/24"}
	for _, networks := range [][]Network{{a, b}, {b, a}} {
		got, err := selectIPv4Network(networks, "", "ethernet0")
		if err != nil || got != b {
			t.Fatal(got, err)
		}
		got, err = selectIPv4Network(networks, "virtual0", "ethernet0")
		if err != nil || got != a {
			t.Fatal("explicit interface lost", got, err)
		}
		if _, err := selectIPv4Network(networks, "", "missing0"); err == nil {
			t.Fatal("ambiguous fallback accepted")
		}
	}
	if _, err := selectIPv4Network([]Network{a}, "missing0", "virtual0"); err == nil {
		t.Fatal("unknown explicit interface fell back")
	}
	if got, err := selectIPv4Network([]Network{a}, "", "missing0"); err != nil || got != a {
		t.Fatal("single-network fallback lost", got, err)
	}
}

func TestIPv4NeighborInterfaceIsolation(t *testing.T) {
	for _, lines := range [][]string{
		{"on (192.0.2.1) at 00:11:22:33:44:55 on ethernet0 ifscope [ethernet]", "? (192.0.2.1) at aa:bb:cc:dd:ee:ff on virtual0 ifscope [ethernet]"},
		{"192.0.2.1 dev ethernet0 lladdr 00:11:22:33:44:55 REACHABLE", "192.0.2.1 dev virtual0 lladdr aa:bb:cc:dd:ee:ff STALE"},
	} {
		for _, input := range []string{lines[0] + "\n" + lines[1], lines[1] + "\n" + lines[0]} {
			for _, tc := range []struct{ iface, mac string }{{"ethernet0", "00:11:22:33:44:55"}, {"virtual0", "aa:bb:cc:dd:ee:ff"}} {
				table := parseNeighborsOn(input, tc.iface)
				if len(table) != 1 || table[netip.MustParseAddr("192.0.2.1")] != tc.mac {
					t.Fatal(tc, table)
				}
			}
			if len(parseNeighborsOn(input, "missing0")) != 0 {
				t.Fatal("wrong-link mapping retained")
			}
		}
	}
	// A row without interface provenance can be used only for an unscoped scan.
	const unscoped = "? (192.0.2.1) at 00:11:22:33:44:55"
	if len(parseNeighbors(unscoped)) != 1 || len(parseNeighborsOn(unscoped, "ethernet0")) != 0 {
		t.Fatal("missing interface provenance mishandled")
	}
}

func TestIPv4InvalidInterfaceFailsBeforeProbes(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("192.0.2.1/32")
	o.Interface = "lantern-missing-interface"
	f := &fakeDialer{}
	called := false
	_, err := (Engine{Dialer: f, NeighborSource: func(context.Context) (map[netip.Addr]string, error) { called = true; return nil, nil }}).Scan(context.Background(), o, nil)
	if err == nil || called || f.calls.Load() != 0 {
		t.Fatal(err, called, f.calls.Load())
	}
}

func TestIPv4LocalEvidenceRespectsSelectedInterface(t *testing.T) {
	networks, err := Networks()
	if err != nil {
		t.Fatal(err)
	}
	for _, selected := range networks {
		for _, other := range networks {
			if selected.Interface == other.Interface || selected.Address == other.Address {
				continue
			}
			o := Defaults()
			o.Target = netip.PrefixFrom(netip.MustParseAddr(other.Address), 32)
			o.Interface = selected.Interface
			o.ICMP, o.Multicast, o.Resolve, o.Descriptions = false, false, false, false
			o.Ports = nil
			r, err := (Engine{NeighborSource: noNeighbors}).Scan(context.Background(), o, nil)
			if err != nil || len(r.Devices) != 0 {
				t.Fatal("other interface became local evidence", r, err)
			}
			o.Interface = other.Interface
			r, err = (Engine{NeighborSource: noNeighbors}).Scan(context.Background(), o, nil)
			if err != nil || len(r.Devices) != 1 || fmt.Sprint(r.Devices[0].Evidence) != "[local-interface]" {
				t.Fatal("selected local evidence lost", r, err)
			}
			return
		}
	}
	t.Skip("requires two active IPv4 interfaces; no network traffic is sent")
}

func TestAutoTarget4ReturnsAnExistingInterface(t *testing.T) {
	networks, err := Networks()
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) == 0 {
		t.Skip("no active IPv4 networks")
	}
	n := networks[0]
	prefix, iface, err := AutoTarget4(n.Interface)
	legacy, legacyErr := AutoTarget(n.Interface)
	if err != nil || legacyErr != nil || iface != n.Interface || prefix.String() != n.CIDR || legacy != prefix {
		t.Fatal(prefix, iface, err, legacy, legacyErr)
	}
}
