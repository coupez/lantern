package scanner

import (
	"context"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/netip"
	"testing"
)

func TestIPv6Targets(t *testing.T) {
	for _, tc := range []struct{ raw, want, zone string }{
		{"::1", "::1/128", ""}, {"2001:db8::5/120", "2001:db8::/120", ""}, {"fe80::1%en0", "fe80::1/128", "en0"}, {"fe80::%en0/64", "fe80::/64", "en0"}, {"::/0", "::/0", ""},
	} {
		p, z, e := ParseTargetSpec(tc.raw)
		if e != nil || p.String() != tc.want || z != tc.zone {
			t.Fatal(tc, p, z, e)
		}
	}
	for _, raw := range []string{"::", "ff02::1", "::ffff:192.0.2.1", "2001:db8::/129", "fe80::%/64"} {
		if _, _, err := ParseTargetSpec(raw); err == nil {
			t.Fatal("accepted", raw)
		}
	}
	if _, err := ParseTarget("fe80::1%en0"); err == nil {
		t.Fatal("discarded scope")
	}
	for _, tc := range []struct {
		cidr  string
		count int
		last  string
	}{
		{"::1/128", 1, "::1"}, {"2001:db8::/127", 2, "2001:db8::1"}, {"2001:db8::/120", 256, "2001:db8::ff"},
	} {
		p := netip.MustParsePrefix(tc.cidr)
		hs, e := Hosts(p, 256)
		if e != nil || len(hs) != tc.count || hs[len(hs)-1].String() != tc.last || sparseIPv6(p, 256) {
			t.Fatal(tc, hs, e)
		}
	}
	if !sparseIPv6(netip.MustParsePrefix("2001:db8::/64"), 4096) || !sparseIPv6(netip.MustParsePrefix("2001:db8::/120"), 128) {
		t.Fatal("would enumerate a large network")
	}
}

func TestIPv6NeighborScopes(t *testing.T) {
	input := "Neighbor Linklayer Address Netif Expire S Flags\nfe80::1%en0 a:b:c:d:e:f en0 23h R R\nfe80::2%en1 00:11:22:33:44:55 en1 permanent R\nfe80::3 dev en0 lladdr 00:11:22:33:44:56 STALE\n2001:db8::1 dev en0 lladdr 00:11:22:33:44:57 REACHABLE\nfe80::4 dev en0 INCOMPLETE\nfe80::5%en1 00:11:22:33:44:58 en0 1s S\n"
	m := parseNeighbors6(input, "en0")
	if len(m) != 3 || m[netip.MustParseAddr("fe80::1%en0")] != "0a:0b:0c:0d:0e:0f" || m[netip.MustParseAddr("fe80::3%en0")] == "" {
		t.Fatal(m)
	}
}

func TestIPv6SeedsBoundedToLocalInterface(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("::/0")
	o.MaxHosts = 2
	seeds := ipv6Seeds{macs: map[netip.Addr]string{netip.MustParseAddr("fe80::1"): "00:11:22:33:44:55"}}
	for _, ip := range []string{"2001:db8:1::2", "2001:db8:1::3", "2001:db8:2::1", "fe80::2%other", "ff02::1", "::", "::ffff:192.0.2.1"} {
		seeds.hits = append(seeds.hits, discoveryHit{IP: netip.MustParseAddr(ip), Evidence: "mdns"})
	}
	ps := []netip.Prefix{netip.MustParsePrefix("2001:db8:1::1/64")}
	for _, ip := range []string{"2001:db8:2::1", "fe80::2%other", "ff02::1", "::", "::ffff:192.0.2.1"} {
		if onIPv6Link(netip.MustParseAddr(ip), "test0", ps) {
			t.Fatal("accepted off-link", ip)
		}
	}
	result := filterIPv6Seeds(seeds, o, "test0", ps)
	if len(result.hosts) != 2 || len(result.hits) != 2 || len(result.warnings) != 1 || result.warnings[0].method != "candidates" {
		t.Fatalf("%+v", result)
	}
	o.MaxHosts = 10
	result = filterIPv6Seeds(seeds, o, "test0", ps)
	if len(result.hosts) != 4 || result.macs[netip.MustParseAddr("fe80::1%test0")] == "" {
		t.Fatalf("%+v", result)
	}
}

func TestIPv6CoreValidationBeforeDiscovery(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("fe80::1/128")
	if _, err := (Engine{}).Scan(context.Background(), o, nil); err == nil {
		t.Fatal("missing interface accepted")
	}
	o.Target = netip.MustParsePrefix("::/0")
	o.Ports = []uint16{0}
	called := false
	_, err := (Engine{NeighborSource: func(context.Context) (map[netip.Addr]string, error) { called = true; return nil, nil }}).Scan(context.Background(), o, nil)
	if err == nil || called {
		t.Fatal("invalid port reached discovery", err, called)
	}
}

func TestIPv6PingPeerScope(t *testing.T) {
	a, ok := pingPeer(&net.UDPAddr{IP: net.ParseIP("fe80::1"), Zone: "en0"})
	if !ok || a.String() != "fe80::1%en0" {
		t.Fatal(a, ok)
	}
	a, ok = pingPeer(&net.IPAddr{IP: net.ParseIP("2001:db8::1"), Zone: "en0"})
	if !ok || a.Zone() != "" {
		t.Fatal(a, ok)
	}
}

func TestMDNSIPv6FamilyAndAddress(t *testing.T) {
	r := newMDNSRecords()
	host := dnsmessage.MustNewName("printer.local.")
	r.services["office._ipp._tcp.local."] = dnsmessage.SRVResource{Target: host, Port: 631}
	r.txt["office._ipp._tcp.local."] = map[string]string{}
	r.addresses[host.String()] = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	qs := r.followups(true)
	if len(qs) != 1 || qs[0].Type != dnsmessage.TypeAAAA {
		t.Fatal(qs)
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: host, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("fe80::1").As16()}}}}
	b, _ := m.Pack()
	if !r.ingest(b) {
		t.Fatal("AAAA rejected")
	}
	hits := scopedHits(r.hits(netip.MustParsePrefix("fe80::/64")), "en0")
	if len(hits) != 1 || hits[0].IP.String() != "fe80::1%en0" || len(hits[0].Ads) != 1 || hits[0].Ads[0].Port != 631 || len(r.followups(true)) != 0 {
		t.Fatal(hits, r.followups(true))
	}
}

func TestIPv6DescriptionScope(t *testing.T) {
	peer := netip.MustParseAddr("fe80::1%en0")
	for _, raw := range []string{"http://[fe80::1]/device", "http://[fe80::1%25en0]:8080/device"} {
		if _, err := descriptionURL(raw, peer); err != nil {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range []string{"http://[fe80::1%25en1]/device", "http://[fe80::2]/device", "http://[::1]/device"} {
		if _, err := descriptionURL(raw, peer); err == nil {
			t.Fatal("accepted", raw)
		}
	}
}
func TestIPv6SparseEngineCandidateLimit(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	name := ""
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback != 0 && len(interfacePrefixes(i)) > 0 {
			name = i.Name
			break
		}
	}
	if name == "" {
		t.Skip("no IPv6 loopback interface")
	}
	o := Defaults()
	o.Target = netip.MustParsePrefix("::/0")
	o.Interface = name
	o.ICMP = false
	o.Multicast = false
	o.Resolve = false
	o.MaxHosts = 1
	o.Ports = nil
	r, err := (Engine{NeighborSource: func(context.Context) (map[netip.Addr]string, error) {
		return map[netip.Addr]string{netip.MustParseAddr("fe80::123"): "00:11:22:33:44:55"}, nil
	}}).Scan(context.Background(), o, nil)
	if err != nil || r.AddressMode != "discovered" || r.Targets != 1 || len(r.Devices) != 1 || len(r.Warnings) != 1 || r.Devices[0].IP.String() != "::1" {
		t.Fatal(r, err)
	}
	if len(r.IncompleteMethods) != 1 || r.IncompleteMethods[0] != "candidates" {
		t.Fatal(r.IncompleteMethods)
	}
	// A seed-pass failure must survive a successful post-probe cache refresh.
	o.MaxHosts = 10
	calls := 0
	r, err = (Engine{NeighborSource: func(context.Context) (map[netip.Addr]string, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("seed neighbor lookup failed")
		}
		return nil, nil
	}}).Scan(context.Background(), o, nil)
	if err != nil || calls != 2 || len(r.IncompleteMethods) != 1 || r.IncompleteMethods[0] != "neighbors" {
		t.Fatal(r, calls, err)
	}
}
