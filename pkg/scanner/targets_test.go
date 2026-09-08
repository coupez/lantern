package scanner

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestHosts(t *testing.T) {
	for _, c := range []struct {
		cidr        string
		count       int
		first, last string
	}{{"10.0.0.42/24", 254, "10.0.0.1", "10.0.0.254"}, {"10.0.0.0/31", 2, "10.0.0.0", "10.0.0.1"}, {"127.0.0.1/32", 1, "127.0.0.1", "127.0.0.1"}} {
		h, e := Hosts(netip.MustParsePrefix(c.cidr), 4096)
		if e != nil || len(h) != c.count || h[0].String() != c.first || h[len(h)-1].String() != c.last {
			t.Fatalf("%s: %v %v", c.cidr, h, e)
		}
	}
	if _, e := Hosts(netip.MustParsePrefix("0.0.0.0/0"), 4096); e == nil {
		t.Fatal("unbounded target accepted")
	}
}
func TestPorts(t *testing.T) {
	p, e := ParsePorts("443,80,80,100-102")
	if e != nil || !reflect.DeepEqual(p, []uint16{80, 100, 101, 102, 443}) {
		t.Fatal(p, e)
	}
	for _, s := range []string{"0", "65536", "4-2", "1-2-3", "foo", ""} {
		if _, e := ParsePorts(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
func TestNeighbors(t *testing.T) {
	s := "? (192.168.1.1) at a:b:c:d:e:f on en0 ifscope [ethernet]\n? (192.168.1.2) at (incomplete) on en0\n192.168.1.3 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE\n"
	m := parseNeighbors(s)
	if len(m) != 2 || m[netip.MustParseAddr("192.168.1.1")] != "0a:0b:0c:0d:0e:0f" {
		t.Fatal(m)
	}
}

func TestHostsExcludeUnspecifiedAddresses(t *testing.T) {
	for _, target := range []string{"0.0.0.0/31", "::/127"} {
		prefix := netip.MustParsePrefix(target)
		hosts, err := Hosts(prefix, 1)
		if err != nil || len(hosts) != 1 || hosts[0] != prefix.Addr().Next() {
			t.Fatal(target, hosts, err)
		}
		if sparseIPv6(prefix, 1) {
			t.Fatal("eligible single host classified as sparse", target)
		}
	}
	for _, target := range []string{"0.0.0.0/32", "::/128", "224.0.0.1/32", "ff02::1/128"} {
		if _, err := Hosts(netip.MustParsePrefix(target), 4096); err == nil {
			t.Fatal("accepted non-unicast host", target)
		}
	}
}
