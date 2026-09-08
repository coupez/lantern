package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestNetworkIntegration(t *testing.T) {
	if os.Getenv("LANTERN_NETWORK_TESTS") != "1" {
		t.Skip("set LANTERN_NETWORK_TESTS=1 for real loopback sockets")
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				fmt.Fprint(c, "SSH-2.0-Lantern_Test\r\n")
			}()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	o := Defaults()
	o.Target = netip.MustParsePrefix("127.0.0.1/32")
	o.Ports = []uint16{port}
	o.Resolve = false
	o.Multicast = false
	r, e := (Engine{NeighborSource: noNeighbors}).Scan(context.Background(), o, nil)
	if e != nil || len(r.Devices) != 1 || len(r.Devices[0].Ports) != 1 || r.Devices[0].Ports[0].Number != port {
		t.Fatal(r, e)
	}
	if !contains(r.Devices[0].Evidence, "icmp") {
		t.Fatalf("ICMP did not report localhost: %+v", r)
	}
	banner := readBanner(context.Background(), o.Target.Addr(), Port{Number: port, Service: "ssh"}, time.Second)
	if banner != "SSH-2.0-Lantern_Test" {
		t.Fatal(banner)
	}
}
