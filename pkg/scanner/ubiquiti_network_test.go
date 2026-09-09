package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestUbiquitiLoopbackExchange(t *testing.T) {
	if os.Getenv("LANTERN_NETWORK_TESTS") != "1" {
		t.Skip("set LANTERN_NETWORK_TESTS=1")
	}
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 32)
		for i, want := range [][]byte{{1, 0, 0, 0}, {2, 8, 0, 0}} {
			n, from, e := server.ReadFromUDP(buf)
			if e != nil {
				done <- e
				return
			}
			if !reflect.DeepEqual(buf[:n], want) {
				done <- &net.AddrError{Err: "unexpected Ubiquiti query", Addr: string(buf[:n])}
				return
			}
			reply := ubReply(byte(i+1), []byte{0, 6}[i], []byte{20, 21}[i], []string{"Model V1", "Model V2"}[i])
			if _, e = server.WriteToUDP(reply, from); e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	host := netip.MustParseAddr("127.0.0.1")
	got, err := exchangeUbiquiti(context.Background(), client, []netip.Addr{host}, 100*time.Millisecond, port)
	if err != nil {
		t.Fatal(err)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if len(got.Replies) != 2 {
		t.Fatalf("%#v", got)
	}
	var ads []Advertisement
	for _, r := range got.Replies {
		h := ubiquitiHit(r.IP, r.Observation)
		if h.IP != host || h.Evidence != "ubiquiti" || len(h.Ads) != 1 || h.Ads[0].Port != 10001 {
			t.Fatalf("%#v", h)
		}
		ads = append(ads, h.Ads...)
	}
	id := identify(ads)
	if id == nil || id.Model == "" || id.Manufacturer != "Ubiquiti" {
		t.Fatalf("%#v", id)
	}
	d := Device{IP: host, Advertisements: ads, Evidence: []string{"ubiquiti"}, Identity: id}
	if len(d.Ports) != 0 || d.MAC != "" {
		t.Fatalf("%#v", d)
	}
}

func TestUbiquitiLoopbackInFlightCancellation(t *testing.T) {
	if os.Getenv("LANTERN_NETWORK_TESTS") != "1" {
		t.Skip("set LANTERN_NETWORK_TESTS=1")
	}
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 32)
		for _, want := range [][]byte{{1, 0, 0, 0}, {2, 8, 0, 0}} {
			n, from, e := server.ReadFromUDP(buf)
			if e != nil {
				done <- e
				return
			}
			if !reflect.DeepEqual(buf[:n], want) {
				done <- &net.AddrError{Err: "unexpected Ubiquiti query", Addr: string(buf[:n])}
				return
			}
			if reflect.DeepEqual(want, []byte{2, 8, 0, 0}) {
				if _, e = server.WriteToUDP(ubReply(2, 6, 20, "partial"), from); e != nil {
					done <- e
					return
				}
			}
		}
		done <- nil
	}()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	start := time.Now()
	got, err := exchangeUbiquiti(ctx, cancelOnUbiquitiRead{PacketConn: client, cancel: cancel}, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, time.Second, port)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("cancellation took %v", elapsed)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if len(got.Probed) != 1 || len(got.Replies) != 1 || got.Replies[0].Observation.Fields[0].Value != "partial" {
		t.Fatalf("partial result = %#v", got)
	}
}

// Cancel after a real datagram has been delivered, before the collector parses
// it. This synchronizes partial-result coverage without scheduler sleeps.
type cancelOnUbiquitiRead struct {
	net.PacketConn
	cancel context.CancelFunc
}

func (c cancelOnUbiquitiRead) ReadFrom(b []byte) (int, net.Addr, error) {
	n, peer, err := c.PacketConn.ReadFrom(b)
	if err == nil && n > 0 {
		c.cancel()
	}
	return n, peer, err
}
