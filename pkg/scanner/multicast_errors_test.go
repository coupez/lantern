package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

type scriptedDiscoveryUDP struct {
	packet                     []byte
	peer                       *net.UDPAddr
	reads, writes, packetCount int
	readErr, writeErr          error
	failWrite, shortWrite      int
	beforeRead                 func(int)
}

func (c *scriptedDiscoveryUDP) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) {
	c.writes++
	if c.writes == c.failWrite {
		return 0, c.writeErr
	}
	if c.writes == c.shortWrite {
		return len(b) - 1, nil
	}
	return len(b), nil
}
func (c *scriptedDiscoveryUDP) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	if c.beforeRead != nil {
		c.beforeRead(c.reads)
	}
	c.reads++
	if c.reads <= c.packetCount {
		return copy(b, c.packet), c.peer, nil
	}
	return 0, nil, c.readErr
}

func multicastErrorFixture(t *testing.T, protocol string, pointers int) *scriptedDiscoveryUDP {
	t.Helper()
	port := 1900
	packet := []byte("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:fixture\r\n\r\n")
	if protocol == "mDNS" {
		port = 5353
		m := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("fixture.local."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}}}
		for i := range pointers {
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("_http._tcp.local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(fmt.Sprintf("Fixture%d._http._tcp.local.", i))}})
		}
		var err error
		packet, err = m.Pack()
		if err != nil || len(packet) > 9000 {
			t.Fatal("invalid fixture", err, len(packet))
		}
	}
	return &scriptedDiscoveryUDP{packet: packet, peer: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: port}, packetCount: 1, readErr: os.ErrDeadlineExceeded}
}
func collectFixture(ctx context.Context, protocol string, c *scriptedDiscoveryUDP) ([]discoveryHit, error) {
	target := netip.MustParsePrefix("192.0.2.0/24")
	if protocol == "mDNS" {
		return collectMDNS(ctx, c, c.peer, target)
	}
	return collectSSDP(ctx, c, c.peer, target, "fixture0")
}

func TestMulticastReceiveFailuresRetainPartialResults(t *testing.T) {
	for _, protocol := range []string{"mDNS", "SSDP"} {
		for _, failure := range []error{io.ErrUnexpectedEOF, net.ErrClosed} {
			c := multicastErrorFixture(t, protocol, 0)
			c.readErr = failure
			hits, err := collectFixture(context.Background(), protocol, c)
			if len(hits) != 1 || !errors.Is(err, failure) || !strings.Contains(err.Error(), protocol+" receive") {
				t.Fatal(protocol, hits, err)
			}
		}
		c := multicastErrorFixture(t, protocol, 0)
		hits, err := collectFixture(context.Background(), protocol, c)
		if len(hits) != 1 || err != nil {
			t.Fatal("normal response deadline became failure", protocol, hits, err)
		}
	}
}

func TestMulticastWriteFailuresAndShortWrites(t *testing.T) {
	for _, protocol := range []string{"mDNS", "SSDP"} {
		for _, short := range []bool{false, true} {
			c := multicastErrorFixture(t, protocol, 0)
			want := os.ErrDeadlineExceeded
			if short {
				c.shortWrite = 1
				want = io.ErrShortWrite
			} else {
				c.failWrite = 1
				c.writeErr = want
			}
			hits, err := collectFixture(context.Background(), protocol, c)
			if len(hits) != 0 || !errors.Is(err, want) || c.reads != 0 {
				t.Fatal(protocol, hits, err, c.reads)
			}
		}
	}
	c := multicastErrorFixture(t, "mDNS", 1)
	c.failWrite, c.writeErr = len(mdnsKinds)+1, io.ErrClosedPipe
	hits, err := collectFixture(context.Background(), "mDNS", c)
	if len(hits) != 1 || !errors.Is(err, io.ErrClosedPipe) || !strings.Contains(err.Error(), "follow-up") {
		t.Fatal(hits, err)
	}
}

func TestMulticastCancellationIsQuietAndRetainsResults(t *testing.T) {
	for _, protocol := range []string{"mDNS", "SSDP"} {
		ctx, cancel := context.WithCancel(context.Background())
		c := multicastErrorFixture(t, protocol, 0)
		c.beforeRead = func(n int) {
			if n == 1 {
				cancel()
			}
		}
		c.readErr = net.ErrClosed
		hits, err := collectFixture(ctx, protocol, c)
		cancel()
		if len(hits) != 1 || err != nil {
			t.Fatal(protocol, hits, err)
		}
		c = multicastErrorFixture(t, protocol, 0)
		hits, err = collectFixture(ctx, protocol, c)
		if len(hits) != 0 || err != nil || c.reads != 0 || c.writes != 0 {
			t.Fatal("pre-cancelled collector performed I/O", protocol, hits, err)
		}
	}
}

func TestMulticastBudgetWarnings(t *testing.T) {
	for _, protocol := range []string{"mDNS", "SSDP"} {
		c := multicastErrorFixture(t, protocol, 0)
		c.packetCount = maxDiscoveryPackets + 10
		hits, err := collectFixture(context.Background(), protocol, c)
		if len(hits) == 0 || err == nil || !strings.Contains(err.Error(), "packet limit reached") || c.reads != maxDiscoveryPackets {
			t.Fatal(protocol, len(hits), err, c.reads)
		}
	}
	c := multicastErrorFixture(t, "mDNS", 60)
	hits, err := collectFixture(context.Background(), "mDNS", c)
	if len(hits) != 1 || err == nil || !strings.Contains(err.Error(), "query limit reached") || c.writes != maxMDNSQueries {
		t.Fatal(hits, err, c.writes)
	}
	// An actual receive failure is retained alongside the query-budget warning.
	c = multicastErrorFixture(t, "mDNS", 60)
	c.readErr = io.ErrUnexpectedEOF
	hits, err = collectFixture(context.Background(), "mDNS", c)
	if len(hits) != 1 || !errors.Is(err, io.ErrUnexpectedEOF) || !strings.Contains(err.Error(), "query limit reached") || strings.Contains(err.Error(), "\n") {
		t.Fatal(hits, err)
	}
}
