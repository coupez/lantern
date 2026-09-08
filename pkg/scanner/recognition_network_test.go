package scanner

import (
	"context"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func requireNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("LANTERN_NETWORK_TESTS") != "1" {
		t.Skip("set LANTERN_NETWORK_TESTS=1 for controlled localhost sockets")
	}
}
func TestDescriptionNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/device":
			fmt.Fprint(w, descriptionFixture)
		case "/redirect":
			http.Redirect(w, r, "/device", http.StatusFound)
		case "/large":
			fmt.Fprint(w, strings.Repeat("x", maxDescriptionBytes+1))
		case "/slow":
			<-r.Context().Done()
		}
	}))
	defer server.Close()
	ip := netip.MustParseAddr("127.0.0.1")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d := Device{IP: ip, Advertisements: []Advertisement{{Protocol: "ssdp", Properties: map[string]string{"location": server.URL + "/device", "usn": "uuid:child::upnp:rootdevice"}}, {Protocol: "ssdp", Properties: map[string]string{"location": server.URL + "/device", "usn": "uuid:child"}}}}
	enrichDescriptions(ctx, &d, time.Second)
	normalizeAdvertisements(&d)
	identity := identify(d.Advertisements)
	if identity == nil || identity.Model != "Bridge 7" || identity.Manufacturer != "Bridge Inc" || hits.Load() != 1 {
		t.Fatal(identity, hits.Load())
	}
	before := hits.Load()
	if _, err := fetchDescription(ctx, ip, server.URL+"/redirect"); err == nil || hits.Load() != before+1 {
		t.Fatal("followed redirect", err, hits.Load())
	}
	if _, err := fetchDescription(ctx, ip, server.URL+"/large"); err == nil {
		t.Fatal("accepted oversized body")
	}
	slow, cancelSlow := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelSlow()
	start := time.Now()
	if _, err := fetchDescription(slow, ip, server.URL+"/slow"); err == nil || time.Since(start) > time.Second {
		t.Fatal("deadline ignored", err)
	}
	// Advertising another target must not even contact the local server.
	before = hits.Load()
	if _, err := fetchDescription(ctx, netip.MustParseAddr("192.168.1.5"), server.URL+"/device"); err == nil || hits.Load() != before {
		t.Fatal("off-device fetch attempted")
	}
}
func TestMDNSSplitReplyNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(300 * time.Millisecond))
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 9000)
		for {
			n, peer, err := server.ReadFromUDP(b)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(b[:n]) != nil {
				continue
			}
			for _, q := range m.Questions {
				var body dnsmessage.ResourceBody
				switch strings.ToLower(q.Name.String()) {
				case "_services._dns-sd._udp.local.":
					body = &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("_lantern-test._tcp.local.")}
				case "_lantern-test._tcp.local.":
					body = &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("Office._lantern-test._tcp.local.")}
				case "office._lantern-test._tcp.local.":
					if q.Type == dnsmessage.TypeSRV {
						body = &dnsmessage.SRVResource{Target: dnsmessage.MustNewName("Office.local."), Port: 8765}
					} else if q.Type == dnsmessage.TypeTXT {
						body = &dnsmessage.TXTResource{TXT: []string{"model=Protocol Fixture"}}
					}
				case "office.local.":
					body = &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}
				}
				if body == nil {
					continue
				}
				reply := dnsmessage.Message{Header: dnsmessage.Header{ID: m.Header.ID, Response: true}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, Type: q.Type, TTL: 120}, Body: body}}}
				packet, _ := reply.Pack()
				server.WriteToUDP(packet, peer)
			}
		}
	}()
	hits, err := collectMDNS(context.Background(), client, server.LocalAddr().(*net.UDPAddr), netip.MustParsePrefix("127.0.0.1/32"))
	server.Close()
	<-done
	if err != nil || len(hits) != 1 || len(hits[0].Ads) != 1 || hits[0].Ads[0].Service != "_lantern-test._tcp" || hits[0].Ads[0].Port != 8765 || hits[0].Ads[0].Properties["model"] != "Protocol Fixture" {
		t.Fatalf("hits=%+v err=%v", hits, err)
	}
}
