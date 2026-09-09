package scanner

import (
	"context"
	"errors"
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
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			t.Run("unknown-service", func(t *testing.T) { testMDNSSplitReply(t, address, "_lantern-test._tcp", "Protocol Fixture") })
			t.Run("companion-model", func(t *testing.T) { testMDNSSplitReply(t, address, "_companion-link._tcp", "Mac16,9") })
			t.Run("catalog-model", func(t *testing.T) { testMDNSSplitReply(t, address, "_device-info._tcp", "Mac16,9") })
			t.Run("esphome", func(t *testing.T) { testMDNSSplitReply(t, address, "_esphomelib._tcp", "2026.8.1") })
			t.Run("shelly", func(t *testing.T) { testMDNSSplitReply(t, address, "_shelly._tcp", "2") })
			t.Run("homekit", func(t *testing.T) { testMDNSSplitReply(t, address, "_hap._tcp", "Fixture Light 7") })
			t.Run("matter-catalog", func(t *testing.T) {
				testMDNSSplitReply(t, address, "_matterc._udp", "256", mdnsReplyOptions{matterCatalog: true})
			})
			for _, service := range []string{"_matterc._udp", "_matterd._udp", "_matter._tcp"} {
				t.Run(service, func(t *testing.T) { testMDNSSplitReply(t, address, service, "256") })
			}
		})
	}
}

func TestMDNSLostQueriesNetworkIntegration(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			testMDNSSplitReply(t, address, "_matterc._udp", "256", mdnsReplyOptions{loss: true})
		})
	}
}

func TestMDNSRetryCancellationNetworkIntegration(t *testing.T) {
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	deadline := time.Now().Add(3 * time.Second)
	client.SetDeadline(deadline)
	server.SetReadDeadline(deadline)
	done := make(chan bool, 1)
	go func() {
		seen := map[dnsmessage.Question]bool{}
		b := make([]byte, 9000)
		for {
			n, _, err := server.ReadFromUDP(b)
			if err != nil {
				done <- false
				return
			}
			var message dnsmessage.Message
			if message.Unpack(b[:n]) != nil {
				continue
			}
			for _, question := range message.Questions {
				if seen[question] {
					cancel()
					done <- true
					return
				}
				seen[question] = true
			}
		}
	}()
	start := time.Now()
	hits, err := collectMDNS(ctx, client, server.LocalAddr().(*net.UDPAddr), netip.MustParsePrefix("127.0.0.1/32"), deadline)
	server.Close()
	retried := <-done
	if !retried || err != nil || len(hits) != 0 || ctx.Err() == nil || time.Since(start) > 2*time.Second {
		t.Fatal("retry cancellation failed to release the collector", retried, hits, err, time.Since(start))
	}
}

type mdnsReplyOptions struct{ loss, matterCatalog bool }

func testMDNSSplitReply(t *testing.T, address, service, model string, options ...mdnsReplyOptions) {
	requireNetwork(t)
	var option mdnsReplyOptions
	if len(options) > 0 {
		option = options[0]
	}
	loss := option.loss
	modelKey := "model"
	port := uint16(8765)
	var shellyReads atomic.Int32
	if service == "_shelly._tcp" {
		modelKey = "gen"
		httpServer := shellyHTTPFixture(t, address, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" || r.URL.Path != "/shelly" || r.URL.RawQuery != "" {
				t.Errorf("unexpected Shelly request: %s %s", r.Method, r.URL)
			}
			shellyReads.Add(1)
			fmt.Fprint(w, shellyFixture)
		}))
		port = uint16(httpServer.Listener.Addr().(*net.TCPAddr).Port)
	}
	if service == "_esphomelib._tcp" {
		modelKey = "version"
	}
	if service == "_companion-link._tcp" {
		modelKey = "rpmd"
	}
	if service == "_hap._tcp" {
		modelKey = "md"
	}
	if matterRole(service) != "" {
		modelKey = "dt"
	}
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(address)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(address)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	window := 300 * time.Millisecond
	if loss {
		window = 4 * time.Second
	}
	deadline := time.Now().Add(window)
	client.SetDeadline(deadline)
	queryTimes := map[dnsmessage.Question][]time.Time{}
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
				queryTimes[q] = append(queryTimes[q], time.Now())
				if loss && len(queryTimes[q]) == 1 {
					continue // Drop the first PTR, SRV, TXT, and address query.
				}
				var body dnsmessage.ResourceBody
				switch strings.ToLower(q.Name.String()) {
				case "_services._dns-sd._udp.local.":
					if service == "_esphomelib._tcp" || service == "_shelly._tcp" || service == "_companion-link._tcp" || matterRole(service) != "" {
						continue
					} // Verify direct service discovery without enumeration.
					body = &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(service + ".local.")}
				case service + ".local.":
					body = &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("Office." + service + ".local.")}
				case "office." + service + ".local.":
					if q.Type == dnsmessage.TypeSRV {
						body = &dnsmessage.SRVResource{Target: dnsmessage.MustNewName("Office.local."), Port: port}
					} else if q.Type == dnsmessage.TypeTXT {
						txt := []string{modelKey + "=" + model}
						if service == "_companion-link._tcp" {
							txt = []string{"rpMd=" + model, "RPMD=Unknown9,9", "rpVr=715.2", "rpBA=02:00:00:00:00:01"}
						}
						if service == "_esphomelib._tcp" {
							txt = append(txt, "FRIENDLY_NAME=Workshop Air", "board=esp32dev", "platform=ESP32", "project_name=example.air-monitor", "mac=001122334455")
						}
						if service == "_hap._tcp" {
							txt = append(txt, "CI=5", "id=AA:BB:CC:DD:EE:FF")
						}
						if matterRole(service) != "" {
							vp := "65521+32769"
							if option.matterCatalog {
								vp = "4447+6145"
							}
							txt = append(txt, "DN=Kitchen Light", "VP="+vp)
						}
						body = &dnsmessage.TXTResource{TXT: txt}
					}
				case "office.local.":
					if q.Type == dnsmessage.TypeAAAA {
						body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(address).As16()}
					} else {
						body = &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}
					}
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
	target, _ := ParseTarget(address)
	hits, err := collectMDNS(context.Background(), client, server.LocalAddr().(*net.UDPAddr), target, deadline)
	server.Close()
	<-done
	if loss {
		if time.Since(deadline) > 500*time.Millisecond {
			t.Fatal("recovery extended the original deadline")
		}
		total := 0
		for q, times := range queryTimes {
			total += len(times)
			if len(times) > 3 {
				t.Fatal("unbounded retransmission", q, len(times))
			}
			for i := 1; i < len(times); i++ {
				if times[i].Sub(times[i-1]) < time.Duration(1<<uint(i-1))*time.Second-20*time.Millisecond {
					t.Fatal("query retried without backoff", q, times)
				}
			}
			if len(times) > 2 && q.Name.String() == service+".local." {
				t.Fatal("answered PTR was retried", q, times)
			}
		}
		if total > maxMDNSQueries {
			t.Fatal("wire query cap exceeded", total)
		}
	}
	if err != nil || len(hits) != 1 || len(hits[0].Ads) != 1 || hits[0].Ads[0].Service != service || hits[0].Ads[0].Port != port || hits[0].Ads[0].Properties[modelKey] != model {
		t.Fatalf("hits=%+v err=%v", hits, err)
	}
	if service == "_shelly._tcp" {
		d := Device{IP: hits[0].IP, Advertisements: hits[0].Ads}
		if shellyReads.Load() != 0 {
			t.Fatal("mDNS opened API connection")
		}
		enrichDescriptions(context.Background(), &d, time.Second)
		normalizeAdvertisements(&d)
		d.Identity = identify(d.Advertisements)
		if shellyReads.Load() != 1 || d.Identity == nil || d.Identity.Name != "Workshop relay" || d.Identity.Model != "SNSW-001X16EU" || len(d.Identity.ModelNames) != 1 || d.Identity.ModelNames[0] != "Shelly Plus 1" || d.Identity.Manufacturer != "Shelly" || d.Identity.FirmwareVersion != "1.4.0" || inferKind(d) != "smart home device" || d.MAC != "" || len(d.Ports) != 0 {
			t.Fatal("packet-to-Shelly identity integration", d, shellyReads.Load())
		}
	}
	if service == "_hap._tcp" {
		id := identify(hits[0].Ads)
		d := Device{IP: hits[0].IP, Advertisements: hits[0].Ads, Identity: id}
		if id == nil || id.Model != model || id.Name != "Office" || id.Manufacturer != "" || inferKind(d) != "light" || d.MAC != "" || len(d.Ports) != 0 {
			t.Fatal("packet-to-HomeKit integration", d)
		}
	}
	if service == "_esphomelib._tcp" {
		id := identify(hits[0].Ads)
		d := Device{IP: hits[0].IP, Advertisements: hits[0].Ads, Identity: id}
		if id == nil || id.Name != "Workshop Air" || id.Firmware != "ESPHome" || id.FirmwareVersion != model || id.Model != "" || id.Manufacturer != "" || inferKind(d) != "smart home device" || d.MAC != "" || len(d.Ports) != 0 {
			t.Fatal("packet-to-ESPHome integration", d)
		}
	}
	if service == "_device-info._tcp" || service == "_companion-link._tcp" {
		id := identify(hits[0].Ads)
		if id == nil || id.Model != "Mac16,9" || len(id.ModelNames) != 1 || id.ModelNames[0] != "Mac Studio (M4 Max, 2025)" {
			t.Fatal("packet-to-catalog integration", id)
		}
	}
	if role := matterRole(service); role != "" {
		id := identify(hits[0].Ads)
		d := Device{IP: hits[0].IP, Advertisements: hits[0].Ads, Identity: id}
		wantName, wantKind := "Kitchen Light", "on/off light"
		if role == "operational" {
			wantName, wantKind = "", "smart home device"
		}
		if id == nil || id.Name != wantName || id.Model != "" || id.Manufacturer != "" || inferKind(d) != wantKind || d.MAC != "" || len(d.Ports) != 0 {
			t.Fatal("packet-to-Matter integration", d)
		}
		if option.matterCatalog && (len(id.ModelNames) != 1 || id.ModelNames[0] != "Aqara LED Bulb T2 RGB CCT") {
			t.Fatal("packet-to-product catalog failed", id)
		}
	}
}

func TestIPv6HTTPNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	badHost := make(chan string, 2)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != ln.Addr().String() {
			badHost <- r.Host
		}
		w.Header().Set("Server", "Lantern IPv6 fixture")
		fmt.Fprint(w, descriptionFixture)
	}))
	server.Listener.Close()
	server.Listener = ln
	server.Start()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ip := netip.MustParseAddr("::1")
	data, err := fetchDescription(ctx, ip, server.URL)
	if err != nil || len(data) != 2 {
		t.Fatal(data, err)
	}
	banner := readBanner(ctx, ip, Port{Number: uint16(ln.Addr().(*net.TCPAddr).Port), Service: "http"}, time.Second)
	if banner != "Lantern IPv6 fixture" {
		t.Fatal(banner)
	}
	select {
	case host := <-badHost:
		t.Fatal("invalid HTTP Host", host)
	default:
	}
}

// Close only after one actual datagram arrives, so the next receive fails on a
// real closed socket while the collector still has an observation to retain.
type closeAfterDiscoveryReply struct{ *net.UDPConn }

func (c closeAfterDiscoveryReply) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	n, peer, err := c.UDPConn.ReadFromUDP(b)
	if err == nil {
		c.UDPConn.Close()
	}
	return n, peer, err
}

func TestSSDPNetworkIntegration(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			requireNetwork(t)
			server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(address)})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(address)})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server.SetDeadline(time.Now().Add(time.Second))
			client.SetDeadline(time.Now().Add(time.Second))
			served := make(chan error, 1)
			go func() {
				b := make([]byte, 4096)
				n, peer, err := server.ReadFromUDP(b)
				if err != nil {
					served <- err
					return
				}
				if !strings.HasPrefix(string(b[:n]), "M-SEARCH * HTTP/1.1\r\n") || !strings.Contains(string(b[:n]), "HOST: "+server.LocalAddr().String()+"\r\n") {
					served <- fmt.Errorf("incorrect SSDP request: %q", b[:n])
					return
				}
				_, err = server.WriteToUDP([]byte("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\nUSN: uuid:fixture\r\n\r\n"), peer)
				served <- err
			}()
			target, _ := ParseTarget(address)
			hits, err := collectSSDP(context.Background(), closeAfterDiscoveryReply{client}, server.LocalAddr().(*net.UDPAddr), target, "")
			if len(hits) != 1 || hits[0].IP.String() != address || hits[0].Evidence != "ssdp" || len(hits[0].Ads) != 1 || !errors.Is(err, net.ErrClosed) || !strings.Contains(err.Error(), "SSDP receive") {
				t.Fatal(hits, err)
			}
			if err := <-served; err != nil {
				t.Fatal(err)
			}
		})
	}
}
