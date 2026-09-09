package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRokuDiscoveryNetworkIntegration(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			requireNetwork(t)
			var hits atomic.Int32
			api := shellyHTTPFixture(t, address, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.Method != "GET" || r.URL.Path != "/query/device-info" || r.URL.RawQuery != "" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
				}
				fmt.Fprint(w, rokuFixture)
			}))
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
			deadline := time.Now().Add(200 * time.Millisecond)
			client.SetDeadline(deadline)
			server.SetDeadline(deadline)
			queries := make(chan []string, 1)
			go func() {
				var seen []string
				b := make([]byte, 2048)
				for {
					n, peer, err := server.ReadFromUDP(b)
					if err != nil {
						queries <- seen
						return
					}
					q := string(b[:n])
					seen = append(seen, q)
					if strings.Contains(q, "\r\nST: roku:ecp\r\n") {
						server.WriteToUDP([]byte("HTTP/1.1 200 OK\r\nST: roku:ecp\r\nLOCATION: "+api.URL+"/untrusted?control=ignored\r\nUSN: uuid:roku:ecp:fixture\r\n\r\n"), peer)
					}
				}
			}()
			target, _ := ParseTarget(address)
			found, err := collectSSDP(context.Background(), client, server.LocalAddr().(*net.UDPAddr), target, "")
			server.Close()
			sent := <-queries
			if err != nil || len(found) != 1 || len(sent) != 2 || !strings.Contains(sent[0], "ST: ssdp:all") || !strings.Contains(sent[1], "ST: roku:ecp") {
				t.Fatal(found, err, sent)
			}
			d := Device{IP: netip.MustParseAddr(address), MAC: "02:aa:bb:cc:dd:ee", Advertisements: append(found[0].Ads, found[0].Ads...)}
			if hits.Load() != 0 {
				t.Fatal("discovery contacted device API")
			}
			enrichDescriptions(context.Background(), &d, time.Second)
			normalizeAdvertisements(&d)
			d.Identity = identify(d.Advertisements)
			if hits.Load() != 1 || len(d.Advertisements) != 2 || d.Identity == nil || d.Identity.Model != "Roku 3" || d.Identity.Name != "Living room" || d.Identity.Manufacturer != "Roku" || d.Identity.Firmware != "Roku OS" || d.Identity.FirmwareVersion != "14.0.0" || inferKind(d) != "media" || d.MAC != "02:aa:bb:cc:dd:ee" || len(d.Ports) != 0 {
				t.Fatal(d, d.Identity, hits.Load())
			}
			modelNumber := false
			for _, c := range d.Identity.Claims {
				if c.Reference != rokuInfoReference {
					t.Fatal(c)
				}
				if c.Field == "model_number" && c.Value == "4200X" {
					modelNumber = true
				}
			}
			if !modelNumber {
				t.Fatal("lost reported model number")
			}
		})
	}
}

func TestRokuHTTPFailureAndBudgetNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	var hits atomic.Int32
	var mode atomic.Int32
	api := shellyHTTPFixture(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch mode.Load() {
		case 1:
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		case 2:
			w.WriteHeader(http.StatusUnauthorized)
		case 3:
			fmt.Fprint(w, strings.Repeat(" ", maxRokuBytes)+rokuFixture)
		case 4:
			fmt.Fprint(w, `<html>not a device</html>`)
		case 5:
			<-r.Context().Done()
		default:
			fmt.Fprint(w, rokuFixture)
		}
	}))
	ip := netip.MustParseAddr("127.0.0.1")
	ad := Advertisement{Protocol: "ssdp", Service: "roku:ecp", Properties: map[string]string{"location": api.URL}}
	for _, m := range []int32{1, 2, 3, 4, 5} {
		mode.Store(m)
		d := Device{IP: ip, Advertisements: []Advertisement{ad}}
		before := hits.Load()
		start := time.Now()
		enrichDescriptions(context.Background(), &d, 100*time.Millisecond)
		if hits.Load() != before+1 || !reflect.DeepEqual(d.Advertisements, []Advertisement{ad}) || time.Since(start) > time.Second {
			t.Fatal(m, d, hits.Load())
		}
	}
	mode.Store(0)
	d := Device{IP: netip.MustParseAddr("192.0.2.1"), Advertisements: []Advertisement{ad}}
	before := hits.Load()
	enrichDescriptions(context.Background(), &d, time.Second)
	if hits.Load() != before || len(d.Advertisements) != 1 {
		t.Fatal("off-device read", d)
	}
	// Five distinct Roku endpoints share the same existing four-request ceiling.
	var servers []string
	for i := 0; i < 5; i++ {
		s := shellyHTTPFixture(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, rokuFixture) }))
		servers = append(servers, s.URL)
	}
	d = Device{IP: ip}
	for _, location := range servers {
		d.Advertisements = append(d.Advertisements, Advertisement{Protocol: "ssdp", Service: "roku:ecp", Properties: map[string]string{"location": location}})
	}
	before = hits.Load()
	enrichDescriptions(context.Background(), &d, time.Second)
	if hits.Load() != before+4 || len(d.Advertisements) != 9 {
		t.Fatal("request budget", d, hits.Load()-before)
	}
}

func TestRokuIdentitySourceIsolation(t *testing.T) {
	a := Advertisement{Protocol: "roku", Service: "device-info", Instance: "device-info", Properties: map[string]string{"location": "http://192.0.2.1:8060/query/device-info", "model-number": "Code7", "friendly-device-name": "Fallback", "software-version": "1", "is-tv": "true"}}
	b := a
	b.Properties = map[string]string{"location": "http://192.0.2.1:8061/query/device-info", "model-name": "Other", "software-version": "2"}
	one, two := identify([]Advertisement{a, b}), identify([]Advertisement{b, a})
	if !reflect.DeepEqual(one, two) || one.FirmwareVersion != "1" {
		t.Fatal(one, two)
	}
	id := identify([]Advertisement{a})
	if id.Model != "Code7" || id.Manufacturer != "" || id.Name != "Fallback" || len(id.ModelNames) != 0 || inferKind(Device{Advertisements: []Advertisement{a}}) != "television" {
		t.Fatal(id)
	}
	a.Service = "other"
	if identify([]Advertisement{a}) != nil || inferKind(Device{Advertisements: []Advertisement{a}}) != "device" {
		t.Fatal("wrong service identified")
	}
}

func TestRokuCompetingVendorAndTaintedIdentity(t *testing.T) {
	a := Advertisement{Protocol: "roku", Service: "device-info", Instance: "device-info", Properties: map[string]string{"location": "http://192.0.2.1:8060/query/device-info", "model-name": "Alpha"}}
	b := a
	b.Properties = map[string]string{"location": "http://192.0.2.1:8061/query/device-info", "model-name": "Beta", "vendor-name": "Other Vendor", "user-device-name": "Other Name"}
	id := identify([]Advertisement{b, a})
	if id.Model != "Alpha" || id.Manufacturer != "" || id.Name != "" {
		t.Fatal("mixed endpoint identity", id)
	}
	for _, bad := range []string{"Mac16,\x009", "\u202e", strings.Repeat("x", 257)} {
		a.Properties["model-name"] = bad
		a.Properties["model-number"] = "Code7"
		a.Properties["vendor-name"] = "Ven\u202edor"
		a.Properties["user-device-name"] = "Na\x00me"
		id = identify([]Advertisement{a})
		if id.Model != "Code7" || id.Name != "" || id.Manufacturer != "" {
			t.Fatal("tainted identity or missing fallback", id)
		}
	}
}
