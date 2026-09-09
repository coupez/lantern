package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Independent wire encoder, deliberately not using the production IPP package.
func ippResponseFixture(id uint32) []byte {
	b := []byte{1, 1, 0, 0, 0, 0, 0, 0, 1}
	binary.BigEndian.PutUint32(b[4:8], id)
	attr := func(tag byte, key, value string) {
		b = append(b, tag, byte(len(key)>>8), byte(len(key)))
		b = append(b, key...)
		b = append(b, byte(len(value)>>8), byte(len(value)))
		b = append(b, value...)
	}
	attr(0x47, "attributes-charset", "utf-8")
	attr(0x48, "attributes-natural-language", "en")
	b = append(b, 4)
	attr(0x41, "printer-make-and-model", "Example Laser 42")
	attr(0x42, "printer-name", "Office queue")
	attr(0x41, "printer-device-id", "MFG:Example;MDL:Laser 42;SN:do-not-store;")
	return append(b, 3)
}
func ippAdvertisement(t *testing.T, endpoint, service, rp string) Advertisement {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return Advertisement{Protocol: "mdns", Service: service, Port: uint16(n), Instance: "Office." + service + ".local", Properties: map[string]string{"rp": rp}}
}
func TestIPPIdentityNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			var hits atomic.Int32
			server := shellyHTTPFixture(t, address, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				b, err := io.ReadAll(io.LimitReader(r.Body, 4096))
				if err != nil {
					t.Error(err)
				}
				if r.Method != "POST" || r.URL.EscapedPath() != "/printers/Office%20Queue" || r.Header.Get("Content-Type") != "application/ipp" || len(b) < 9 || binary.BigEndian.Uint16(b[2:4]) != 11 || b[len(b)-1] != 3 {
					t.Errorf("unexpected request: %s %s %x", r.Method, r.URL, b)
					w.WriteHeader(400)
					return
				}
				if !strings.Contains(string(b), "ipp://"+r.Host+"/printers/Office%20Queue") || !strings.Contains(string(b), "requested-attributes") {
					t.Errorf("wrong IPP target: %x", b)
				}
				w.Header().Set("Content-Type", "application/ipp")
				w.Write(ippResponseFixture(binary.BigEndian.Uint32(b[4:8])))
			}))
			ad := ippAdvertisement(t, server.URL, "_ipp._tcp", "printers/Office Queue")
			d := Device{IP: netip.MustParseAddr(address), Advertisements: []Advertisement{ad, ad}, MAC: "02:aa:bb:cc:dd:ee"}
			enrichDescriptions(context.Background(), &d, time.Second)
			normalizeAdvertisements(&d)
			d.Identity = identify(d.Advertisements)
			if hits.Load() != 1 || d.Identity == nil || d.Identity.Model != "Laser 42" || d.Identity.Manufacturer != "Example" || d.Identity.Name != "" || inferKind(d) != "printer" || len(d.Ports) != 0 || d.MAC != "02:aa:bb:cc:dd:ee" {
				t.Fatal(d, d.Identity, hits.Load())
			}
			for _, a := range d.Advertisements {
				for _, v := range a.Properties {
					if strings.Contains(v, "do-not-store") {
						t.Fatal("serial retained", a)
					}
				}
			}
		})
	}
}
func TestIPPHTTPSNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		if len(b) < 8 || !strings.Contains(string(b), "ipps://") {
			t.Error("wrong secure printer URI")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/ipp")
		w.Write(ippResponseFixture(binary.BigEndian.Uint32(b[4:8])))
	}))
	defer server.Close()
	ad := ippAdvertisement(t, server.URL, "_ipps._tcp", "ipp/print")
	d := Device{IP: netip.MustParseAddr("127.0.0.1"), Advertisements: []Advertisement{ad}}
	enrichDescriptions(context.Background(), &d, time.Second)
	id := identify(d.Advertisements)
	if id == nil || id.Model != "Laser 42" {
		t.Fatal(id)
	}
	marked := false
	for _, c := range id.Claims {
		if c.Field == "transport" && c.Basis == "transport" {
			marked = true
		}
	}
	if !marked {
		t.Fatal("unverified TLS lost provenance", id)
	}
}
func TestIPPFailureAndBudgetNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	var hits atomic.Int32
	var mode atomic.Int32
	shutdown := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
		hits.Add(1)
		switch mode.Load() {
		case 1:
			http.Redirect(w, r, "/admin", 302)
		case 2:
			w.WriteHeader(401)
		case 3:
			w.Header().Set("Content-Type", "text/html")
			w.Write(ippResponseFixture(1))
		case 4:
			w.Header().Set("Content-Type", "application/ipp")
			fmt.Fprint(w, strings.Repeat("x", int(maxIPPBytes)+1))
		case 5:
			select {
			case <-r.Context().Done():
			case <-shutdown:
			}
		case 6:
			w.Header().Set("Content-Type", "application/ipp")
			w.Write(ippResponseFixture(2))
		default:
			w.Header().Set("Content-Type", "application/ipp")
			w.Write(ippResponseFixture(1))
		}
	}))
	defer server.Close()
	defer close(shutdown)
	peer := netip.MustParseAddr("127.0.0.1")
	for i := int32(1); i <= 6; i++ {
		mode.Store(i)
		before := hits.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		start := time.Now()
		_, err := fetchIPPDescription(ctx, peer, server.URL+"/ipp/print")
		cancel()
		if err == nil || hits.Load() != before+1 || time.Since(start) > time.Second {
			t.Fatal("bad response or follow-up accepted", i, err, hits.Load(), before)
		}
	}
	before := hits.Load()
	if _, err := fetchIPPDescription(context.Background(), netip.MustParseAddr("192.0.2.9"), server.URL+"/ipp/print"); err == nil || hits.Load() != before {
		t.Fatal("off-peer request")
	}
	mode.Store(0)
	d := Device{IP: peer}
	for i := 0; i < 8; i++ {
		d.Advertisements = append(d.Advertisements, ippAdvertisement(t, server.URL, "_ipp._tcp", fmt.Sprintf("ipp/%d", i)))
	}
	before = hits.Load()
	enrichDescriptions(context.Background(), &d, time.Second)
	if hits.Load()-before != 4 {
		t.Fatal("description budget changed", hits.Load()-before)
	}
}
