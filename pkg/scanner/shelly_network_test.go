package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func shellyHTTPFixture(t *testing.T, address string, handler http.Handler) *httptest.Server {
	t.Helper()
	requireNetwork(t)
	ln, err := net.Listen("tcp", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(handler)
	s.Listener.Close()
	s.Listener = ln
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func TestShellyHTTPNetworkIntegration(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			var hits atomic.Int32
			server := shellyHTTPFixture(t, address, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				switch r.URL.Path {
				case "/shelly":
					fmt.Fprint(w, shellyFixture)
				case "/redirect":
					http.Redirect(w, r, "/shelly", http.StatusFound)
				case "/large":
					fmt.Fprint(w, strings.Repeat(" ", maxShellyBytes)+shellyFixture)
				case "/headers":
					w.Header().Set("X-Long", strings.Repeat("x", 32*1024))
					fmt.Fprint(w, shellyFixture)
				case "/invalid":
					fmt.Fprint(w, `<html>web page</html>`)
				case "/auth":
					w.WriteHeader(http.StatusUnauthorized)
				case "/slow":
					<-r.Context().Done()
				}
			}))
			ip := netip.MustParseAddr(address)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			for _, path := range []string{"/redirect", "/large", "/headers", "/invalid", "/auth"} {
				before := hits.Load()
				if _, err := fetchShellyDescription(ctx, ip, server.URL+path); err == nil || hits.Load() != before+1 {
					t.Fatal(path, err, hits.Load())
				}
			}
			before := hits.Load()
			if _, err := fetchShellyDescription(ctx, netip.MustParseAddr("192.0.2.1"), server.URL+"/shelly"); err == nil || hits.Load() != before {
				t.Fatal("off-device request", err)
			}
			slow, stop := context.WithTimeout(ctx, 30*time.Millisecond)
			defer stop()
			start := time.Now()
			if _, err := fetchShellyDescription(slow, ip, server.URL+"/slow"); err == nil || time.Since(start) > time.Second {
				t.Fatal("unbounded read", err)
			}
			ad := Advertisement{Protocol: "mdns", Service: "_shelly._tcp", Port: uint16(server.Listener.Addr().(*net.TCPAddr).Port), Properties: map[string]string{"url": "http://192.0.2.2/control", "path": "/invalid"}}
			d := Device{IP: ip, MAC: "02:aa:bb:cc:dd:ee", Advertisements: []Advertisement{ad, ad, ad}}
			before = hits.Load()
			enrichDescriptions(ctx, &d, time.Second)
			id := identify(d.Advertisements)
			if hits.Load() != before+1 || len(d.Advertisements) != 4 || id == nil || id.Model != "SNSW-001X16EU" || d.MAC != "02:aa:bb:cc:dd:ee" || len(d.Ports) != 0 {
				t.Fatal(d, id, hits.Load())
			}
		})
	}
}

func TestShellySharedDescriptionBudgetNetworkIntegration(t *testing.T) {
	var hits atomic.Int32
	server := shellyHTTPFixture(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/shelly" {
			fmt.Fprint(w, shellyFixture)
		} else {
			fmt.Fprint(w, descriptionFixture)
		}
	}))
	ad := Advertisement{Protocol: "mdns", Service: "_shelly._tcp", Port: uint16(server.Listener.Addr().(*net.TCPAddr).Port)}
	d := Device{IP: netip.MustParseAddr("127.0.0.1"), Advertisements: []Advertisement{ad}}
	for i := 0; i < 5; i++ {
		d.Advertisements = append(d.Advertisements, Advertisement{Protocol: "ssdp", Properties: map[string]string{"location": fmt.Sprintf("%s/device%d", server.URL, i)}})
	}
	enrichDescriptions(context.Background(), &d, time.Second)
	if hits.Load() != 4 {
		t.Fatal("separate per-protocol budgets", hits.Load())
	}
	// An earlier UPnP request can consume the shared deadline; Shelly must not
	// start a new timeout or open a socket after the budget expires.
	started, closed := make(chan struct{}), make(chan struct{})
	slow := shellyHTTPFixture(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(closed)
	}))
	d.Advertisements = []Advertisement{{Protocol: "ssdp", Properties: map[string]string{"location": slow.URL}}, ad}
	before := hits.Load()
	begin := time.Now()
	enrichDescriptions(context.Background(), &d, 50*time.Millisecond)
	if hits.Load() != before || time.Since(begin) > time.Second {
		t.Fatal("deadline not shared")
	}
	select {
	case <-started:
	default:
		t.Fatal("slow fixture never requested")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("expired connection not closed")
	}
}

func TestShellyCancellationNetworkIntegration(t *testing.T) {
	started, closed := make(chan struct{}), make(chan struct{})
	server := shellyHTTPFixture(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(closed)
	}))
	ad := Advertisement{Protocol: "mdns", Service: "_shelly._tcp", Port: uint16(server.Listener.Addr().(*net.TCPAddr).Port)}
	d := Device{IP: netip.MustParseAddr("127.0.0.1"), Advertisements: []Advertisement{ad}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { enrichDescriptions(ctx, &d, 30*time.Second); close(done) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request never started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("enrichment ignored cancellation")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("cancelled connection not closed")
	}
	if len(d.Advertisements) != 1 {
		t.Fatal("failed request replaced discovery")
	}
}
