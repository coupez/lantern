package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type eventFixtureDialer struct{ port uint16 }

func (f eventFixtureDialer) Probe(_ context.Context, ip netip.Addr, port uint16, _ time.Duration) (bool, bool, time.Duration, error) {
	return true, ip == netip.MustParseAddr("127.0.0.1") && port == f.port, 0, nil
}

func TestEnrichedEventsNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	// Discovery is injected; only the slow banner uses a real loopback socket.
	var listener net.Listener
	var port uint16
	for _, candidate := range []uint16{3000, 5000, 8008, 8080, 9000} {
		var err error
		listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", candidate))
		if err == nil {
			port = candidate
			break
		}
	}
	if listener == nil {
		t.Skip("all supported loopback HTTP fixture ports are occupied")
	}
	defer listener.Close()
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		close(started)
		<-release
		fmt.Fprint(c, "HTTP/1.0 200 OK\r\nServer: Apache/2.4.65\r\n\r\n")
	}()
	o := Defaults()
	o.Target = netip.MustParsePrefix("127.0.0.0/30")
	o.Ports = []uint16{port}
	o.ICMP, o.Multicast, o.Resolve, o.Descriptions = false, false, false, false
	o.Banners = true
	o.Timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updated := make(chan Event, 1)
	type result struct {
		report Report
		err    error
	}
	done := make(chan result, 1)
	go func() {
		r, err := (Engine{Dialer: eventFixtureDialer{port}, NeighborSource: noNeighbors}).Scan(ctx, o, func(e Event) {
			if e.Type == "device_update" && len(e.Device.Ports) > 0 {
				if e.Device.Ports[0].Fingerprint == nil {
					t.Error("missing fingerprint in final event")
				} else {
					e.Device.Ports[0].Fingerprint.Fields["service.product"] = "consumer mutation"
				}
			}
			if e.Type == "device_update" && e.Device.IP == netip.MustParseAddr("127.0.0.2") {
				updated <- e
			}
		})
		done <- result{r, err}
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("banner fixture did not start")
	}
	select {
	case e := <-updated:
		if e.Device.Kind == "" {
			t.Fatal("unenriched update", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slow device withheld another device's update")
	}
	select {
	case <-done:
		t.Fatal("scan completed before releasing slow banner")
	default:
	}
	unblock()
	select {
	case result := <-done:
		if result.err != nil || len(result.report.Devices) != 2 || len(result.report.Devices[0].Ports) != 1 || result.report.Devices[0].Ports[0].Banner != "Apache/2.4.65" {
			t.Fatal(result)
		}
		if match := result.report.Devices[0].Ports[0].Fingerprint; match == nil || match.Fields["service.product"] != "HTTPD" {
			t.Fatal("event mutation escaped into returned report", match)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not finish after banner release")
	}
}
