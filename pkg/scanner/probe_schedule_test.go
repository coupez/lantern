package scanner

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type scheduledProbe struct {
	ip   netip.Addr
	port uint16
}

type gatedDiscoveryDialer struct {
	mu           sync.Mutex
	requested    chan struct{}
	once         sync.Once
	calls        map[scheduledProbe]int
	active, peak int
}

func (d *gatedDiscoveryDialer) Probe(ctx context.Context, ip netip.Addr, port uint16, _ time.Duration) (bool, bool, time.Duration, error) {
	d.mu.Lock()
	d.calls[scheduledProbe{ip, port}]++
	d.active++
	d.peak = max(d.peak, d.active)
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.active--; d.mu.Unlock() }()
	if port == 8080 {
		d.once.Do(func() { close(d.requested) })
	} else {
		select {
		case <-d.requested:
		case <-ctx.Done():
			return false, false, 0, nil
		}
	}
	return true, true, time.Millisecond, nil
}

func directTargetOptions(target string, all bool) Options {
	o := Defaults()
	o.Target = netip.MustParsePrefix(target)
	o.AllHosts = all
	o.Ports = []uint16{8080, 8080}
	o.Concurrency = 4
	o.ICMP, o.Multicast, o.Resolve, o.Descriptions = false, false, false, false
	return o
}

func TestDirectTargetsDoNotWaitForDiscoveryPorts(t *testing.T) {
	for _, tc := range []struct {
		target string
		all    bool
		hosts  int
	}{
		{"192.0.2.1/32", false, 1}, {"2001:db8::1/128", false, 1},
		{"192.0.2.0/31", true, 2}, {"2001:db8::/127", true, 2},
	} {
		t.Run(tc.target, func(t *testing.T) {
			o := directTargetOptions(tc.target, tc.all)
			d := &gatedDiscoveryDialer{requested: make(chan struct{}), calls: map[scheduledProbe]int{}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var last Event
			r, err := (Engine{Dialer: d, NeighborSource: noNeighbors}).Scan(ctx, o, func(e Event) {
				if e.Type == "progress" && e.Phase != "enrichment" {
					if e.Phase != "ports" {
						t.Errorf("unexpected phase: %+v", e)
					}
					last = e
				}
			})
			if err != nil || r.Cancelled || len(r.Devices) != tc.hosts || r.Probed != tc.hosts {
				t.Fatalf("requested probes waited for liveness: %+v, %v", r, err)
			}
			if d.active != 0 || d.peak > o.Concurrency || len(d.calls) != tc.hosts*4 || last.Completed != tc.hosts*4 || last.Total != tc.hosts*4 {
				t.Fatalf("plan/concurrency/progress: calls=%v active=%d peak=%d progress=%+v", d.calls, d.active, d.peak, last)
			}
			for job, count := range d.calls {
				if count != 1 {
					t.Fatalf("duplicate job: %+v: %d", job, count)
				}
			}
			for _, device := range r.Devices {
				if len(device.Ports) != 1 || device.Ports[0].Number != 8080 {
					t.Fatalf("discovery-only port leaked into requested results: %+v", device)
				}
			}
			if len(o.Ports) != 2 || len(r.Coverage.TCPPorts) != 1 || r.Coverage.TCPPorts[0] != 8080 {
				t.Fatal("plan ownership/coverage changed")
			}
		})
	}
}

type delayedProbeDialer struct{}

func (delayedProbeDialer) Probe(ctx context.Context, _ netip.Addr, _ uint16, _ time.Duration) (bool, bool, time.Duration, error) {
	select {
	case <-ctx.Done():
		return false, false, 0, nil
	case <-time.After(10 * time.Millisecond):
		return true, true, 10 * time.Millisecond, nil
	}
}

// Controlled per-probe delay isolates scheduling overhead from real routing,
// target load, packet loss, and privileged firewall configuration.
func BenchmarkDirectTargetProbeLatency(b *testing.B) {
	o := directTargetOptions("192.0.2.1/32", false)
	e := Engine{Dialer: delayedProbeDialer{}, NeighborSource: noNeighbors}
	b.ReportAllocs()
	for b.Loop() {
		r, err := e.Scan(context.Background(), o, nil)
		if err != nil || len(r.Devices) != 1 || len(r.Devices[0].Ports) != 1 {
			b.Fatal(r, err)
		}
	}
}
