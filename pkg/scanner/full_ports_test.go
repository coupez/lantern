package scanner

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type countedFullPortDialer struct{ calls [2][65536]atomic.Uint32 }

func (d *countedFullPortDialer) Probe(_ context.Context, ip netip.Addr, port uint16, _ time.Duration) (bool, bool, time.Duration, error) {
	d.calls[ip.As4()[3]][port].Add(1)
	return true, true, time.Millisecond, nil
}

func TestFullPortScanHasUniqueJobsAndOwnedResults(t *testing.T) {
	for name, all := range map[string]bool{"filtered": false, "all-hosts": true} {
		t.Run(name, func(t *testing.T) {
			o := Defaults()
			o.AllHosts = all
			o.Target = netip.MustParsePrefix("192.0.2.0/31")
			o.Ports, _ = ParsePorts("1-65535")
			// Include overlaps with the initial discovery pass and duplicated end ports.
			o.Ports = append(o.Ports, 65535, 1, 80, 443, 22, 65535)
			o.ICMP, o.Multicast, o.Resolve, o.Descriptions = false, false, false, false
			dialer := &countedFullPortDialer{}
			updates := 0
			r, err := (Engine{Dialer: dialer, NeighborSource: noNeighbors}).Scan(context.Background(), o, func(e Event) {
				if e.Type == "device_update" {
					updates++
					if len(e.Device.Ports) != 65535 {
						t.Errorf("incomplete device update: %d ports", len(e.Device.Ports))
					}
				}
				if e.Device != nil && len(e.Device.Ports) > 0 {
					e.Device.Ports[0].Number = 0
				}
			})
			if err != nil || r.Cancelled || r.Probed != 2 || len(r.Devices) != 2 || updates != 2 {
				t.Fatal(r.Probed, len(r.Devices), updates, err)
			}
			if len(r.Coverage.TCPPorts) != 65535 || len(o.Ports) != 65541 || o.Ports[len(o.Ports)-1] != 65535 {
				t.Fatal("plan/coverage ownership lost")
			}
			for _, device := range r.Devices {
				if len(device.Ports) != 65535 {
					t.Fatal(device.IP, len(device.Ports))
				}
				for i, p := range device.Ports {
					if int(p.Number) != i+1 || dialer.calls[device.IP.As4()[3]][p.Number].Load() != 1 {
						t.Fatal("missing/duplicate/mutated port", device.IP, i, p)
					}
				}
			}
		})
	}
}

type cancellingPortDialer struct {
	probes atomic.Uint32
	cancel context.CancelFunc
}

func (d *cancellingPortDialer) Probe(context.Context, netip.Addr, uint16, time.Duration) (bool, bool, time.Duration, error) {
	if d.probes.Add(1) == 100 {
		d.cancel()
	}
	return true, true, time.Millisecond, nil
}

func TestFullPortCancellationKeepsUniquePartialResults(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("192.0.2.1/32")
	o.Ports, _ = ParsePorts("1-65535")
	o.ICMP, o.Multicast, o.Resolve, o.Descriptions = false, false, false, false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialer := &cancellingPortDialer{cancel: cancel}
	r, err := (Engine{Dialer: dialer, NeighborSource: noNeighbors}).Scan(ctx, o, nil)
	if err != nil || !r.Cancelled || len(r.Devices) != 1 {
		t.Fatal(len(r.Devices), r.Cancelled, err)
	}
	ports := r.Devices[0].Ports
	if len(ports) != int(dialer.probes.Load()) || len(ports) < 100 || len(ports) >= 100+o.Concurrency {
		t.Fatal("cancel did not stop pending jobs", len(ports), dialer.probes.Load())
	}
	for i, port := range ports {
		if port.Number == 0 || i > 0 && ports[i-1].Number >= port.Number {
			t.Fatal("duplicate/unsorted partial observation", i, port)
		}
	}
}
