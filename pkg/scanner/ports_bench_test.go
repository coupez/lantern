package scanner

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// Isolate core scheduling/aggregation from network latency. An address that
// accepts every TCP port is the worst case for growing its observed-port list.
type allOpenDialer struct{}

func (allOpenDialer) Probe(context.Context, netip.Addr, uint16, time.Duration) (bool, bool, time.Duration, error) {
	return true, true, time.Millisecond, nil
}

func BenchmarkPortAggregation(b *testing.B) {
	for _, count := range []int{14, 1024, 65535} {
		for _, workers := range []int{1, 512} {
			b.Run(fmt.Sprintf("ports-%d/workers-%d", count, workers), func(b *testing.B) {
				o := Defaults()
				o.Target = netip.MustParsePrefix("192.0.2.1/32")
				o.ICMP, o.Multicast, o.Resolve, o.Descriptions = false, false, false, false
				o.Concurrency = workers
				o.Ports = make([]uint16, count)
				for i := range o.Ports {
					o.Ports[i] = uint16(i + 1)
				}
				e := Engine{Dialer: allOpenDialer{}, NeighborSource: noNeighbors}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					r, err := e.Scan(context.Background(), o, nil)
					if err != nil || len(r.Devices) != 1 || len(r.Devices[0].Ports) != count {
						b.Fatal(r, err)
					}
				}
			})
		}
	}
}
