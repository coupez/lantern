package scanner

import (
	"fmt"
	"net/netip"
	"testing"
)

// Repeated watch scans commonly retain the same port observations. Both reports
// own their lists, as they would after separate scans or snapshot loads.
func BenchmarkDiffPortObservations(b *testing.B) {
	for _, count := range []int{14, 65535} {
		for _, changed := range []bool{false, true} {
			b.Run(fmt.Sprintf("ports-%d/changed-%t", count, changed), func(b *testing.B) {
				before, after := Report{}, Report{}
				for i := 0; i < 16; i++ {
					d := Device{IP: netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), Ports: make([]Port, count)}
					for p := range d.Ports {
						d.Ports[p] = Port{Number: uint16(p + 1), Service: "unknown"}
					}
					before.Devices = append(before.Devices, d)
					next := d.Clone()
					if changed && i == 0 {
						next.Ports = next.Ports[:len(next.Ports)-1]
					}
					after.Devices = append(after.Devices, next)
				}
				want := 0
				if changed {
					want = 1
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if changes := Diff(before, after); len(changes) != want {
						b.Fatalf("got %d changes, want %d", len(changes), want)
					}
				}
			})
		}
	}
}
