package ui

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/coupez/lantern/pkg/scanner"
)

func largeWatchFixture(count, ports int) watchModel {
	m := watchModel{hasReport: true, target: "192.0.2.0/24", profile: "deep"}
	for i := 0; i < count; i++ {
		d := scanner.Device{IP: netip.AddrFrom4([4]byte{192, 0, byte(i / 256), byte(i % 256)}), Names: []string{"fixture.local"}, Evidence: []string{"tcp-open"}}
		for p := 1; p <= ports; p++ {
			d.Ports = append(d.Ports, scanner.Port{Number: uint16(p), Service: "unknown"})
		}
		m.report.Devices = append(m.report.Devices, d)
	}
	return m
}

func BenchmarkWatchLargeResults(b *testing.B) {
	for _, tc := range []struct{ devices, ports int }{{1024, 14}, {16, 65535}} {
		for _, mode := range []string{"list", "search", "details"} {
			b.Run(fmt.Sprintf("devices-%d/ports-%d/%s", tc.devices, tc.ports, mode), func(b *testing.B) {
				m := largeWatchFixture(tc.devices, tc.ports)
				m.details = mode == "details"
				if mode == "search" {
					m.query = "65535/unknown"
				}
				now := time.Unix(0, 0)
				u := &UI{}
				// A normal 10 Hz redraw while the current report/query is stable.
				m.frame(u, 120, 40, now)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					m.frame(u, 120, 40, now)
				}
			})
		}
	}
}

// Measure the work intentionally retained when a new report invalidates a view.
func BenchmarkWatchBuildViews(b *testing.B) {
	for _, mode := range []string{"list", "search", "details"} {
		b.Run(mode, func(b *testing.B) {
			m := largeWatchFixture(16, 65535)
			m.details = mode == "details"
			if mode == "search" {
				m.query = "65535/unknown"
			}
			u, now := &UI{}, time.Unix(0, 0)
			b.ReportAllocs()
			for b.Loop() {
				m.invalidateDeviceView()
				m.frame(u, 120, 40, now)
			}
		})
	}
}

func BenchmarkWatchClaimSearch(b *testing.B) {
	for _, mode := range []string{"new-report", "changing-query", "steady-frame"} {
		b.Run(mode, func(b *testing.B) {
			m := largeWatchFixture(1024, 14)
			for i := range m.report.Devices {
				id := &scanner.Identity{Name: fmt.Sprintf("Device %d", i), Model: "Selected model"}
				for j := range 64 {
					id.Claims = append(id.Claims, scanner.IdentityClaim{Field: "hardware", Value: fmt.Sprintf("Board-%04d revision-%02d", i, j)})
				}
				m.report.Devices[i].Identity = id
			}
			m.query = "revision-63"
			m.devices()
			u, now := &UI{}, time.Unix(0, 0)
			b.ReportAllocs()
			b.ResetTimer()
			toggle := false
			for b.Loop() {
				switch mode {
				case "new-report":
					m.invalidateDeviceView()
					m.devices()
				case "changing-query":
					toggle = !toggle
					if toggle {
						m.query = "revision-62"
					} else {
						m.query = "revision-63"
					}
					m.devices()
				case "steady-frame":
					m.frame(u, 120, 40, now)
				}
			}
		})
	}
}
