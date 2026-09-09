package scanner

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/coupez/lantern/pkg/fingerprints"
)

func BenchmarkDiffServiceObservations(b *testing.B) {
	for _, size := range []int{14, 65535} {
		ports := []uint16{21, 22, 25, 80, 110, 143, 443, 631, 993, 995, 3389, 8080, 8443, 9100}
		if size == 65535 {
			ports = make([]uint16, size)
			for i := range ports {
				ports[i] = uint16(i + 1)
			}
		}
		before := Report{Coverage: &ScanCoverage{TCPPorts: ports, Banners: true}}
		after := Report{Coverage: &ScanCoverage{TCPPorts: ports, Banners: true}}
		match := fingerprints.Lookup(fingerprints.HTTPServer, "Apache/2.4.64")
		for i := 0; i < 16; i++ {
			d := Device{IP: netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})}
			for _, number := range ports {
				p := Port{Number: number}
				if number == 80 || number == 443 || number == 8080 || number == 8443 {
					p.Fingerprint = match.Clone()
				}
				d.Ports = append(d.Ports, p)
			}
			before.Devices = append(before.Devices, d)
			after.Devices = append(after.Devices, d.Clone())
		}
		for _, changed := range []bool{false, true} {
			name := "unchanged"
			if changed {
				name = "one-version"
				for j, p := range after.Devices[0].Ports {
					if p.Number == 80 {
						after.Devices[0].Ports[j].Fingerprint = fingerprints.Lookup(fingerprints.HTTPServer, "Apache/2.4.65")
					}
				}
			}
			b.Run(fmt.Sprintf("%d/%s", size, name), func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					changes := Diff(before, after)
					want := 0
					if changed {
						want = 1
					}
					if len(changes) != want {
						b.Fatal(changes)
					}
				}
			})
		}
	}
}
