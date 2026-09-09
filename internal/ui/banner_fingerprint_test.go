package ui

import (
	"bytes"
	"github.com/coupez/lantern/pkg/fingerprints"
	"github.com/coupez/lantern/pkg/scanner"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestBannerCatalogDisplayAndSearch(t *testing.T) {
	match := fingerprints.Lookup(fingerprints.HTTPServer, "Eltex TAU-72")
	d := scanner.Device{IP: netip.MustParseAddr("192.0.2.1"), Ports: []scanner.Port{{Number: 80, Service: "http", Banner: match.Input, Fingerprint: match}}}
	report := scanner.Report{Devices: []scanner.Device{d}}
	var out bytes.Buffer
	(&UI{Out: &out, Width: 100}).Report(report)
	if !strings.Contains(out.String(), "Catalog · TCP 80") {
		t.Fatal(out.String())
	}
	out.Reset()
	(&UI{Out: &out, Width: 100}).Details(report)
	for _, value := range []string{match.Reference, "hw.product = TAU-72", "os.product = TAU-72 Firmware"} {
		if !strings.Contains(out.String(), value) {
			t.Fatal(value, out.String())
		}
	}
	m := watchModel{}
	m.accept(report)
	for _, query := range []string{"TAU-72 Firmware", "hw.product", "Eltex"} {
		m.query = query
		if len(m.devices()) != 1 {
			t.Fatal(query)
		}
	}
	m.query = ""
	frame := m.frame(&UI{}, 160, 24, time.Now())
	if !strings.Contains(frame, "catalog:") {
		t.Fatal(frame)
	}
	next := d.Clone()
	next.Ports[0].Fingerprint = nil
	m.accept(scanner.Report{Devices: []scanner.Device{next}})
	m.query = "hw.product"
	if len(m.devices()) != 0 {
		t.Fatal("stale fingerprint search")
	}
	for _, width := range []int{10, 30, 60, 100} {
		if got, want := deviceServicesPreview(d, width), fit(deviceServices(d), width); got != want {
			t.Fatal(width, got, want)
		}
	}
}
