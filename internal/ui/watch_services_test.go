package ui

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coupez/lantern/pkg/fingerprints"
	"github.com/coupez/lantern/pkg/scanner"
)

func TestWatchActivityServiceUpgrade(t *testing.T) {
	report := func(value string) scanner.Report {
		return scanner.Report{Coverage: &scanner.ScanCoverage{TCPPorts: []uint16{443}, Banners: true}, Devices: []scanner.Device{{IP: netip.MustParseAddr("192.0.2.1"), Ports: []scanner.Port{{Number: 443, Service: "https", Fingerprint: fingerprints.Lookup(fingerprints.HTTPServer, value)}}}}}
	}
	m := watchModel{}
	m.accept(report("Apache/2.4.64"))
	m.accept(report("Apache/2.4.65"))
	if len(m.changes) != 1 || !strings.Contains(m.changes[0], "TCP 443 catalog version") || !strings.Contains(m.changes[0], "2.4.64") || !strings.Contains(m.changes[0], "2.4.65") {
		t.Fatal(m.changes)
	}
	m.key("a")
	for _, width := range []int{80, 120} {
		frame := m.frame(&UI{}, width, 24, time.Now())
		if !strings.Contains(frame, "TCP 443 catalog version") || !strings.Contains(frame, "2.4.64") || !strings.Contains(frame, "2.4.65") {
			t.Fatal(frame)
		}
	}
	m.accept(report("Apache/2.4.65 (build 12345)"))
	if len(m.changes) != 1 {
		t.Fatal("volatile banner created activity", m.changes)
	}
}
