package ui

import (
	"bytes"
	"lantern/pkg/scanner"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestResponsiveReportFitsTerminal(t *testing.T) {
	for _, width := range []int{80, 120} {
		var b bytes.Buffer
		u := &UI{Out: &b, Width: width}
		r := scanner.Report{Probed: 254, Devices: []scanner.Device{{IP: netip.MustParseAddr("192.168.100.100"), Names: []string{strings.Repeat("x", 100) + "\x1b[2J"}, Evidence: []string{"icmp"}, Ports: []scanner.Port{{Number: 443, Service: "https"}}}}}
		u.Report(r)
		for _, line := range strings.Split(b.String(), "\n") {
			if utf8.RuneCountInString(line) > width {
				t.Fatalf("width %d overflow: %q", width, line)
			}
		}
		if strings.Contains(b.String(), "\x1b") {
			t.Fatal("terminal escape leaked into plain output")
		}
	}
}

func TestIPv6ReportKeepsFullAddress(t *testing.T) {
	ip := netip.MustParseAddr("fe80::1234:5678:abcd:ef12%en123")
	for _, width := range []int{60, 80, 100, 140} {
		var b bytes.Buffer
		(&UI{Out: &b, Width: width}).Report(scanner.Report{AddressMode: "discovered", Devices: []scanner.Device{{IP: ip, Names: []string{"A very long device name that needs to fit within a narrow terminal"}}}})
		if !strings.Contains(b.String(), ip.String()) {
			t.Fatal("address truncated", b.String())
		}
		for _, line := range strings.Split(b.String(), "\n") {
			if utf8.RuneCountInString(line) > width {
				t.Fatalf("width %d overflow: %q", width, line)
			}
		}
	}
}

func TestModelCandidateRendering(t *testing.T) {
	for _, names := range [][]string{{"Mac Studio (M4 Max, 2025)"}, {"MacBook Pro Late 2013", "MacBook Pro Mid 2014"}} {
		r := scanner.Report{Devices: []scanner.Device{{IP: netip.MustParseAddr("192.0.2.1"), Identity: &scanner.Identity{Model: "Model1,1", Manufacturer: "Apple", ModelNames: names}}}}
		var b bytes.Buffer
		u := &UI{Out: &b, Width: 80}
		u.Report(r)
		if len(names) == 1 && !strings.Contains(b.String(), names[0]) {
			t.Fatal(b.String())
		}
		if len(names) > 1 && !strings.Contains(b.String(), "2 possible models") {
			t.Fatal(b.String())
		}
		for _, line := range strings.Split(b.String(), "\n") {
			if utf8.RuneCountInString(line) > 80 {
				t.Fatal("overflow", line)
			}
		}
		b.Reset()
		u.Details(r)
		for _, name := range names {
			if !strings.Contains(b.String(), name) {
				t.Fatal("lost candidate", name)
			}
		}
	}
}
