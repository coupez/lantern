package ui

import (
	"bytes"
	"github.com/coupez/lantern/pkg/scanner"
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

func TestNetBIOSIsResponsiveEvidence(t *testing.T) {
	if !live(scanner.Device{Evidence: []string{"netbios"}}) {
		t.Fatal("NetBIOS reply classified as cached")
	}
}

func TestProtocolClaimsAndUntrustedTXTDisplay(t *testing.T) {
	var b bytes.Buffer
	id := &scanner.Identity{Model: "Fixture Light", Claims: []scanner.IdentityClaim{{Field: "kind", Value: "light", Source: "mdns:Fixture", Key: "ci", Basis: "protocol", Identifier: "5", Reference: "https://example.com/protocol"}}}
	r := scanner.Report{Devices: []scanner.Device{{IP: netip.MustParseAddr("192.0.2.1"), Identity: id, Kind: "light", Advertisements: []scanner.Advertisement{{Protocol: "mdns", Service: "_hap._tcp", Properties: map[string]string{"md": "Fixture\x1b\x00\u202e Light", "ci": "5\r\nInjected"}}}}}}
	(&UI{Out: &b, Width: 100}).Details(r)
	out := b.String()
	if !strings.Contains(out, "kind = light") || !strings.Contains(out, "ci; protocol") || !strings.Contains(out, "https://example.com/protocol") || strings.ContainsAny(out, "\x1b\x00\r\u202e") || strings.Contains(out, "\nInjected") {
		t.Fatal(out)
	}
}

func TestProgressPhaseChangeBypassesThrottle(t *testing.T) {
	var b bytes.Buffer
	u := &UI{Out: &b, Color: true}
	u.Progress(scanner.Event{Type: "progress", Phase: "ports", Completed: 1, Total: 1})
	b.Reset()
	u.Progress(scanner.Event{Type: "progress", Phase: "enrichment", Total: 2})
	if !strings.Contains(b.String(), "Identifying") || !strings.Contains(b.String(), "0 / 2") {
		t.Fatal("phase change was throttled", b.String())
	}
}

func TestFirmwareReportDetailsAndWatchSearch(t *testing.T) {
	d := scanner.Device{IP: netip.MustParseAddr("192.0.2.1"), Identity: &scanner.Identity{Firmware: "ESPHome", FirmwareVersion: "2026.8.1\x1b\u202e"}}
	for _, width := range []int{36, 80, 120} {
		var b bytes.Buffer
		u := &UI{Out: &b, Width: width}
		u.Report(scanner.Report{Devices: []scanner.Device{d}})
		if !strings.Contains(b.String(), "ESPHome") || !strings.Contains(b.String(), "2026.8.1") || strings.ContainsAny(b.String(), "\x1b\u202e") {
			t.Fatal(b.String())
		}
		for _, line := range strings.Split(b.String(), "\n") {
			if utf8.RuneCountInString(line) > width {
				t.Fatal("overflow", width, line)
			}
		}
		b.Reset()
		u.Details(scanner.Report{Devices: []scanner.Device{d}})
		if !strings.Contains(b.String(), "Firmware") || !strings.Contains(b.String(), "FW version") || strings.ContainsAny(b.String(), "\x1b\u202e") {
			t.Fatal(b.String())
		}
	}
	m := watchModel{report: scanner.Report{Devices: []scanner.Device{d}}}
	for _, query := range []string{"esphome", "2026.8.1"} {
		m.query = query
		if len(m.devices()) != 1 || deviceName(d) != "ESPHome" {
			t.Fatal("firmware missing from watch search/name", query)
		}
	}
}
