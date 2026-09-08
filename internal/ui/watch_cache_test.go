package ui

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coupez/lantern/pkg/scanner"
)

func TestServicePreviewMatchesFullRendering(t *testing.T) {
	for _, services := range [][]string{nil, {"https"}, {"東京", "👩‍💻", "e\u0301", "🇧🇪", "\x1b[2Jbad\u202e", ""}, {strings.Repeat("x", 500), "last"}, {"\u200d", "\u0301", "last"}} {
		d := scanner.Device{}
		for i, service := range services {
			d.Ports = append(d.Ports, scanner.Port{Number: uint16(i + 1), Service: service})
		}
		for width := 0; width < 140; width++ {
			if got, want := deviceServicesPreview(d, width), fit(deviceServices(d), width); got != want {
				t.Fatalf("width=%d services=%q: %q != %q", width, services, got, want)
			}
		}
	}
}

func TestWatchSearchRetainsFullPortsAndRefreshes(t *testing.T) {
	m := largeWatchFixture(1, 65535)
	m.devices()
	if m.searchText != nil {
		t.Fatal("empty query built search index")
	}
	m.query = "65535/unknown"
	if len(m.devices()) != 1 {
		t.Fatal("late port not searchable")
	}
	text := m.searchText[0]
	m.query = "65534/unknown 65535/unknown"
	if len(m.devices()) != 1 || m.searchText[0] != text {
		t.Fatal("query changed search semantics")
	}
	changed := m.report.Devices[0].Clone()
	changed.Ports = []scanner.Port{{Number: 22, Service: "ssh"}}
	changed.Identity = &scanner.Identity{Firmware: "Shelly", FirmwareVersion: "2.0", Name: "Updated"}
	m.accept(scanner.Report{Devices: []scanner.Device{changed}})
	if len(m.devices()) != 0 {
		t.Fatal("old port remained indexed")
	}
	m.query = "shelly 2.0"
	if len(m.devices()) != 1 {
		t.Fatal("new firmware was not indexed")
	}
	m.query = ""
	if len(m.devices()) != 1 {
		t.Fatal("clearing search lost device")
	}
}

func TestWatchDetailsCacheRefreshResizeAndSelection(t *testing.T) {
	m := largeWatchFixture(2, 1)
	m.details = true
	m.report.Devices[0].Ports[0].Banner = strings.Repeat("long banner ", 12)
	u := &UI{}
	now := time.Unix(0, 0)
	m.frame(u, 80, 20, now)
	wideCount := len(m.detailLines)
	first := &m.detailLines[0]
	m.frame(u, 80, 20, now.Add(time.Millisecond))
	if &m.detailLines[0] != first {
		t.Fatal("unchanged details rebuilt")
	}
	m.frame(u, 36, 20, now)
	if len(m.detailLines) <= wideCount || m.detailWidth != 35 {
		t.Fatal("resize reused stale wrapping")
	}
	m.selected = m.report.Devices[1].IP.String()
	m.frame(u, 80, 20, now)
	if m.detailIP != m.selected || strings.Contains(strings.Join(m.detailLines, "\n"), "long banner") {
		t.Fatal("previous device remained in inspector")
	}
	changed := m.report.Devices[1].Clone()
	changed.Identity = &scanner.Identity{Name: "Updated inspector"}
	m.accept(scanner.Report{Devices: []scanner.Device{changed}})
	frame := m.frame(u, 80, 20, now)
	if !strings.Contains(frame, "Updated inspector") {
		t.Fatal("completed report did not invalidate details", frame)
	}
}

func TestWatchMailboxInvalidatesOnlyForDeviceUpdates(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	b := watchMailbox{discovered: map[string]scanner.Device{}}
	m := watchModel{details: true, query: "before"}
	b.emit(scanner.Event{Type: "device", Device: &scanner.Device{IP: ip, Names: []string{"before"}}})
	b.update(&m)
	m.frame(&UI{}, 80, 20, time.Now())
	if len(m.devices()) != 1 || m.detailLines == nil {
		t.Fatal("initial device missing")
	}
	first := &m.detailLines[0]
	b.emit(scanner.Event{Type: "progress", Phase: "enrichment", Completed: 1, Total: 2})
	b.update(&m)
	m.frame(&UI{}, 80, 20, time.Now())
	if &m.detailLines[0] != first || m.completed != 1 || m.total != 2 {
		t.Fatal("progress invalidated device cache or went stale")
	}
	b.emit(scanner.Event{Type: "device_update", Device: &scanner.Device{IP: ip, Names: []string{"after"}}})
	b.update(&m)
	if len(m.devices()) != 0 || m.detailLines != nil {
		t.Fatal("updated device retained old cache")
	}
	m.query = "after"
	if frame := m.frame(&UI{}, 80, 20, time.Now()); !strings.Contains(frame, "after") {
		t.Fatal("live update invisible", frame)
	}
}

func TestWatchInspectorRetainsLastPort(t *testing.T) {
	m := largeWatchFixture(1, 65535)
	m.details = true
	m.key("end")
	frame := m.frame(&UI{}, 80, 20, time.Now())
	if !strings.Contains(frame, "65535") || len(m.detailLines) < 65535 {
		t.Fatal("inspector truncated ports")
	}
}
