package ui

import (
	"lantern/pkg/scanner"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rivo/uniseg"
)

func TestFitGraphemesAndControls(t *testing.T) {
	for _, s := range []string{"東京のプリンター", "👩‍💻 café e\u0301 🇧🇪", "\x1b[2Jbad\u202ename"} {
		for width := 0; width < 30; width++ {
			got := fit(s, width)
			if !utf8.ValidString(got) || uniseg.StringWidth(got) != width || strings.ContainsAny(got, "\x1b\u202e") {
				t.Fatalf("fit(%q,%d)=%q width=%d", s, width, got, uniseg.StringWidth(got))
			}
		}
	}
	if got := fit("👩‍💻abc", 3); got != "👩‍💻…" {
		t.Fatal("split emoji", got)
	}
	if got := fit("e\u0301abc", 2); got != "e\u0301…" {
		t.Fatal("split accent", got)
	}
}
func fixtureWatch() watchModel {
	m := watchModel{target: "fe80::%en123", profile: "standard", hasReport: true, next: time.Now().Add(time.Second)}
	for i := 1; i <= 50; i++ {
		ip := netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0x12, 0x34, 0x56, 0x78, 0, byte(i)}).WithZone("en123")
		m.report.Devices = append(m.report.Devices, scanner.Device{IP: ip, Names: []string{"東京 👩‍💻 café\x1b[2J"}, Identity: &scanner.Identity{Model: "Mac16,9", ModelNames: []string{"Mac Studio (M4 Max, 2025)"}}, Ports: []scanner.Port{{Number: 443, Service: "https", Banner: strings.Repeat("長", 200)}}})
	}
	return m
}
func TestWatchFramesFitAndSanitize(t *testing.T) {
	ansi := regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	for _, size := range [][2]int{{1, 1}, {20, 6}, {36, 10}, {60, 15}, {80, 24}, {120, 40}, {180, 55}} {
		for _, details := range []bool{false, true} {
			m := fixtureWatch()
			m.details = details
			m.offset = 100000
			frame := m.frame(&UI{Color: true}, size[0], size[1], time.Now())
			lines := strings.Split(ansi.ReplaceAllString(frame, ""), "\r\n")
			if len(lines) != size[1] {
				t.Fatal(size, len(lines))
			}
			for _, line := range lines {
				if strings.Contains(line, "\x1b") || uniseg.StringWidth(line) > max(1, size[0]-1) {
					t.Fatalf("overflow %v: %q", size, line)
				}
			}
			if strings.Contains(frame, "\x1b[2J") {
				t.Fatal("network escape escaped sanitization")
			}
		}
	}
}
func TestWatchSelectionSearchAndRefresh(t *testing.T) {
	m := fixtureWatch()
	ds := m.devices()
	m.key("down")
	selected := m.selected
	if selected != ds[1].IP.String() {
		t.Fatal(selected)
	}
	m.report.Devices = append([]scanner.Device{{IP: netip.MustParseAddr("10.0.0.1")}}, m.report.Devices...)
	m.devices()
	if m.selected != selected {
		t.Fatal("selection shifted on insertion")
	}
	m.key("/")
	for _, r := range "Mac16" {
		m.key(string(r))
	}
	if len(m.devices()) != 50 {
		t.Fatal("model search failed")
	}
	m.key("enter")
	m.key("enter")
	if !m.details {
		t.Fatal("inspector")
	}
	m.key("end")
	m.frame(&UI{}, 60, 12, time.Now())
	if m.offset == 0 || m.offset > 1000 {
		t.Fatal("unbounded scroll", m.offset)
	}
	m.key("escape")
	if m.query != "" || m.details {
		t.Fatal("escape")
	}
	m.key(" ")
	if !m.paused || m.key("r") != "refresh" || m.key("q") != "quit" {
		t.Fatal("commands")
	}
	m.searching = true
	m.query = "a👩‍💻"
	m.key("backspace")
	if m.query != "a" {
		t.Fatal("grapheme backspace", m.query)
	}
	if m.key("quit") != "quit" {
		t.Fatal("Ctrl-C in search")
	}
}
func TestKeyDecoderFragmentationAndPaste(t *testing.T) {
	d := keyDecoder{}
	var got []string
	for _, b := range []byte("\x1b[B👩‍💻\x1b[200~q\x03\x1b[A\x1b[201~r") {
		got = append(got, d.feed(string([]byte{b}))...)
	}
	if strings.Join(got, "|") != "down|👩|\u200d|💻|r" {
		t.Fatalf("%q", got)
	}
	if len(d.feed("\x1b")) != 0 || strings.Join(d.flushEscape(), "") != "escape" {
		t.Fatal("escape")
	}
	if len(d.feed("\x1b[99q\x1bOQ")) != 0 {
		t.Fatal("unknown escape interpreted as commands")
	}
}
func TestWatchPartialReportDoesNotClaimMissing(t *testing.T) {
	m := fixtureWatch()
	m.accept(scanner.Report{Cancelled: true})
	if len(m.changes) != 0 {
		t.Fatal(m.changes)
	}
}

func TestActivityRetainsWarningsAndBoundsHistory(t *testing.T) {
	m := fixtureWatch()
	for i := 0; i < 5; i++ {
		m.accept(fixtureWatch().report)
		m.accept(scanner.Report{})
	}
	if len(m.changes) != 40 {
		t.Fatal(len(m.changes))
	}
	m.report.Warnings = []string{"First warning", "Second warning"}
	m.key("a")
	frame := m.frame(&UI{}, 100, 24, time.Now())
	if !strings.Contains(frame, "First warning") || !strings.Contains(frame, "Second warning") {
		t.Fatal(frame)
	}
	m.key("end")
	frame = m.frame(&UI{}, 36, 10, time.Now())
	if !strings.Contains(frame, "q quit") || m.offset == 0 {
		t.Fatal(frame)
	}
	m.key("enter")
	if m.activity || m.details {
		t.Fatal("did not return to devices")
	}
}

func TestWatchActivityReportsIdentityChanges(t *testing.T) {
	m := watchModel{}
	ip := netip.MustParseAddr("192.0.2.1")
	m.accept(scanner.Report{Devices: []scanner.Device{{IP: ip, Identity: &scanner.Identity{Name: "Before"}}}})
	m.accept(scanner.Report{Devices: []scanner.Device{{IP: ip, Identity: &scanner.Identity{Name: "After"}}}})
	if len(m.changes) != 1 || !strings.Contains(m.changes[0], "reported name") || !strings.Contains(m.changes[0], "After") {
		t.Fatal(m.changes)
	}
}
