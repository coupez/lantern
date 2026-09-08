package ui

import (
	"bytes"
	"fmt"
	"github.com/coupez/lantern/pkg/scanner"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rivo/uniseg"
)

type watchModel struct {
	target, profile, phase                                    string
	report                                                    scanner.Report
	hasReport, scanning, paused, details, searching, activity bool
	query, selected                                           string
	completed, total, discovered, offset                      int
	started, next                                             time.Time
	changes                                                   []string
}

func (m *watchModel) accept(r scanner.Report) {
	if m.hasReport && !r.Cancelled && r.Error == "" {
		for _, c := range scanner.Diff(m.report, r) {
			m.changes = append(m.changes, fmt.Sprintf("%s  %s · %s %s", time.Now().Format("15:04:05"), c.Type, c.IP, c.Detail))
		}
		if len(m.changes) > 40 {
			m.changes = append([]string(nil), m.changes[len(m.changes)-40:]...)
		}
	}
	m.report = r
	m.hasReport = true
	m.devices()
}
func deviceName(d scanner.Device) string {
	if d.Identity != nil && d.Identity.Name != "" {
		return d.Identity.Name
	}
	if len(d.Names) > 0 {
		return d.Names[0]
	}
	if d.Vendor.Name != "" {
		return d.Vendor.Name
	}
	if d.Identity != nil && d.Identity.Model != "" {
		return d.Identity.Model
	}
	if d.Vendor.Private {
		return "Private / randomized MAC"
	}
	return "Unknown device"
}
func deviceServices(d scanner.Device) string {
	var ports []string
	for _, p := range d.Ports {
		ports = append(ports, fmt.Sprintf("%d/%s", p.Number, p.Service))
	}
	if len(ports) == 0 {
		return "—"
	}
	return strings.Join(ports, " ")
}
func (m *watchModel) devices() []scanner.Device {
	out := make([]scanner.Device, 0, len(m.report.Devices))
	query := strings.ToLower(m.query)
	for _, d := range m.report.Devices {
		haystack := d.IP.String() + " " + d.MAC + " " + d.Vendor.Name + " " + strings.Join(d.Names, " ") + " " + deviceName(d) + " " + deviceServices(d)
		if d.Identity != nil {
			haystack += " " + d.Identity.Manufacturer + " " + d.Identity.Model + " " + strings.Join(d.Identity.ModelNames, " ")
		}
		if query == "" || strings.Contains(strings.ToLower(scanner.CleanText(haystack)), query) {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Compare(out[j].IP) < 0 })
	for _, d := range out {
		if d.IP.String() == m.selected {
			return out
		}
	}
	if m.selected != "" && !m.activity {
		m.offset = 0
	}
	m.selected = ""
	if len(out) > 0 {
		m.selected = out[0].IP.String()
	}
	return out
}
func (m *watchModel) key(key string) string {
	if key == "quit" {
		return "quit"
	}
	if m.searching {
		switch key {
		case "escape":
			m.searching = false
			m.query = ""
		case "enter":
			m.searching = false
		case "backspace":
			g := uniseg.NewGraphemes(m.query)
			end := 0
			for g.Next() {
				start, _ := g.Positions()
				end = start
			}
			m.query = m.query[:end]
		default:
			if utf8.RuneCountInString(key) == 1 && utf8.RuneCountInString(m.query) < 128 {
				m.query += scanner.CleanText(key)
			}
		}
		m.devices()
		return ""
	}
	switch key {
	case "q":
		return "quit"
	case "r":
		return "refresh"
	case " ":
		m.paused = !m.paused
	case "/":
		m.searching = true
	case "escape":
		m.activity = false
		m.details = false
		m.query = ""
		m.offset = 0
	case "a":
		m.activity = !m.activity
		m.details = false
		m.offset = 0
	case "enter":
		if m.activity {
			m.activity = false
		} else {
			m.details = !m.details
		}
		m.offset = 0
	case "up", "k", "down", "j", "pageup", "pagedown", "home", "end":
		delta := 1
		if key == "up" || key == "k" || key == "pageup" {
			delta = -1
		}
		if key == "pageup" || key == "pagedown" {
			delta *= 10
		}
		if m.details || m.activity {
			m.offset = max(0, m.offset+delta)
			if key == "home" {
				m.offset = 0
			}
			if key == "end" {
				m.offset = 1 << 30
			}
		} else {
			ds := m.devices()
			for i, d := range ds {
				if d.IP.String() == m.selected {
					index := max(0, min(len(ds)-1, i+delta))
					if key == "home" {
						index = 0
					}
					if key == "end" {
						index = len(ds) - 1
					}
					m.selected = ds[index].IP.String()
					break
				}
			}
		}
	}
	return ""
}

func wrapCells(s string, width int) []string {
	var lines []string
	var b strings.Builder
	used := 0
	g := uniseg.NewGraphemes(scanner.CleanText(s))
	for g.Next() {
		if used+g.Width() > width && used > 0 {
			lines = append(lines, b.String())
			b.Reset()
			used = 0
		}
		b.WriteString(g.Str())
		used += g.Width()
	}
	return append(lines, b.String())
}

func (m *watchModel) frame(u *UI, width, height int, now time.Time) string {
	width = max(1, width-1)
	height = max(1, height)
	lines := make([]string, 0, height)
	add := func(code, s string) { lines = append(lines, u.style(code, fit(s, width))) }
	if width < 35 || height < 10 {
		add("1;38;5;158", "◈ LANTERN")
		add("", "Enlarge to 36 × 10 to watch.")
		add("", "q quits · scans continue")
	} else {
		add("1;38;5;158", " ◈ LANTERN  /  LIVE NETWORK")
		add("38;5;245", " "+m.target+" · "+m.profile)
		add("38;5;81", " "+watchStatus(m, now))
		responsive, ports := 0, 0
		for _, d := range m.report.Devices {
			if live(d) {
				responsive++
			}
			ports += len(d.Ports)
		}
		summary := fmt.Sprintf(" %d devices · %d responsive · %d cached · %d open ports", len(m.report.Devices), responsive, len(m.report.Devices)-responsive, ports)
		if !m.hasReport {
			summary = fmt.Sprintf(" %d addresses discovered · details update as checks finish", m.discovered)
		}
		if m.scanning && m.hasReport {
			summary += " · previous scan"
		}
		add("", summary)
		ds := m.devices()
		query := " / search devices"
		if m.query != "" || m.searching {
			query = " / " + m.query
			if m.searching {
				query += "▏"
			}
			query += fmt.Sprintf("  (%d matches)", len(ds))
		}
		add("38;5;245", query)
		bodyHeight := height - 8
		if m.activity {
			var activityLines []string
			entry := func(s string) { activityLines = append(activityLines, wrapCells(" "+s, width)...) }
			entry("ACTIVITY · latest 40 changes · warnings from last scan")
			for _, warning := range m.report.Warnings {
				entry("! " + warning)
			}
			if stats := m.report.ICMP; stats != nil {
				entry(fmt.Sprintf("ICMP: %d sent · %d retries · %d recovered · %d unsent", stats.Sent, stats.Retries, stats.Recovered, stats.Failed))
			}
			if len(m.changes) == 0 {
				entry("No changes recorded yet.")
			}
			for i := len(m.changes) - 1; i >= 0; i-- {
				entry(m.changes[i])
			}
			m.offset = min(m.offset, max(0, len(activityLines)-bodyHeight))
			for _, line := range activityLines[m.offset:min(len(activityLines), m.offset+bodyHeight)] {
				add("", line)
			}
		} else if m.details && len(ds) > 0 {
			var selected scanner.Device
			for _, d := range ds {
				if d.IP.String() == m.selected {
					selected = d
					break
				}
			}
			var b bytes.Buffer
			(&UI{Out: &b, Width: width}).Details(scanner.Report{Devices: []scanner.Device{selected}})
			var detailLines []string
			for _, s := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
				detailLines = append(detailLines, wrapCells(s, width)...)
			}
			m.offset = min(m.offset, max(0, len(detailLines)-bodyHeight))
			for _, line := range detailLines[m.offset:min(len(detailLines), m.offset+bodyHeight)] {
				add("", line)
			}
		} else {
			ipWidth := 17
			for _, d := range ds {
				ipWidth = max(ipWidth, len(d.IP.String())+1)
			}
			wide := width >= ipWidth+48
			heading := " DEVICES · enter inspects selected device"
			if wide {
				heading = "   " + fit("ADDRESS", ipWidth) + fit("NAME / VENDOR", 26) + "SERVICES"
			}
			add("38;5;245", heading)
			rows := bodyHeight - 1
			index := 0
			for i, d := range ds {
				if d.IP.String() == m.selected {
					index = i
				}
			}
			start := max(0, index-rows+1)
			for _, d := range ds[start:min(len(ds), start+rows)] {
				dot := "●"
				if !live(d) {
					dot = "○"
				}
				if !m.hasReport {
					dot = "·"
				}
				prefix := " " + dot + " "
				code := ""
				if d.IP.String() == m.selected {
					prefix = "›" + dot + " "
					code = "1;38;5;158"
				}
				label := prefix + d.IP.String() + "  " + deviceName(d)
				if wide {
					label = prefix + fit(d.IP.String(), ipWidth) + fit(deviceName(d), 26) + deviceServices(d)
				}
				add(code, label)
			}
			if len(ds) == 0 {
				add("38;5;245", " No matching devices.")
			}
		}
		for len(lines) < height-3 {
			add("", "")
		}
		info := " ● responsive = replied this scan · cached neighbors may be offline"
		if len(m.changes) > 0 {
			info = " " + m.changes[len(m.changes)-1]
		}
		if m.report.ICMP != nil && m.report.ICMP.Failed > 0 {
			info = fmt.Sprintf(" ! ICMP: %d unsent · %d retries", m.report.ICMP.Failed, m.report.ICMP.Retries)
		}
		if len(m.report.Warnings) > 0 {
			info = fmt.Sprintf(" ! %d warnings · %s", len(m.report.Warnings), m.report.Warnings[0])
		}
		add("38;5;220", info)
		footer := " ↑↓ select · enter inspect · / search · a activity · space pause · r refresh · q quit"
		if width < 96 {
			footer = " ↑↓ select · enter inspect · / search · a activity · q quit"
		}
		if width < 60 {
			footer = " ↑↓ select · enter details · q quit"
		}
		if m.details || m.activity {
			footer = " ↑↓ scroll · enter back · q quit"
		}
		if m.searching {
			footer = " Type to filter · enter apply · esc clear · Ctrl-C quit"
		}
		add("38;5;245", footer)
		tail := fmt.Sprintf(" %d / %d devices", len(ds), len(m.report.Devices))
		if m.details {
			tail = " Device details · " + m.selected
		}
		if m.activity {
			tail = " Activity · enter returns to devices"
		}
		if width < 96 && !m.details && !m.activity && !m.searching {
			tail += " · space pause · r refresh"
			if width < 60 {
				tail = " / search · a log · space pause · r"
			}
		}
		add("38;5;245", tail)
	}
	for len(lines) < height {
		add("", "")
	}
	lines = lines[:height]
	return "\x1b[H\x1b[2K" + strings.Join(lines, "\r\n\x1b[2K")
}
