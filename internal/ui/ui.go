package ui

import (
	"fmt"
	"golang.org/x/term"
	"io"
	"lantern/pkg/scanner"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type UI struct {
	Out   io.Writer
	Color bool
	Width int
	last  time.Time
}

func New(out *os.File, noColor bool) *UI {
	w := 100
	if width, _, err := term.GetSize(int(out.Fd())); err == nil {
		w = width
	}
	return &UI{Out: out, Color: !noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" && term.IsTerminal(int(out.Fd())), Width: w}
}
func (u *UI) style(code, s string) string {
	if !u.Color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func (u *UI) Intro(target, profile string) {
	fmt.Fprintln(u.Out)
	fmt.Fprintf(u.Out, "  %s  %s\n", u.style("1;38;5;158", "◈ LANTERN"), u.style("38;5;245", "See your network clearly."))
	fmt.Fprintf(u.Out, "  %s  %s · %s\n\n", u.style("38;5;81", "↳"), target, profile)
}
func (u *UI) Progress(e scanner.Event) {
	if !u.Color {
		return
	}
	if e.Type == "progress" && time.Since(u.last) > 70*time.Millisecond {
		u.last = time.Now()
		pct := 0
		if e.Total > 0 {
			pct = e.Completed * 100 / e.Total
		}
		fmt.Fprintf(u.Out, "\r\x1b[2K  %s  Probing  %3d%%  %s", u.style("38;5;81", "◌"), pct, u.style("38;5;245", fmt.Sprintf("%d / %d", e.Completed, e.Total)))
	}
	if e.Type == "device" {
		fmt.Fprintf(u.Out, "\r\x1b[2K  %s  %-15s %s\n", u.style("38;5;158", "+"), e.Device.IP, u.style("38;5;245", "discovered"))
	}
}
func (u *UI) Clear() {
	if u.Color {
		fmt.Fprint(u.Out, "\r\x1b[2K")
	}
}
func fit(s string, n int) string {
	s = scanner.CleanText(s)
	r := []rune(s)
	if len(r) > n {
		if n < 2 {
			return ""
		}
		return string(r[:n-1]) + "…"
	}
	return s + strings.Repeat(" ", n-utf8.RuneCountInString(s))
}
func (u *UI) Report(r scanner.Report) {
	u.Clear()
	open := 0
	responsive := 0
	for _, d := range r.Devices {
		open += len(d.Ports)
		if live(d) {
			responsive++
		}
	}
	fmt.Fprintf(u.Out, "\n  %s  %s  %s\n\n", u.style("1;38;5;158", fmt.Sprintf("%d devices", len(r.Devices))), u.style("38;5;81", fmt.Sprintf("%d open ports", open)), u.style("38;5;245", fmt.Sprintf("%.2fs · %d addresses", float64(r.DurationMS)/1000, r.Probed)))
	if r.AddressMode == "discovered" {
		fmt.Fprintln(u.Out, "  IPv6 discovery · observed addresses on this interface")
		fmt.Fprintln(u.Out)
	}
	if len(r.Devices) == 0 {
		fmt.Fprintln(u.Out, "  No devices observed. Try a longer --timeout or check your interface.")
	}
	addressWidth := 17
	for _, d := range r.Devices {
		addressWidth = max(addressWidth, len(d.IP.String())+2)
	}
	wide := u.Width >= 100+addressWidth-17
	if wide {
		fmt.Fprintf(u.Out, "  %s\n", u.style("38;5;245", fit("IP ADDRESS", addressWidth)+fit("NAME / VENDOR", 31)+fit("MAC ADDRESS", 20)+"SERVICES"))
		fmt.Fprintln(u.Out, u.style("38;5;238", "  "+strings.Repeat("─", min(u.Width-4, 112))))
	}
	for _, d := range r.Devices {
		name := d.Vendor.Name
		if len(d.Names) > 0 {
			name = d.Names[0]
		}
		if d.Identity != nil {
			if d.Identity.Name != "" {
				name = d.Identity.Name
			} else if name == "" && d.Identity.Model != "" {
				name = d.Identity.Model
			}
		}
		if name == "" {
			if d.Vendor.Private {
				name = "Private / randomized MAC"
			} else {
				name = "Unknown device"
			}
		}
		mac := d.MAC
		if mac == "" {
			mac = "—"
		}
		var ports []string
		for _, p := range d.Ports {
			ports = append(ports, fmt.Sprintf("%d/%s", p.Number, p.Service))
		}
		services := strings.Join(ports, "  ")
		if services == "" {
			services = "—"
		}
		dot := u.style("38;5;158", "●")
		if !live(d) {
			dot = u.style("38;5;220", "○")
		}
		if wide {
			fmt.Fprintf(u.Out, "%s %s%s%s%s\n", dot, u.style("1", fit(d.IP.String(), addressWidth)), fit(name, 31), u.style("38;5;245", fit(mac, 20)), u.style("38;5;81", fit(services, max(12, u.Width-55-addressWidth))))
		} else {
			fmt.Fprintf(u.Out, "  %s %s\n", dot, u.style("1", d.IP.String()))
			fmt.Fprintf(u.Out, "    %s\n", fit(name, max(12, u.Width-6)))
			fmt.Fprintf(u.Out, "    %s\n", u.style("38;5;245", fit(mac+" · "+services, max(12, u.Width-6))))
		}
		if d.Identity != nil && d.Identity.Model != "" {
			label := d.Identity.Model
			if len(d.Identity.ModelNames) == 1 {
				label = d.Identity.ModelNames[0] + " · " + label
			} else if len(d.Identity.ModelNames) > 1 {
				label += fmt.Sprintf(" · %d possible models", len(d.Identity.ModelNames))
			}
			if d.Identity.Manufacturer != "" {
				label += " · " + d.Identity.Manufacturer
			}
			fmt.Fprintf(u.Out, "    %s\n", u.style("38;5;245", fit(label, max(12, u.Width-6))))
		}
	}
	fmt.Fprintf(u.Out, "\n  %s\n", u.style("38;5;245", fmt.Sprintf("● %d responsive   ○ %d cached neighbors", responsive, len(r.Devices)-responsive)))
	if r.ICMP != nil && (r.ICMP.Retries > 0 || r.ICMP.Failed > 0) {
		fmt.Fprintf(u.Out, "  ICMP · %d sent · %d retries · %d unsent\n", r.ICMP.Sent, r.ICMP.Retries, r.ICMP.Failed)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(u.Out, "  %s %s\n", u.style("38;5;220", "!"), scanner.CleanText(w))
	}
	if r.Cancelled {
		fmt.Fprintln(u.Out, "  Scan interrupted; partial results shown.")
	}
	fmt.Fprintln(u.Out)
}
func live(d scanner.Device) bool {
	for _, e := range d.Evidence {
		if e == "arp" || e == "icmp" || e == "tcp-open" || e == "tcp-refused" || e == "mdns" || e == "ssdp" || e == "local-interface" {
			return true
		}
	}
	return false
}

func (u *UI) Details(r scanner.Report) {
	for _, d := range r.Devices {
		fmt.Fprintf(u.Out, "  %s %s\n", u.style("38;5;81", "╭─"), u.style("1", d.IP.String()))
		field := func(label, value string) {
			if value != "" {
				fmt.Fprintf(u.Out, "  %s %s %s\n", u.style("38;5;238", "│"), u.style("38;5;245", fit(label, 12)), scanner.CleanText(value))
			}
		}
		field("Names", strings.Join(d.Names, ", "))
		field("MAC", d.MAC)
		field("Vendor", d.Vendor.Name)
		if d.Identity != nil {
			field("Reported name", d.Identity.Name)
			field("Maker", d.Identity.Manufacturer)
			field("Model", d.Identity.Model)
			for _, name := range d.Identity.ModelNames {
				label := "Catalog model"
				if len(d.Identity.ModelNames) > 1 {
					label = "Candidate"
				}
				field(label, name)
			}
			for _, c := range d.Identity.Claims {
				detail := c.Field + " = " + c.Value + " · " + c.Source + " [" + c.Key + "; " + c.Basis + "]"
				if c.Identifier != "" {
					detail += " · " + c.Identifier
				}
				if c.Catalog != "" {
					detail += " · " + c.Catalog
				}
				field("Source", detail)
			}
		}
		field("Type hint", d.Kind)
		if d.LatencyMS > 0 {
			field("Latency", fmt.Sprintf("%.2f ms", d.LatencyMS))
		}
		field("Evidence", strings.Join(d.Evidence, ", "))
		for _, p := range d.Ports {
			field("TCP open", fmt.Sprintf("%d · %s  %s", p.Number, p.Service, p.Banner))
		}
		for _, a := range d.Advertisements {
			field(strings.ToUpper(a.Protocol), a.Instance+" "+a.Service)
			keys := []string{}
			for k := range a.Properties {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				field(k, a.Properties[k])
			}
		}
		fmt.Fprintf(u.Out, "  %s\n\n", u.style("38;5;238", "╰─"))
	}
}
