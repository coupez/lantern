package ui

import (
	"fmt"
	"github.com/coupez/lantern/pkg/scanner"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rivo/uniseg"
	"golang.org/x/term"
)

type UI struct {
	Out   io.Writer
	Color bool
	Width int
	last  time.Time
	phase string
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
	if (e.Type == "progress" || e.Type == "device_update") && (e.Phase != u.phase || time.Since(u.last) > 70*time.Millisecond) {
		u.last = time.Now()
		u.phase = e.Phase
		pct := 0
		if e.Total > 0 {
			pct = e.Completed * 100 / e.Total
		}
		label := "Probing"
		if e.Phase == "enrichment" {
			label = "Identifying"
		}
		fmt.Fprintf(u.Out, "\r\x1b[2K  %s  %s  %3d%%  %s", u.style("38;5;81", "◌"), label, pct, u.style("38;5;245", fmt.Sprintf("%d / %d", e.Completed, e.Total)))
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
	if n <= 0 {
		return ""
	}
	s = scanner.CleanText(s)
	if width := uniseg.StringWidth(s); width <= n {
		return s + strings.Repeat(" ", n-width)
	}
	var out strings.Builder
	used := 0
	g := uniseg.NewGraphemes(s)
	for g.Next() {
		if used+g.Width() > n-1 {
			break
		}
		out.WriteString(g.Str())
		used += g.Width()
	}
	return out.String() + "…" + strings.Repeat(" ", n-used-1)
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
	counts := []string{fmt.Sprintf("%d devices", len(r.Devices)), fmt.Sprintf("%d open ports", open), fmt.Sprintf("%.2fs · %d addresses", float64(r.DurationMS)/1000, r.Probed)}
	styles := []string{"1;38;5;158", "38;5;81", "38;5;245"}
	if uniseg.StringWidth("  "+strings.Join(counts, "  ")) > u.Width {
		fmt.Fprintln(u.Out)
		for i, count := range counts {
			fmt.Fprintf(u.Out, "  %s\n", u.style(styles[i], strings.TrimRight(fit(count, max(1, u.Width-2)), " ")))
		}
		fmt.Fprintln(u.Out)
	} else {
		fmt.Fprintf(u.Out, "\n  %s  %s  %s\n\n", u.style(styles[0], counts[0]), u.style(styles[1], counts[1]), u.style(styles[2], counts[2]))
	}
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
			} else if name == "" && d.Identity.Firmware != "" {
				name = d.Identity.Firmware
			}
		}
		if name == "" {
			name = inventoryModelLabel(d)
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
		if d.Identity != nil && d.Identity.Firmware != "" {
			label := strings.TrimSpace(d.Identity.Firmware + " " + d.Identity.FirmwareVersion)
			fmt.Fprintf(u.Out, "    %s\n", u.style("38;5;245", fit("Firmware · "+label, max(12, u.Width-6))))
		}
		for _, port := range d.Ports {
			if port.Fingerprint != nil {
				fmt.Fprintf(u.Out, "    %s\n", u.style("38;5;245", fit(fmt.Sprintf("Catalog · TCP %d · %s", port.Number, port.Fingerprint.Summary()), max(12, u.Width-6))))
			}
		}
		if role := d.Vendor.AddressRole; role != nil {
			fmt.Fprintf(u.Out, "    %s\n", u.style("38;5;245", fit(fmt.Sprintf("MAC range · %s · ID %d", role.Name, role.Identifier), max(12, u.Width-6))))
		}
		if d.Identity != nil && (d.Identity.Model != "" || len(d.Identity.ModelNames) > 0) {
			label := d.Identity.Model
			if label == "" && len(d.Identity.ModelNames) == 1 {
				label = "Catalog · " + d.Identity.ModelNames[0]
			} else if label == "" {
				label = fmt.Sprintf("Catalog · %d possible models", len(d.Identity.ModelNames))
			} else if len(d.Identity.ModelNames) == 1 {
				label = d.Identity.ModelNames[0] + " · " + label
			} else if len(d.Identity.ModelNames) > 1 {
				label += fmt.Sprintf(" · %d possible models", len(d.Identity.ModelNames))
			}
			if d.Identity.Manufacturer != "" {
				label += " · " + d.Identity.Manufacturer
			}
			fmt.Fprintf(u.Out, "    %s\n", u.style("38;5;245", fit(label, max(12, u.Width-6))))
		}
		if label := inventoryModelLabel(d); label != "" {
			fmt.Fprintf(u.Out, "    %s\n", u.style("38;5;245", fit(label, max(12, u.Width-6))))
		}
	}
	fmt.Fprintln(u.Out)
	for _, line := range wrapCells(fmt.Sprintf("● %d responsive   ○ %d cached neighbors", responsive, len(r.Devices)-responsive), max(1, u.Width-2)) {
		fmt.Fprintf(u.Out, "  %s\n", u.style("38;5;245", line))
	}
	if r.ICMP != nil && (r.ICMP.Retries > 0 || r.ICMP.Failed > 0) {
		fmt.Fprintf(u.Out, "  ICMP · %d sent · %d retries · %d unsent\n", r.ICMP.Sent, r.ICMP.Retries, r.ICMP.Failed)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(u.Out, "  %s %s\n", u.style("38;5;220", "!"), scanner.CleanText(w))
	}
	if r.Error != "" {
		fmt.Fprintln(u.Out, "  Scan failed; partial results shown:", scanner.CleanText(r.Error))
	}
	if r.Cancelled {
		fmt.Fprintln(u.Out, "  Scan interrupted; partial results shown.")
	}
	fmt.Fprintln(u.Out)
}
func live(d scanner.Device) bool { return d.Responsive() }

// inventoryModelLabel is deliberately a display-only fallback. Attached owner
// inventory remains separate from discovery identity and does not affect
// liveness, type hints, or selected network identity fields.
func inventoryModelLabel(d scanner.Device) string {
	models := d.InventoryModels()
	switch len(models) {
	case 0:
		return ""
	case 1:
		return "Inventory · " + models[0]
	default:
		return fmt.Sprintf("Inventory · %d reported models", len(models))
	}
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
		if role := d.Vendor.AddressRole; role != nil {
			field("MAC range", role.Name)
			field("Range ID", fmt.Sprint(role.Identifier))
			field("Prefix", role.Prefix)
			for _, reference := range role.References {
				field("Range source", reference)
			}
		}
		if d.Identity != nil {
			field("Reported name", d.Identity.Name)
			field("Maker", d.Identity.Manufacturer)
			field("Model", d.Identity.Model)
			field("Firmware", d.Identity.Firmware)
			field("FW version", d.Identity.FirmwareVersion)
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
				if c.Reference != "" {
					detail += " · " + c.Reference
				}
				field("Source", detail)
			}
		}
		for _, observation := range d.Inventory {
			field("Inv. kind", observation.Kind)
			field("Inv. ID", observation.ID)
			field("Observed at", observation.ObservedAt)
			field("Time basis", observation.TimeBasis)
			field("Inv. status", observation.Status)
			field("Inv. source", observation.Source)
			field("Source hash", observation.SourceSHA256)
			field("Binding hash", observation.BindingSHA256)
			field("Bind address", observation.BindingAddress)
			for _, claim := range observation.Claims {
				field("Inv. claim", claim.Field+" = "+claim.Value)
				field("Inv. key", claim.Key)
				field("Inv. ref", claim.Reference)
			}
		}
		field("Type hint", d.Kind)
		if d.LatencyMS > 0 {
			field("Latency", fmt.Sprintf("%.2f ms", d.LatencyMS))
		}
		field("Evidence", strings.Join(d.Evidence, ", "))
		for _, p := range d.Ports {
			field("TCP open", fmt.Sprintf("%d · %s  %s", p.Number, p.Service, p.Banner))
			if match := p.Fingerprint; match != nil {
				field("Catalog", match.Name)
				field("Match field", match.Field)
				field("Catalog src", match.Reference)
				field("Certainty", match.Certainty)
				field("Preference", match.Preference)
				keys := make([]string, 0, len(match.Fields))
				for key := range match.Fields {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					field("Catalog claim", key+" = "+match.Fields[key])
				}
			}
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
