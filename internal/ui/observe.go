package ui

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/coupez/lantern/pkg/observe"
	"github.com/coupez/lantern/pkg/scanner"
)

func (u *UI) ObservationIntro(path string) {
	u.Intro(scanner.CleanText(filepath.Base(path)), "offline DHCP evidence")
	fmt.Fprintln(u.Out, "  "+u.style("38;5;245", "Packet sources and client claims are separate; no current-device or model inference."))
}
func (u *UI) Observation(o observe.Observation) {
	label := fmt.Sprintf("DHCPv%d %s", o.Message.Version, observe.MessageName(o.Message.Version, o.Message.Type))
	stamp := "time unknown"
	if !o.Timestamp.IsZero() {
		stamp = o.Timestamp.UTC().Format("15:04:05.000Z")
	}
	width := max(16, u.Width-4)
	fmt.Fprintf(u.Out, "\n  %s\n", u.style("1;38;5;158", strings.TrimSpace(fit(fmt.Sprintf("#%d · %s · %s", o.Packet, stamp, label), width))))
	fields := []string{"Sender: " + o.SourceIP}
	fields = append(fields, fmt.Sprintf("Capture: section %d / interface %d · hop limit %d", o.Section, o.Interface, o.IPHopLimit))
	if len(o.VLANs) > 0 {
		fields = append(fields, fmt.Sprintf("VLANs: %v", o.VLANs))
	}
	if o.CapturedTruncated {
		fields = append(fields, "Capture record is truncated")
	}
	if o.Message.ClientHardwareAddress != "" {
		fields = append(fields, "Client claim: "+o.Message.ClientHardwareAddress)
	}
	if o.Message.Hints.Hostname != "" {
		fields = append(fields, "Hostname: "+o.Message.Hints.Hostname)
	}
	if o.Message.AssignedIP != "" {
		fields = append(fields, "Assigned address: "+o.Message.AssignedIP)
	}
	if o.Message.RelayIP != "" {
		fields = append(fields, "Relay address: "+o.Message.RelayIP)
	}
	if o.Message.Hints.EnterpriseID != nil {
		fields = append(fields, fmt.Sprintf("Vendor enterprise claim: %d", *o.Message.Hints.EnterpriseID))
	}
	if len(o.Message.Relays) > 0 {
		fields = append(fields, fmt.Sprintf("DHCPv6 relay layers: %d", len(o.Message.Relays)))
	}
	if o.Message.Hints.VendorClass != "" {
		fields = append(fields, "Vendor class: "+o.Message.Hints.VendorClass)
	}
	if len(o.Message.Hints.RequestedOptions) > 0 {
		values := make([]string, len(o.Message.Hints.RequestedOptions))
		for i, v := range o.Message.Hints.RequestedOptions {
			values[i] = strconv.Itoa(int(v))
		}
		fields = append(fields, "Requested options: "+strings.Join(values, ","))
	}
	for _, field := range fields {
		fmt.Fprintln(u.Out, "  "+strings.TrimSpace(fit(field, width)))
	}
}
func (u *UI) ObservationSummary(s observe.Summary) {
	fmt.Fprintf(u.Out, "\n  %s\n", u.style("38;5;81", fmt.Sprintf("%d DHCP observations · %d packets", s.Observations, s.Capture.Packets)))
	if s.Ignored > 0 || s.Unsupported > 0 || s.Malformed > 0 || s.Truncated > 0 {
		fmt.Fprintf(u.Out, "  %d other · %d unsupported · %d malformed · %d truncated\n", s.Ignored, s.Unsupported, s.Malformed, s.Truncated)
	}
	if s.Incomplete {
		fmt.Fprintln(u.Out, "  "+u.style("38;5;214", "Partial evidence; see counts or structured output for details."))
	}
}
