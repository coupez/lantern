package evaluation

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/coupez/lantern/pkg/scanner"
)

const maxAdapterRecords = 10000

const (
	maxAdapterWarnings          = 1024
	maxAdapterIncompleteMethods = 32
	maxAdapterCandidates        = 64
)

// FromLantern adapts scanner output into an evaluation run using only the
// caller-supplied address-to-case bindings. It never joins devices by names,
// MAC addresses, advertisements, or catalog candidates.
func FromLantern(report scanner.Report, bindings Bindings) (Run, error) {
	if err := validateBindings(bindings); err != nil {
		return Run{}, err
	}
	if report.Schema != Schema {
		return Run{}, fmt.Errorf("unsupported Lantern report schema %d", report.Schema)
	}
	if report.DurationMS < 0 {
		return Run{}, errors.New("Lantern report duration must not be negative")
	}
	if len(report.Devices) > maxAdapterRecords {
		return Run{}, fmt.Errorf("Lantern report has too many devices (%d)", len(report.Devices))
	}
	if len(report.Warnings) > maxAdapterWarnings {
		return Run{}, fmt.Errorf("Lantern report has too many warnings (%d)", len(report.Warnings))
	}
	if len(report.IncompleteMethods) > maxAdapterIncompleteMethods {
		return Run{}, fmt.Errorf("Lantern report has too many incomplete methods (%d)", len(report.IncompleteMethods))
	}

	bound := make(map[string]string, len(bindings.Addresses))
	for raw, caseID := range bindings.Addresses {
		ip, _ := netip.ParseAddr(raw) // validateBindings has already checked it.
		bound[ip.String()] = caseID
	}
	duration := report.DurationMS
	run := Run{
		Schema:     Schema,
		ID:         bindings.RunID,
		Dataset:    bindings.Dataset,
		System:     "lantern",
		Version:    bindings.Version,
		Context:    bindings.Context,
		Source:     bindings.Source,
		DurationMS: &duration,
		Warnings:   copyWarnings(report),
	}
	seen := make(map[netip.Addr]int, len(report.Devices))
	for i, device := range report.Devices {
		ip := device.IP
		if !validReportIP(ip) {
			return Run{}, fmt.Errorf("Lantern report device %d has an invalid native unicast IP %q", i+1, ip.String())
		}
		if previous, exists := seen[ip]; exists {
			return Run{}, fmt.Errorf("Lantern report device %d repeats IP %q from device %d", i+1, ip.String(), previous)
		}
		seen[ip] = i + 1
		if device.Identity != nil && len(device.Identity.ModelNames) > maxAdapterCandidates {
			return Run{}, fmt.Errorf("Lantern report device %d has too many model candidates (%d)", i+1, len(device.Identity.ModelNames))
		}
		caseID, mapped := bound[ip.String()]
		if !mapped {
			run.Unmapped = append(run.Unmapped, ip.String())
			continue
		}
		observation := Observation{
			ID:          ip.String(),
			CaseID:      caseID,
			Addresses:   []string{ip.String()},
			Seen:        true,
			Responsive:  device.Responsive(),
			Predictions: predictions(device),
		}
		run.Observations = append(run.Observations, observation)
	}
	sort.Strings(run.Unmapped)
	if report.Cancelled {
		run.Incomplete = true
		run.Warnings = append(run.Warnings, "Lantern scan cancelled")
	}
	if report.Error != "" {
		run.Incomplete = true
		run.Warnings = append(run.Warnings, "Lantern scan error: "+report.Error)
	}
	if len(report.IncompleteMethods) > 0 {
		run.Incomplete = true
		for _, method := range report.IncompleteMethods {
			run.Warnings = append(run.Warnings, "Lantern incomplete method: "+method)
		}
	}
	if err := ValidateRun(run); err != nil {
		return Run{}, err
	}
	return run, nil
}

func validateBindings(bindings Bindings) error {
	if bindings.Schema != Schema {
		return fmt.Errorf("unsupported bindings schema %d", bindings.Schema)
	}
	if len(bindings.Addresses) > maxAdapterRecords {
		return fmt.Errorf("too many address bindings (%d)", len(bindings.Addresses))
	}
	seen := make(map[netip.Addr]string, len(bindings.Addresses))
	for raw, caseID := range bindings.Addresses {
		ip, err := netip.ParseAddr(raw)
		if err != nil || raw != ip.String() || !validBindingIP(ip) {
			return fmt.Errorf("invalid canonical binding address %q", raw)
		}
		if !validText(caseID, 256) {
			return fmt.Errorf("binding address %q has an invalid case ID", raw)
		}
		if previous, exists := seen[ip]; exists {
			return fmt.Errorf("binding address %q repeats canonical IP %q", raw, previous)
		}
		seen[ip] = raw
	}
	return nil
}

func validNativeUnicastIP(ip netip.Addr) bool {
	base := ip.WithZone("")
	return base.IsValid() && !base.Is4In6() && (base.IsGlobalUnicast() || base.IsLinkLocalUnicast() || base.IsLoopback())
}

func validBindingIP(ip netip.Addr) bool {
	if !validNativeUnicastIP(ip) || !ip.Is6() {
		return validNativeUnicastIP(ip)
	}
	if ip.IsLinkLocalUnicast() {
		return validText(ip.Zone(), 256)
	}
	return ip.Zone() == "" || validText(ip.Zone(), 256)
}

func validReportIP(ip netip.Addr) bool { return validBindingIP(ip) }

func predictions(device scanner.Device) map[string][]string {
	out := make(map[string][]string, 3)
	if device.Identity != nil {
		if device.Identity.Model != "" {
			out[ReportedModel] = []string{device.Identity.Model}
		}
		if candidates := uniqueNonempty(device.Identity.ModelNames); len(candidates) > 0 {
			out[RetailModel] = candidates
		}
	}
	if kind := device.Kind; kind != "" && !genericKind(kind) {
		out[Kind] = []string{kind}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func uniqueNonempty(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func genericKind(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", "unknown", "device":
		return true
	default:
		return false
	}
}

func copyWarnings(report scanner.Report) []string {
	if len(report.Warnings) == 0 {
		return nil
	}
	return append([]string(nil), report.Warnings...)
}
