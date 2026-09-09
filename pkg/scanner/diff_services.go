package scanner

import (
	"strconv"
	"strings"

	"github.com/coupez/lantern/pkg/fingerprints"
)

// A successful field observation on both sides is required. Missing recognition
// can mean a timeout, unsupported banner, or newly added catalog coverage.
func appendServiceChanges(out []Change, address string, before, after *Device, common *portSet) []Change {
	// Normal scans retain sorted, unique port observations. Check alignment
	// first so no tentative events or large indexes are needed on that path.
	aligned := len(before.Ports) == len(after.Ports)
	if aligned {
		var previous uint16
		for i := range before.Ports {
			number := before.Ports[i].Number
			if number != after.Ports[i].Number || number <= previous {
				aligned = false
				break
			}
			previous = number
		}
		if aligned {
			for i := range before.Ports {
				p, q := &before.Ports[i], &after.Ports[i]
				if p.Fingerprint != nil && q.Fingerprint != nil && (common == nil || common[p.Number/64]&(uint64(1)<<(p.Number%64)) != 0) {
					out = appendServicePair(out, address, p.Number, p.Fingerprint, q.Fingerprint)
				}
			}
			return out
		}
	}

	type pair struct {
		before, after      *fingerprints.Match
		oldCount, newCount int
	}
	// Index only recognized ports, not every port in a deep/full-port scan.
	var pairs map[uint16]*pair
	for _, p := range before.Ports {
		if p.Number == 0 || p.Fingerprint == nil || common != nil && common[p.Number/64]&(uint64(1)<<(p.Number%64)) == 0 {
			continue
		}
		if pairs == nil {
			pairs = make(map[uint16]*pair)
		}
		if pairs[p.Number] == nil {
			pairs[p.Number] = &pair{before: p.Fingerprint}
		}
	}
	if len(pairs) == 0 {
		return out
	}
	// Duplicate observations are ambiguous, even when one lacks a fingerprint.
	for _, p := range before.Ports {
		if candidate := pairs[p.Number]; candidate != nil {
			candidate.oldCount++
		}
	}
	for _, p := range after.Ports {
		if candidate := pairs[p.Number]; candidate != nil {
			candidate.newCount++
			candidate.after = p.Fingerprint
		}
	}
	for port, candidate := range pairs {
		if candidate.oldCount == 1 && candidate.newCount == 1 {
			out = appendServicePair(out, address, port, candidate.before, candidate.after)
		}
	}
	return out
}

func appendServicePair(out []Change, address string, port uint16, a, b *fingerprints.Match) []Change {
	if a == nil || b == nil || a.Input == "" || b.Input == "" || a.Input == b.Input || a.Field == "" || a.Field != b.Field || a.Catalog == "" || a.Catalog != b.Catalog {
		return out
	}
	// Pinned Recog references include a source revision and a rule line. Different
	// rules in the same source may describe an upgrade; different sources cannot
	// establish that a label change came from the service rather than the catalog.
	oldSource, _, oldLine := strings.Cut(a.Reference, "#")
	newSource, _, newLine := strings.Cut(b.Reference, "#")
	if !oldLine || !newLine || oldSource == "" || oldSource != newSource {
		return out
	}
	add := func(key, left, right string) {
		if left == right || !serviceSoftwareField(key) {
			return
		}
		x, y := one(left), one(right)
		label := "TCP " + strconv.Itoa(int(port)) + " catalog " + strings.ReplaceAll(strings.TrimPrefix(key, "service."), ".", " ")
		out = append(out, Change{Type: "changed", IP: address, Port: port, Field: key, Before: x, After: y, Detail: label + ": " + displayValues(x) + " → " + displayValues(y)})
	}
	for key, value := range a.Fields {
		add(key, value, b.Fields[key])
	}
	for key, value := range b.Fields {
		if _, exists := a.Fields[key]; !exists {
			add(key, "", value)
		}
	}
	return out
}

func serviceSoftwareField(key string) bool {
	switch key {
	case "service.vendor", "service.family", "service.product", "service.edition", "service.version",
		"service.component.vendor", "service.component.family", "service.component.product", "service.component.version":
		return true
	}
	// Preserve Recog's qualified version scopes without treating CPE strings,
	// confidence annotations, hostnames, timestamps, or challenges as changes.
	if strings.HasPrefix(key, "service.version.") {
		key = strings.TrimPrefix(key, "service.version.")
		for strings.HasPrefix(key, "version.") {
			key = strings.TrimPrefix(key, "version.")
		}
		return key == "version"
	}
	return false
}
