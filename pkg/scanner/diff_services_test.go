package scanner

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/coupez/lantern/pkg/fingerprints"
)

func serviceDiffReport(input string) Report {
	return Report{Target: "192.0.2.0/24", Interface: "test0", Coverage: &ScanCoverage{Banners: true, TCPPorts: []uint16{80}}, Devices: []Device{{IP: netip.MustParseAddr("192.0.2.1"), Ports: []Port{{Number: 80, Service: "http", Fingerprint: fingerprints.Lookup(fingerprints.HTTPServer, input)}}}}}
}
func onlyServiceChanges(changes []Change) []Change {
	var result []Change
	for _, change := range changes {
		if change.Port != 0 {
			result = append(result, change)
		}
	}
	return result
}
func TestDiffServiceVersionAndOwnership(t *testing.T) {
	before, after := serviceDiffReport("Apache/2.4.64"), serviceDiffReport("Apache/2.4.65")
	changes := Diff(before, after)
	if len(changes) != 1 {
		t.Fatal(changes)
	}
	change := changes[0]
	if change.Port != 80 || change.Field != "service.version" || change.Type != "changed" || change.IP != "192.0.2.1" || !reflect.DeepEqual(change.Before, []string{"2.4.64"}) || !reflect.DeepEqual(change.After, []string{"2.4.65"}) || !strings.Contains(change.Detail, "TCP 80 catalog version") {
		t.Fatal(change)
	}
	raw, err := json.Marshal(changes)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []Change
	if err = json.Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(changes, decoded) {
		t.Fatal(string(raw), err)
	}
	changes[0].Before[0] = "caller mutation"
	changes[0].After[0] = "caller mutation"
	if before.Devices[0].Ports[0].Fingerprint.Fields["service.version"] != "2.4.64" || after.Devices[0].Ports[0].Fingerprint.Fields["service.version"] != "2.4.65" {
		t.Fatal("shared observation state")
	}
}
func TestDiffServiceComparability(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*Report, *Report)
	}{
		{"legacy coverage", func(a, b *Report) { a.Coverage = nil }},
		{"disabled before", func(a, b *Report) { a.Coverage.Banners = false }},
		{"disabled after", func(a, b *Report) { b.Coverage.Banners = false }},
		{"cancelled before", func(a, b *Report) { a.Cancelled = true }},
		{"cancelled after", func(a, b *Report) { b.Cancelled = true }},
		{"failed before", func(a, b *Report) { a.Error = "partial" }},
		{"failed after", func(a, b *Report) { b.Error = "partial" }},
		{"incomplete TCP", func(a, b *Report) { b.IncompleteMethods = []string{"tcp"} }},
		{"unknown incomplete method", func(a, b *Report) { b.IncompleteMethods = []string{"future"} }},
		{"different interface", func(a, b *Report) { b.Interface = "test1" }},
		{"unrequested", func(a, b *Report) { b.Coverage.TCPPorts = []uint16{443} }},
		{"timeout", func(a, b *Report) { b.Devices[0].Ports[0].Fingerprint = nil }},
		{"new recognition", func(a, b *Report) { a.Devices[0].Ports[0].Fingerprint = nil }},
		{"missing port", func(a, b *Report) { b.Devices[0].Ports = nil }},
		{"different field", func(a, b *Report) { b.Devices[0].Ports[0].Fingerprint.Field = fingerprints.FTPBanner }},
		{"different catalog", func(a, b *Report) { b.Devices[0].Ports[0].Fingerprint.Catalog = "New" }},
		{"different source revision", func(a, b *Report) { b.Devices[0].Ports[0].Fingerprint.Reference = "https://example.com/new.xml#L1" }},
		{"missing source", func(a, b *Report) { a.Devices[0].Ports[0].Fingerprint.Reference = "" }},
		{"missing field", func(a, b *Report) { a.Devices[0].Ports[0].Fingerprint.Field = "" }},
		{"missing input", func(a, b *Report) { a.Devices[0].Ports[0].Fingerprint.Input = "" }},
		{"same input new interpretation", func(a, b *Report) { b.Devices[0].Ports[0].Fingerprint.Input = a.Devices[0].Ports[0].Fingerprint.Input }},
		{"duplicate both aligned rows", func(a, b *Report) {
			a.Devices[0].Ports = append(a.Devices[0].Ports, Port{Number: 80})
			b.Devices[0].Ports = append(b.Devices[0].Ports, Port{Number: 80})
		}},
		{"duplicate before", func(a, b *Report) { a.Devices[0].Ports = append([]Port{{Number: 80}}, a.Devices[0].Ports...) }},
		{"duplicate after", func(a, b *Report) { b.Devices[0].Ports = append(b.Devices[0].Ports, b.Devices[0].Ports[0]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := serviceDiffReport("Apache/2.4.64"), serviceDiffReport("Apache/2.4.65")
			tc.alter(&a, &b)
			if got := onlyServiceChanges(Diff(a, b)); len(got) != 0 {
				t.Fatal(got)
			}
		})
	}
}
func TestDiffIgnoresVolatileAndDerivedFingerprintValues(t *testing.T) {
	a, b := serviceDiffReport("Apache/2.4.65"), serviceDiffReport("Apache/2.4.65 (build 12345)")
	if b.Devices[0].Ports[0].Fingerprint == nil {
		t.Fatal("fixture did not match")
	}
	match := b.Devices[0].Ports[0].Fingerprint
	match.Certainty = "0.5"
	match.Preference = "0.5"
	match.Name = "new description"
	for _, key := range []string{"host.name", "host.ip", "host.mac", "service.cpe23", "service.certainty", "os.version", "hw.product"} {
		match.Fields[key] = "changed"
	}
	if got := Diff(a, b); len(got) != 0 {
		t.Fatal(got)
	}
}
func TestDiffServiceRuleChangesAndNumericPorts(t *testing.T) {
	a, b := serviceDiffReport("Apache/2.4.64"), serviceDiffReport("nginx/1.27.0")
	if len(onlyServiceChanges(Diff(a, b))) == 0 {
		t.Fatal("different rule in same source ignored")
	}
	a, b = serviceDiffReport("Apache/2.4.64"), serviceDiffReport("Apache/2.4.65")
	for _, r := range []*Report{&a, &b} {
		r.Coverage.TCPPorts = []uint16{1000, 99}
		p := r.Devices[0].Ports[0]
		p.Number = 1000
		q := p
		q.Number = 99
		q.Fingerprint = p.Fingerprint.Clone()
		r.Devices[0].Ports = []Port{p, q}
	}
	got := Diff(a, b)
	if len(got) != 2 || got[0].Port != 99 || got[1].Port != 1000 {
		t.Fatal(got)
	}
}
func TestDiffQualifiedVersionsAndSafeDetails(t *testing.T) {
	a, b := serviceDiffReport("Apache/2.4.64"), serviceDiffReport("Apache/2.4.65")
	old, new := a.Devices[0].Ports[0].Fingerprint, b.Devices[0].Ports[0].Fingerprint
	old.Fields["service.component.version"] = "1.0"
	new.Fields["service.component.version"] = "2.0\n\x1b[2J"
	new.Fields["service.version.version.version"] = "candidate"
	new.Fields["service.version.certainty"] = "unmeasured"
	changes := onlyServiceChanges(Diff(a, b))
	if len(changes) != 3 {
		t.Fatal(changes)
	}
	for _, c := range changes {
		if strings.ContainsAny(c.Detail, "\n\x1b") {
			t.Fatal("unsafe detail", c)
		}
	}
}
