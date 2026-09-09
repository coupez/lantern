package evaluation

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/coupez/lantern/pkg/scanner"
)

func validBindings() Bindings {
	return Bindings{
		Schema: Schema, Dataset: "fixture-set", RunID: "run-1", Version: "test", Context: "lab", Source: "fixture",
		Addresses: map[string]string{"192.0.2.10": "printer-a", "fe80::10%en0": "printer-a", "192.0.2.11": "other"},
	}
}

func TestFromLanternExplicitBindingsAndPredictions(t *testing.T) {
	bindings := validBindings()
	report := scanner.Report{Schema: 1, DurationMS: 12, Warnings: []string{"fixture warning"}, Devices: []scanner.Device{
		{IP: netip.MustParseAddr("192.0.2.10"), Evidence: []string{"mdns"}, Kind: "printer", Identity: &scanner.Identity{Model: "PX-42", ModelNames: []string{"Laser 42", "Laser 42", "Printer family"}}},
		{IP: netip.MustParseAddr("fe80::10%en0"), Evidence: []string{"local-interface"}, Kind: "device", Identity: &scanner.Identity{Model: "PX-42", ModelNames: []string{"Printer family", "Laser 42"}}},
	}}
	run, err := FromLantern(report, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if run.System != "lantern" || run.DurationMS == nil || *run.DurationMS != 12 || len(run.Observations) != 2 || run.Observations[0].CaseID != "printer-a" || run.Observations[1].CaseID != "printer-a" {
		t.Fatal(run)
	}
	if !run.Observations[0].Responsive || !run.Observations[1].Responsive {
		t.Fatal(run.Observations)
	}
	want := map[string][]string{ReportedModel: {"PX-42"}, RetailModel: {"Laser 42", "Printer family"}, Kind: {"printer"}}
	if !reflect.DeepEqual(run.Observations[0].Predictions, want) {
		t.Fatalf("predictions = %#v, want %#v", run.Observations[0].Predictions, want)
	}
	if _, ok := run.Observations[1].Predictions[Kind]; ok {
		t.Fatal("generic scanner kind became a prediction", run.Observations[1])
	}
	report.Warnings[0] = "mutated"
	report.Devices[0].Identity.ModelNames[0] = "mutated"
	if run.Warnings[0] != "fixture warning" || run.Observations[0].Predictions[RetailModel][0] != "Laser 42" {
		t.Fatal("adapter retained caller-owned mutable data", run)
	}
}

func TestFromLanternUnmappedAndCachedOnly(t *testing.T) {
	bindings := validBindings()
	report := scanner.Report{Schema: 1, Devices: []scanner.Device{
		{IP: netip.MustParseAddr("192.0.2.10"), Evidence: []string{"neighbors"}, Kind: "router"},
		{IP: netip.MustParseAddr("192.0.2.99"), Evidence: []string{"mdns"}, Identity: &scanner.Identity{Model: "not-a-binding"}},
	}}
	run, err := FromLantern(report, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Observations) != 1 || run.Observations[0].Responsive || run.Observations[0].Predictions[Kind][0] != "router" || !reflect.DeepEqual(run.Unmapped, []string{"192.0.2.99"}) {
		t.Fatal(run)
	}
	if len(run.Observations) >= len(bindings.Addresses) {
		t.Fatal("unseen bindings invented observations", run)
	}
}

func TestFromLanternValidatesInputWithoutInference(t *testing.T) {
	bindings := validBindings()
	for name, mutate := range map[string]func(*Bindings){
		"bad schema":              func(b *Bindings) { b.Schema = 2 },
		"missing link-local zone": func(b *Bindings) { b.Addresses = map[string]string{"fe80::10": "case"} },
		"mapped IPv4":             func(b *Bindings) { b.Addresses = map[string]string{"::ffff:192.0.2.10": "case"} },
		"empty case":              func(b *Bindings) { b.Addresses = map[string]string{"192.0.2.10": ""} },
		"control case":            func(b *Bindings) { b.Addresses = map[string]string{"192.0.2.10": "case\nID"} },
	} {
		t.Run(name, func(t *testing.T) {
			b := bindings
			b.Addresses = mapsClone(bindings.Addresses)
			mutate(&b)
			if _, err := FromLantern(scanner.Report{Schema: 1}, b); err == nil {
				t.Fatal("invalid bindings accepted")
			}
		})
	}
	for name, report := range map[string]scanner.Report{
		"schema":              {Schema: 2},
		"negative duration":   {Schema: 1, DurationMS: -1},
		"mapped device":       {Schema: 1, Devices: []scanner.Device{{IP: netip.MustParseAddr("::ffff:192.0.2.10")}}},
		"unscoped link local": {Schema: 1, Devices: []scanner.Device{{IP: netip.MustParseAddr("fe80::10")}}},
		"duplicate device":    {Schema: 1, Devices: []scanner.Device{{IP: netip.MustParseAddr("192.0.2.10")}, {IP: netip.MustParseAddr("192.0.2.10")}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := FromLantern(report, bindings); err == nil {
				t.Fatal("invalid report accepted")
			}
		})
	}
}

func TestFromLanternBoundsUntrustedLists(t *testing.T) {
	bindings := validBindings()
	warnings := make([]string, maxAdapterWarnings+1)
	if _, err := FromLantern(scanner.Report{Schema: 1, Warnings: warnings}, bindings); err == nil {
		t.Fatal("oversized warning list accepted")
	}
	candidates := make([]string, maxAdapterCandidates+1)
	if _, err := FromLantern(scanner.Report{Schema: 1, Devices: []scanner.Device{{IP: netip.MustParseAddr("192.0.2.10"), Identity: &scanner.Identity{ModelNames: candidates}}}}, bindings); err == nil {
		t.Fatal("oversized model candidate list accepted")
	}
}

func TestFromLanternBindingAddressClasses(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "169.254.10.1", "2001:db8::10%en0"} {
		t.Run("accept "+address, func(t *testing.T) {
			bindings := validBindings()
			bindings.Addresses = map[string]string{address: "case"}
			if _, err := FromLantern(scanner.Report{Schema: 1}, bindings); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, address := range []string{"fe80::10%bad\nzone", "::%en0", "255.255.255.255"} {
		t.Run("reject "+address, func(t *testing.T) {
			bindings := validBindings()
			bindings.Addresses = map[string]string{address: "case"}
			if _, err := FromLantern(scanner.Report{Schema: 1}, bindings); err == nil {
				t.Fatal("invalid absent binding accepted")
			}
		})
	}
}

func TestFromLanternCompletenessWarnings(t *testing.T) {
	bindings := validBindings()
	report := scanner.Report{Schema: 1, Cancelled: true, Error: "socket failed", IncompleteMethods: []string{"multicast", "tcp"}}
	run, err := FromLantern(report, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if !run.Incomplete || !reflect.DeepEqual(run.Warnings, []string{"Lantern scan cancelled", "Lantern scan error: socket failed", "Lantern incomplete method: multicast", "Lantern incomplete method: tcp"}) {
		t.Fatal(run)
	}
}

func TestFromLanternRejectsPartialBindingMetadata(t *testing.T) {
	bindings := validBindings()
	bindings.Context = ""
	if _, err := FromLantern(scanner.Report{Schema: 1}, bindings); err == nil {
		t.Fatal("partial binding metadata accepted")
	}
}

func mapsClone(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
