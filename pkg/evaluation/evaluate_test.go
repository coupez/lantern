package evaluation

import (
	"reflect"
	"strings"
	"testing"
)

func label(v ...string) Label {
	return Label{Accepted: v, SourceKind: "settings", Source: "independent"}
}
func truth() Truth {
	return Truth{Schema: 1, ID: "set", Kind: "physical", Cases: []Case{
		{ID: "a", Class: "phone", States: []string{"awake", "private"}, Truth: map[string]Label{ReportedModel: label("Code1"), RetailModel: label("Phone One"), Kind: label("phone")}},
		{ID: "b", Class: "printer", States: []string{"quiet"}, Truth: map[string]Label{RetailModel: label("Printer")}},
		{ID: "c", Class: "phone", Truth: map[string]Label{}},
	}}
}
func run() Run {
	return Run{Schema: 1, ID: "run", Dataset: "set", System: "lantern", Version: "1", Context: "standard", Source: "report.json", Observations: []Observation{
		{ID: "v4", CaseID: "a", Addresses: []string{"192.0.2.1"}, Seen: true, Responsive: true, Predictions: map[string][]string{ReportedModel: {"Code1"}, RetailModel: {"Phone One"}, Kind: {"phone"}}},
		{ID: "v6", CaseID: "a", Addresses: []string{"fe80::1%en0"}, Seen: true, Predictions: map[string][]string{RetailModel: {"Wrong"}}},
		{ID: "blank", CaseID: "c", Seen: true},
	}, Unmapped: []string{"192.0.2.99"}}
}

func TestEvaluateUnionGroupsAndOwnership(t *testing.T) {
	r := run()
	d := int64(4)
	r.DurationMS = &d
	r.Warnings = []string{"partial"}
	got, e := Evaluate(truth(), r)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Cases) != 3 || got.Cases[0].ID != "a" || got.Cases[0].Outcomes[ReportedModel] != "correct" || got.Cases[0].Outcomes[RetailModel] != "ambiguous" || got.Cases[0].Records != 2 {
		t.Fatal(got.Cases)
	}
	if got.Cases[1].Outcomes[RetailModel] != "missed" || got.Cases[2].Outcomes[RetailModel] != "unlabeled" {
		t.Fatal(got.Cases)
	}
	if got.Overall.Cases != 3 || got.Overall.Observed != 2 || got.Overall.Responsive != 1 || got.Overall.Records != 3 || got.Overall.Fragmentation != 1 {
		t.Fatal(got.Overall)
	}
	s := got.Overall.Fields[RetailModel]
	if s.Labeled != 2 || s.Ambiguous != 1 || s.Missed != 1 || s.Precision == nil || *s.Precision != 0 || s.Recall == nil || *s.Recall != 0 {
		t.Fatal(s)
	}
	if got.ByClass["phone"].Cases != 2 || got.ByState["private"].Cases != 1 {
		t.Fatal(got)
	}
	r.Warnings[0] = "changed"
	r.Unmapped[0] = "198.51.100.1"
	r.Observations[0].Predictions[ReportedModel][0] = "changed"
	*r.DurationMS = 9
	if got.Warnings[0] != "partial" || got.Unmapped[0] != "192.0.2.99" || got.Cases[0].Predictions[ReportedModel][0] != "Code1" || *got.DurationMS != 4 {
		t.Fatal("result aliases input")
	}
}

func TestExactBytesUnknownAndNilDenominators(t *testing.T) {
	tr := truth()
	r := run()
	r.Observations = []Observation{{ID: "x", CaseID: "a", Seen: true, Predictions: map[string][]string{ReportedModel: {"code1"}}}}
	g, e := Evaluate(tr, r)
	if e != nil || g.Cases[0].Outcomes[ReportedModel] != "incorrect" || g.Cases[0].Outcomes[RetailModel] != "unknown" {
		t.Fatal(g, e)
	}
	if g.Overall.Fields[ReportedModel].Precision == nil {
		t.Fatal("missing denominator")
	}
	empty := Truth{Schema: 1, ID: "e", Kind: "physical", Cases: []Case{{ID: "x", Class: "x", Truth: map[string]Label{}}}}
	er := Run{Schema: 1, ID: "r", Dataset: "e", System: "s", Version: "v", Context: "c", Source: "s"}
	x, _ := Evaluate(empty, er)
	if x.Overall.Fields[Kind].Precision != nil || x.Overall.Fields[Kind].Recall != nil {
		t.Fatal(x)
	}
}

func TestValidation(t *testing.T) {
	tr := truth()
	badTruth := []Truth{
		{Schema: 2, ID: "x", Kind: "physical"},
		{Schema: 1, ID: "   ", Kind: "physical"},
		{Schema: 1, ID: "x", Kind: "physical", Cases: []Case{{ID: "a", Class: "x", Truth: map[string]Label{"other": label("x")}}}},
		{Schema: 1, ID: "x", Kind: "physical", Cases: []Case{{ID: "a", Class: "x", Truth: map[string]Label{Kind: {Accepted: []string{"x"}, SourceKind: "synthetic", Source: "x"}}}}},
		{Schema: 1, ID: "x", Kind: "physical", Cases: []Case{{ID: "a", Class: "x", States: []string{"s", "s"}}}},
	}
	for _, x := range badTruth {
		if ValidateTruth(x) == nil {
			t.Fatal("accepted truth", x)
		}
	}
	neg := int64(-1)
	badRuns := []struct {
		name, want string
		mutate     func(*Run)
	}{
		{"schema", "metadata", func(x *Run) { x.Schema = 2 }},
		{"duration", "duration", func(x *Run) { x.DurationMS = &neg }},
		{"unseen output", "unseen", func(x *Run) { x.Observations[0].Seen = false }},
		{"mapped and unmapped address", "duplicate address", func(x *Run) { x.Unmapped = []string{"192.0.2.1"} }},
		{"duplicate mapped address", "duplicate address", func(x *Run) { x.Observations[1].Addresses = []string{"192.0.2.1"} }},
		{"duplicate prediction", "duplicate prediction", func(x *Run) { x.Observations[0].Predictions = map[string][]string{Kind: {"phone", "phone"}} }},
		{"replacement character", "prediction", func(x *Run) { x.Observations[0].Predictions = map[string][]string{Kind: {"bad�value"}} }},
		{"unspecified", "address", func(x *Run) { x.Observations[0].Addresses = []string{"0.0.0.0"} }},
		{"multicast", "address", func(x *Run) { x.Observations[0].Addresses = []string{"224.0.0.1"} }},
		{"v4 mapped", "address", func(x *Run) { x.Observations[0].Addresses = []string{"::ffff:192.0.2.1"} }},
		{"unscoped v6 link local", "address", func(x *Run) { x.Observations[0].Addresses = []string{"fe80::1"} }},
	}
	for _, tc := range badRuns {
		t.Run("run "+tc.name, func(t *testing.T) {
			x := run()
			if err := ValidateRun(x); err != nil {
				t.Fatalf("invalid baseline: %v", err)
			}
			tc.mutate(&x)
			if err := ValidateRun(x); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
	r := run()
	x := r
	x.Dataset = "other"
	if _, e := Evaluate(tr, x); e == nil {
		t.Fatal("dataset")
	}
	x = r
	x.Observations[0].CaseID = "missing"
	if _, e := Evaluate(tr, x); e == nil {
		t.Fatal("unknown case")
	}
}

func TestDeterminism(t *testing.T) {
	a, e := Evaluate(truth(), run())
	if e != nil {
		t.Fatal(e)
	}
	b, _ := Evaluate(truth(), run())
	if !reflect.DeepEqual(a, b) {
		t.Fatal("nondeterministic")
	}
}

func TestEmptyDataset(t *testing.T) {
	tr := Truth{Schema: 1, ID: "empty", Kind: "physical"}
	r := Run{Schema: 1, ID: "run", Dataset: "empty", System: "system", Version: "version", Context: "context", Source: "source"}
	got, err := Evaluate(tr, r)
	if err != nil || got.Overall.Cases != 0 || len(got.Overall.Fields) != 4 || got.Overall.ObservedRecall != nil {
		t.Fatal(got, err)
	}
}

func TestNativeScopedAddressValidation(t *testing.T) {
	base := Run{Schema: 1, ID: "run", Dataset: "set", System: "system", Version: "version", Context: "context", Source: "source"}
	for _, address := range []string{"127.0.0.1", "::1", "169.254.1.2", "192.0.2.1", "2001:db8::1", "2001:db8::1%en0", "fe80::1%en0"} {
		r := base
		r.Observations = []Observation{{ID: "observation", CaseID: "case", Addresses: []string{address}, Seen: true}}
		if err := ValidateRun(r); err != nil {
			t.Fatalf("rejected native address %q: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0", "::", "224.0.0.1", "ff02::1%en0", "::ffff:192.0.2.1", "fe80::1"} {
		r := base
		r.Observations = []Observation{{ID: "observation", CaseID: "case", Addresses: []string{address}, Seen: true}}
		if err := ValidateRun(r); err == nil {
			t.Fatalf("accepted invalid address %q", address)
		}
	}
}

func TestFamilyDoesNotBecomeExactModel(t *testing.T) {
	tr := truth()
	tr.Cases[0].Truth[Family] = label("Phone family")
	r := run()
	r.Observations = []Observation{{ID: "family-only", CaseID: "a", Seen: true, Responsive: true, Predictions: map[string][]string{Family: {"Phone family"}}}}
	got, err := Evaluate(tr, r)
	if err != nil {
		t.Fatal(err)
	}
	c := got.Cases[0]
	if c.Outcomes[Family] != "correct" || c.Outcomes[RetailModel] != "unknown" || c.Outcomes[ReportedModel] != "unknown" {
		t.Fatal(c)
	}
	if got.Overall.Fields[RetailModel].Precision != nil {
		t.Fatal("family counted as an exact assertion")
	}
}
