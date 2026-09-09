package evaluation

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

var fields = []string{ReportedModel, RetailModel, Family, Kind}
var allowedSources = map[string]bool{"physical_label": true, "settings": true, "authorized_inventory": true, "purchase_record": true, "manufacturer_record": true, "manual_verification": true}

func validText(s string, max int) bool {
	if s == "" || strings.TrimSpace(s) == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == unicode.ReplacementChar || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func knownField(s string) bool {
	return s == ReportedModel || s == RetailModel || s == Family || s == Kind
}

// ValidateTruth validates an independent benchmark dataset without interpreting labels.
func ValidateTruth(t Truth) error {
	if t.Schema != Schema || !validText(t.ID, 256) || (t.Kind != "physical" && t.Kind != "synthetic") || len(t.Cases) > 10000 {
		return errors.New("invalid truth metadata")
	}
	ids := map[string]bool{}
	states := map[string]bool{}
	for _, c := range t.Cases {
		if !validText(c.ID, 256) || !validText(c.Class, 256) || ids[c.ID] {
			return errors.New("invalid or duplicate case ID/class")
		}
		ids[c.ID] = true
		local := map[string]bool{}
		for _, s := range c.States {
			if !validText(s, 256) || local[s] {
				return errors.New("invalid or duplicate case state")
			}
			local[s] = true
			states[s] = true
		}
		if len(states) > 32 {
			return errors.New("too many unique states")
		}
		for f, l := range c.Truth {
			if !knownField(f) || len(l.Accepted) == 0 || len(l.Accepted) > 64 || !validText(l.SourceKind, 256) || !validText(l.Source, 2048) {
				return errors.New("invalid truth label")
			}
			if l.SourceKind == "synthetic" {
				if t.Kind != "synthetic" {
					return errors.New("synthetic source on physical dataset")
				}
			} else if !allowedSources[l.SourceKind] {
				return errors.New("invalid truth source kind")
			}
			seen := map[string]bool{}
			for _, a := range l.Accepted {
				if !validText(a, 256) || seen[a] {
					return errors.New("invalid or duplicate truth alias")
				}
				seen[a] = true
			}
		}
	}
	return nil
}

// ValidateRun validates normalized recognizer output without joining it to truth.
func ValidateRun(r Run) error {
	if r.Schema != Schema || !validText(r.ID, 256) || !validText(r.Dataset, 256) || !validText(r.System, 256) || !validText(r.Version, 256) || !validText(r.Context, 2048) || !validText(r.Source, 2048) || len(r.Observations) > 10000 || len(r.Unmapped) > 10000 || len(r.Warnings) > 1024 {
		return errors.New("invalid run metadata")
	}
	if r.DurationMS != nil && *r.DurationMS < 0 {
		return errors.New("negative duration")
	}
	ids := map[string]bool{}
	addresses := map[string]bool{}
	addressCount := 0
	for _, o := range r.Observations {
		if !validText(o.ID, 256) || !validText(o.CaseID, 256) || ids[o.ID] || len(o.Addresses) > 32 {
			return errors.New("invalid or duplicate observation")
		}
		ids[o.ID] = true
		if !o.Seen && (o.Responsive || len(o.Predictions) > 0) {
			return errors.New("unseen observation has output")
		}
		for _, a := range o.Addresses {
			addressCount++
			if addressCount > 100000 {
				return errors.New("too many run addresses")
			}
			if err := addAddress(a, addresses); err != nil {
				return err
			}
		}
		for f, v := range o.Predictions {
			if !knownField(f) || len(v) > 64 {
				return errors.New("invalid prediction field")
			}
			seen := map[string]bool{}
			for _, x := range v {
				if !validText(x, 256) || seen[x] {
					return errors.New("invalid or duplicate prediction")
				}
				seen[x] = true
			}
		}
	}
	for _, a := range r.Unmapped {
		addressCount++
		if addressCount > 100000 {
			return errors.New("too many run addresses")
		}
		if err := addAddress(a, addresses); err != nil {
			return err
		}
	}
	for _, w := range r.Warnings {
		if !validText(w, 2048) {
			return errors.New("invalid warning")
		}
	}
	return nil
}
func addAddress(s string, seen map[string]bool) error {
	a, e := netip.ParseAddr(s)
	if e != nil || a.String() != s || !validBindingIP(a) || seen[s] {
		return errors.New("invalid, non-native, or duplicate address")
	}
	seen[s] = true
	return nil
}

// Evaluate validates and scores one normalized run against independent truth.
func Evaluate(t Truth, r Run) (Result, error) {
	if err := ValidateTruth(t); err != nil {
		return Result{}, err
	}
	if err := ValidateRun(r); err != nil {
		return Result{}, err
	}
	if r.Dataset != t.ID {
		return Result{}, errors.New("run dataset mismatch")
	}
	caseByID := map[string]Case{}
	for _, c := range t.Cases {
		caseByID[c.ID] = c
	}
	obs := map[string][]Observation{}
	for _, o := range r.Observations {
		if _, ok := caseByID[o.CaseID]; !ok {
			return Result{}, fmt.Errorf("unknown case ID %q", o.CaseID)
		}
		obs[o.CaseID] = append(obs[o.CaseID], o)
	}
	res := Result{Schema: Schema, Dataset: t.ID, DatasetKind: t.Kind, RunID: r.ID, System: r.System, Version: r.Version, Context: r.Context, Source: r.Source, Incomplete: r.Incomplete, Warnings: append([]string(nil), r.Warnings...), Unmapped: append([]string(nil), r.Unmapped...), ByClass: map[string]Group{}, ByState: map[string]Group{}}
	if r.DurationMS != nil {
		v := *r.DurationMS
		res.DurationMS = &v
	}
	cases := append([]Case(nil), t.Cases...)
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	for _, c := range cases {
		cr := scoreCase(c, obs[c.ID])
		res.Cases = append(res.Cases, cr)
		addCase(&res.Overall, c, cr)
		g := res.ByClass[c.Class]
		addCase(&g, c, cr)
		res.ByClass[c.Class] = g
		for _, s := range c.States {
			g := res.ByState[s]
			addCase(&g, c, cr)
			res.ByState[s] = g
		}
	}
	finish(&res.Overall)
	for k, g := range res.ByClass {
		finish(&g)
		res.ByClass[k] = g
	}
	for k, g := range res.ByState {
		finish(&g)
		res.ByState[k] = g
	}
	return res, nil
}
func scoreCase(c Case, os []Observation) CaseResult {
	cr := CaseResult{ID: c.ID, Predictions: map[string][]string{}, Outcomes: map[string]string{}}
	sets := map[string]map[string]bool{}
	for _, f := range fields {
		sets[f] = map[string]bool{}
	}
	for _, o := range os {
		if !o.Seen {
			continue
		}
		cr.Observed = true
		cr.Records++
		cr.Responsive = cr.Responsive || o.Responsive
		for f, vs := range o.Predictions {
			for _, v := range vs {
				sets[f][v] = true
			}
		}
	}
	for _, f := range fields {
		for v := range sets[f] {
			cr.Predictions[f] = append(cr.Predictions[f], v)
		}
		sort.Strings(cr.Predictions[f])
		label, ok := c.Truth[f]
		if !ok {
			cr.Outcomes[f] = "unlabeled"
			continue
		}
		if !cr.Observed {
			cr.Outcomes[f] = "missed"
			continue
		}
		if len(sets[f]) == 0 {
			cr.Outcomes[f] = "unknown"
			continue
		}
		accepted := map[string]bool{}
		for _, v := range label.Accepted {
			accepted[v] = true
		}
		inside := 0
		for v := range sets[f] {
			if accepted[v] {
				inside++
			}
		}
		if inside == len(sets[f]) {
			cr.Outcomes[f] = "correct"
		} else if inside > 0 {
			cr.Outcomes[f] = "ambiguous"
		} else {
			cr.Outcomes[f] = "incorrect"
		}
	}
	return cr
}
func addCase(g *Group, c Case, cr CaseResult) {
	if g.Fields == nil {
		g.Fields = map[string]FieldScore{}
	}
	g.Cases++
	if cr.Observed {
		g.Observed++
	}
	if cr.Responsive {
		g.Responsive++
	}
	g.Records += cr.Records
	if cr.Records > 1 {
		g.Fragmentation += cr.Records - 1
	}
	for _, f := range fields {
		s := g.Fields[f]
		switch cr.Outcomes[f] {
		case "unlabeled":
			s.Unlabeled++
		case "missed":
			s.Labeled++
			s.Missed++
		case "unknown":
			s.Labeled++
			s.Unknown++
		case "correct":
			s.Labeled++
			s.Correct++
		case "ambiguous":
			s.Labeled++
			s.Ambiguous++
		case "incorrect":
			s.Labeled++
			s.Incorrect++
		}
		g.Fields[f] = s
	}
}
func ratio(n, d int) *float64 {
	if d == 0 {
		return nil
	}
	v := float64(n) / float64(d)
	return &v
}
func finish(g *Group) {
	if g.Fields == nil {
		g.Fields = map[string]FieldScore{}
	}
	g.ObservedRecall = ratio(g.Observed, g.Cases)
	g.ResponsiveRecall = ratio(g.Responsive, g.Cases)
	for _, f := range fields {
		s := g.Fields[f]
		s.Precision = ratio(s.Correct, s.Correct+s.Ambiguous+s.Incorrect)
		s.Recall = ratio(s.Correct, s.Labeled)
		g.Fields[f] = s
	}
}
