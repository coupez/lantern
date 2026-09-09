package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/coupez/lantern/pkg/evaluation"
	"github.com/coupez/lantern/pkg/scanner"
)

const maxEvaluationJSON = 16 << 20

type evaluationInput struct {
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
}
type evaluationOutput struct {
	Evaluation evaluation.Result `json:"evaluation"`
	Inputs     []evaluationInput `json:"inputs"`
}

func evaluateCommand(args []string, out io.Writer) error {
	f := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	truthPath := f.String("truth", "", "independently labeled device dataset")
	runPath := f.String("run", "", "normalized observations from any scanner")
	scanPath := f.String("scan", "", "saved Lantern schema-1 report")
	bindingsPath := f.String("bindings", "", "explicit scan-address to case-ID mapping")
	asJSON := f.Bool("json", false, "write scores, case outcomes and input hashes as JSON")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *truthPath == "" || ((*runPath == "") == (*scanPath == "")) || (*scanPath != "" && *bindingsPath == "") || (*runPath != "" && *bindingsPath != "") {
		return errors.New("usage: lantern evaluate --truth FILE (--run FILE | --scan FILE --bindings FILE) [--json]")
	}
	var truth evaluation.Truth
	var run evaluation.Run
	inputs := []evaluationInput{}
	load := func(role, path string, target any, strict bool) error {
		digest, err := readEvaluationJSON(path, target, strict)
		if err != nil {
			return fmt.Errorf("%s: %w", role, err)
		}
		inputs = append(inputs, evaluationInput{Role: role, SHA256: digest})
		return nil
	}
	if err := load("truth", *truthPath, &truth, true); err != nil {
		return err
	}
	if err := evaluation.ValidateTruth(truth); err != nil {
		return err
	}
	if *runPath != "" {
		if err := load("run", *runPath, &run, true); err != nil {
			return err
		}
	} else {
		var report scanner.Report
		var bindings evaluation.Bindings
		if err := load("scan", *scanPath, &report, false); err != nil {
			return err
		}
		if err := load("bindings", *bindingsPath, &bindings, true); err != nil {
			return err
		}
		// Validate the full mapping against the truth, including addresses absent from
		// the scan. A typo must not turn a known miss into an apparently unused row.
		cases := map[string]bool{}
		for _, c := range truth.Cases {
			cases[c.ID] = true
		}
		for _, id := range bindings.Addresses {
			if !cases[id] {
				return fmt.Errorf("binding refers to unknown case %q", id)
			}
		}
		var err error
		run, err = evaluation.FromLantern(report, bindings)
		if err != nil {
			return err
		}
	}
	result, err := evaluation.Evaluate(truth, run)
	if err != nil {
		return err
	}
	if *asJSON {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(evaluationOutput{Evaluation: result, Inputs: inputs})
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s · %s %s · %s dataset %s\n", result.RunID, result.System, result.Version, result.DatasetKind, result.Dataset)
	if result.Incomplete {
		fmt.Fprintln(&b, "Partial run: scores include missed and incomplete observations.")
	}
	g := result.Overall
	fmt.Fprintf(&b, "Observed %d/%d · responsive %d/%d · unmapped %d · extra mapped records %d\n", g.Observed, g.Cases, g.Responsive, g.Cases, len(result.Unmapped), g.Fragmentation)
	if result.DurationMS != nil {
		fmt.Fprintf(&b, "Scan duration: %d ms\n", *result.DurationMS)
	}
	fmt.Fprintln(&b, "Field             Correct Wrong Ambiguous Unknown Missed Unlabeled Precision Recall")
	for _, field := range []string{evaluation.ReportedModel, evaluation.RetailModel, evaluation.Family, evaluation.Kind} {
		s := g.Fields[field]
		fmt.Fprintf(&b, "%-17s %7d %5d %9d %7d %6d %9d %9s %6s\n", field, s.Correct, s.Incorrect, s.Ambiguous, s.Unknown, s.Missed, s.Unlabeled, scorePercent(s.Precision), scorePercent(s.Recall))
	}
	fmt.Fprintln(&b, "Use --json for case outcomes, class/state breakdowns and input hashes.")
	_, err = io.WriteString(out, b.String())
	return err
}
func scorePercent(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100**v)
}

// Read bounded regular files; reject duplicate keys before typed decoding can
// silently replace earlier labels, observations or mappings.
func readEvaluationJSON(path string, target any, strict bool) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("input must be a regular JSON file")
	}
	if info.Size() > maxEvaluationJSON {
		return "", errors.New("JSON exceeds 16 MiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxEvaluationJSON+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxEvaluationJSON {
		return "", errors.New("JSON exceeds 16 MiB")
	}
	if !utf8.Valid(b) {
		return "", errors.New("JSON must be valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	tokens := 0
	if err = validateEvaluationJSON(d, 0, &tokens); err != nil {
		return "", err
	}
	if _, err = d.Token(); err != io.EOF {
		return "", errors.New("expected exactly one JSON document")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	if strict {
		d.DisallowUnknownFields()
	}
	if err = d.Decode(target); err != nil {
		return "", err
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:]), nil
}
func validateEvaluationJSON(d *json.Decoder, depth int, tokens *int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64")
	}
	*tokens++
	if *tokens > 1000000 {
		return errors.New("JSON token limit exceeded")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			normalized := strings.ToLower(name)
			if seen[normalized] {
				return fmt.Errorf("duplicate JSON key %q", name)
			}
			seen[normalized] = true
			if err = validateEvaluationJSON(d, depth+1, tokens); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err = validateEvaluationJSON(d, depth+1, tokens); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}
