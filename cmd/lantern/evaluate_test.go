package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/coupez/lantern/pkg/evaluation"
)

func TestEvaluationJSONFraming(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate":        `{"schema":1,"schema":2}`,
		"folded-duplicate": `{"schema":1,"Schema":2}`,
		"nested-duplicate": `{"truth":{"kind":1,"kind":2}}`,
		"trailing":         `{} {}`,
		"invalid-utf8":     "{\"id\":\"\xff\"}",
		"depth":            strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66),
		"unknown":          `{"schema":1,"unexpected":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			var target any
			if name == "unknown" {
				target = &evaluation.Truth{}
			}
			if _, err := readEvaluationJSON(p, &target, true); err == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
}
func TestEvaluationRegularFileAndLimit(t *testing.T) {
	d := t.TempDir()
	fifo := filepath.Join(d, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	var value any
	if _, err := readEvaluationJSON(fifo, &value, true); err == nil {
		t.Fatal("accepted FIFO")
	}
	p := filepath.Join(d, "large.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(maxEvaluationJSON + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := readEvaluationJSON(p, &value, true); err == nil {
		t.Fatal("accepted oversize file")
	}
}

type evaluationFailWriter struct{}

func (evaluationFailWriter) Write([]byte) (int, error) { return 0, errors.New("sink closed") }
func TestEvaluationOutputAndWriterFailure(t *testing.T) {
	args := []string{"--truth", "../../examples/identification/truth.json", "--run", "../../examples/identification/normalized-run.json"}
	for _, jsonMode := range []bool{false, true} {
		a := append([]string{}, args...)
		if jsonMode {
			a = append(a, "--json")
		}
		if err := evaluateCommand(a, evaluationFailWriter{}); err == nil || !strings.Contains(err.Error(), "sink closed") {
			t.Fatal(err)
		}
	}
	var b bytes.Buffer
	if err := evaluateCommand(args, &b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "synthetic dataset") {
		t.Fatal(b.String())
	}
	if got := scorePercent(nil); got != "n/a" {
		t.Fatal(got)
	}
}
