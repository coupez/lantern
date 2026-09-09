package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/coupez/lantern/internal/ui"
	"github.com/coupez/lantern/pkg/observe"
)

func observeCommand(args []string) error {
	f := flag.NewFlagSet("observe", flag.ContinueOnError)
	file := f.String("read", "", "read a PCAP/PCAPNG file without sending packets")
	jsonOutput := f.Bool("json", false, "write bounded observations and summary as JSON")
	jsonLines := f.Bool("jsonl", false, "stream observation events and final summary")
	limit := f.Int("limit", 5000, "maximum DHCP observations (1-100000)")
	noColor := f.Bool("no-color", false, "disable color")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *file == "" || f.NArg() != 0 || (*jsonOutput && *jsonLines) || *limit < 1 || *limit > 100000 {
		return errors.New("usage: lantern observe --read FILE [--json | --jsonl] [--limit 5000] [--no-color]")
	}
	// A FIFO must not block before the regular-file check can reject it.
	input, err := os.OpenFile(*file, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("capture input must be a regular file")
	}
	if info.Size() > 128*1024*1024 {
		return errors.New("capture file exceeds 128 MiB limit")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	output := ui.New(os.Stdout, *noColor)
	if !*jsonOutput && !*jsonLines {
		output.ObservationIntro(*file)
	}
	return writeObservations(ctx, input, os.Stdout, *jsonOutput, *jsonLines, *limit, func(o observe.Observation) { output.Observation(o) }, func(s observe.Summary) { output.ObservationSummary(s) })
}

// writeObservations streams by default; aggregate JSON has a separate 16 MiB
// retained-output bound. An interrupted/malformed capture preserves prior evidence.
func writeObservations(ctx context.Context, input io.Reader, out io.Writer, asJSON, asJSONL bool, limit int, onRow func(observe.Observation), onSummary func(observe.Summary)) error {
	if limit < 1 || limit > 100000 {
		return errors.New("invalid observation limit")
	}
	rows := []json.RawMessage{}
	retained, count := 0, 0
	writeFailed := false
	encoder := json.NewEncoder(out)
	summary, err := observe.Read(ctx, input, func(o observe.Observation) error {
		if count >= limit {
			return fmt.Errorf("observation limit reached (%d)", limit)
		}
		if asJSON {
			raw, e := json.Marshal(o)
			if e != nil {
				return e
			}
			if retained+len(raw) > 16*1024*1024 {
				return errors.New("JSON observation output exceeds 16 MiB; use --jsonl")
			}
			retained += len(raw)
			rows = append(rows, raw)
		} else if asJSONL {
			if e := encoder.Encode(struct {
				Type        string              `json:"type"`
				Observation observe.Observation `json:"observation"`
			}{"observation", o}); e != nil {
				writeFailed = true
				return e
			}
		} else if onRow != nil {
			onRow(o)
		}
		count++
		return nil
	})
	if writeFailed {
		return err
	}
	if asJSON {
		if e := encoder.Encode(struct {
			Summary      observe.Summary   `json:"summary"`
			Observations []json.RawMessage `json:"observations"`
		}{summary, rows}); e != nil {
			return e
		}
	} else if asJSONL {
		if e := encoder.Encode(struct {
			Type    string          `json:"type"`
			Summary observe.Summary `json:"summary"`
		}{"complete", summary}); e != nil {
			return e
		}
	} else if onSummary != nil {
		onSummary(summary)
	}
	return err
}
