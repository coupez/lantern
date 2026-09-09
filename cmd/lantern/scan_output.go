package main

import (
	"context"
	"errors"

	"github.com/coupez/lantern/pkg/scanner"
)

type scanOutput struct {
	Event  func(scanner.Event) error
	Save   func(scanner.Report) error
	Report func(scanner.Report) error
}

// scanWithOutput joins the scan before saving or publishing its aggregate.
// Scanner callbacks are serialized; the first output failure cancels work and
// suppresses further writes to that stream, while an independent save still runs.
func scanWithOutput(parent context.Context, scan func(context.Context, func(scanner.Event)) (scanner.Report, error), output scanOutput) (scanner.Report, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var outputErr error
	var emit func(scanner.Event)
	if output.Event != nil {
		emit = func(e scanner.Event) {
			if outputErr == nil {
				outputErr = output.Event(e)
				if outputErr != nil {
					cancel()
				}
			}
		}
	}
	report, scanErr := scan(ctx, emit)
	if scanErr != nil && report.Error == "" {
		// Invalid options or target setup: leave existing snapshots untouched.
		return report, errors.Join(scanErr, outputErr)
	}
	var saveErr, reportErr error
	if output.Save != nil {
		saveErr = output.Save(report)
	}
	if outputErr == nil && output.Report != nil {
		reportErr = output.Report(report)
	}
	return report, errors.Join(scanErr, outputErr, saveErr, reportErr)
}
