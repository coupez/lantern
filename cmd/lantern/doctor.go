package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/coupez/lantern/pkg/models"
	"github.com/coupez/lantern/pkg/scanner"
	"github.com/coupez/lantern/pkg/vendors"
)

func doctorCommand(ctx context.Context, args []string, out io.Writer, inspect func(context.Context, string) (scanner.Diagnostics, error)) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(out)
	iface := fs.String("interface", "", "check discovery on this interface")
	asJSON := fs.Bool("json", false, "emit structured diagnostics")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: lantern doctor [--interface NAME] [--json]")
	}
	r, err := inspect(ctx, *iface)
	if err != nil && !r.Cancelled {
		return err
	}
	if *asJSON {
		payload := struct {
			scanner.Diagnostics
			Version           string `json:"version"`
			VendorAssignments int    `json:"vendor_assignments"`
			ModelIdentifiers  int    `json:"model_identifiers"`
		}{r, buildVersion(), vendors.Count(), models.Count()}
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if writeErr := encoder.Encode(payload); writeErr != nil {
			return writeErr
		}
	} else {
		if writeErr := printDiagnostics(out, r); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func printDiagnostics(out io.Writer, r scanner.Diagnostics) error {
	if _, err := fmt.Fprintf(out, "Lantern %s · %s/%s\nLocal checks only; no discovery packets sent.\nOffline data: %d MAC assignments · %d model identifiers\n\n", scanner.CleanText(buildVersion()), r.OS, r.Arch, vendors.Count(), models.Count()); err != nil {
		return err
	}
	for _, n := range r.Networks {
		if _, err := fmt.Fprintf(out, "Network  %-12s %s (%s)\n", scanner.CleanText(n.Interface), scanner.CleanText(n.CIDR), scanner.CleanText(n.Address)); err != nil {
			return err
		}
	}
	for _, check := range r.Checks {
		if _, err := fmt.Fprintf(out, "\n%-12s %-20s %s\n", scanner.CleanText(check.Status), scanner.CleanText(check.Name), scanner.CleanText(check.Detail)); err != nil {
			return err
		}
		if check.Hint != "" {
			if _, err := fmt.Fprintf(out, "             %s\n", scanner.CleanText(check.Hint)); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(out, "\nChecks completed in %d ms. An unavailable optional method does not prevent other discovery.\n", r.DurationMS)
	return err
}
