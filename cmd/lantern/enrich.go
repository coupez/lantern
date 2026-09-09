package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/coupez/lantern/internal/ui"
	"github.com/coupez/lantern/pkg/android"
	"github.com/coupez/lantern/pkg/inventory"
	"github.com/coupez/lantern/pkg/scanner"
	"github.com/coupez/lantern/pkg/snmp"
)

type inventoryManifest struct {
	Schema   int                        `json:"schema"`
	Bindings []inventoryManifestBinding `json:"bindings"`
}
type inventoryManifestBinding struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Path       string   `json:"path"`
	ObservedAt string   `json:"observed_at,omitempty"`
	Addresses  []string `json:"addresses"`
}

// enrichCommand only reads saved files. Address bindings are explicit owner
// assertions; neither source hashes nor report metadata authenticate hardware.
func enrichCommand(args []string, out io.Writer) error {
	f := flag.NewFlagSet("enrich", flag.ContinueOnError)
	f.SetOutput(out)
	scanPath := f.String("scan", "", "existing saved network snapshot")
	manifestPath := f.String("inventory", "", "explicit inventory binding manifest")
	savePath := f.String("save", "", "atomically save enriched snapshot")
	asJSON := f.Bool("json", false, "print enriched snapshot as JSON")
	details := f.Bool("details", false, "show all inventory claims and provenance")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 || *scanPath == "" || *manifestPath == "" {
		return errors.New("usage: lantern enrich --scan FILE --inventory MANIFEST [--save FILE] [--json] [--details]")
	}
	var report scanner.Report
	if _, err := readBoundedJSON(*scanPath, &report, true, maxEvaluationJSON); err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	if err := scanner.ValidateSnapshot(report); err != nil {
		return err
	}
	var manifest inventoryManifest
	digest, err := readBoundedJSON(*manifestPath, &manifest, true, 1<<20)
	if err != nil {
		return fmt.Errorf("inventory manifest: %w", err)
	}
	if manifest.Schema != 1 || len(manifest.Bindings) == 0 || len(manifest.Bindings) > 128 {
		return errors.New("inventory manifest requires schema 1 and 1..128 bindings")
	}
	bindings := make([]inventory.Binding, 0, len(manifest.Bindings))
	for i, entry := range manifest.Bindings {
		if entry.Path == "" {
			return fmt.Errorf("inventory binding %d has no source path", i+1)
		}
		path := entry.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(*manifestPath), path)
		}
		meta := inventory.Meta{ID: entry.ID, BindingSHA256: digest, ObservedAt: entry.ObservedAt}
		var observation scanner.InventoryObservation
		switch entry.Kind {
		case "android":
			var source struct {
				android.Report
				Error string `json:"error,omitempty"`
			}
			meta.SourceSHA256, err = readBoundedJSON(path, &source, true, 1<<20)
			if err == nil && source.Error != "" && source.Complete {
				err = errors.New("complete Android report contains an error")
			}
			if err == nil {
				observation, err = inventory.FromAndroid(meta, source.Report)
			}
		case "snmp":
			var source struct {
				Schema   int    `json:"schema"`
				Protocol string `json:"protocol"`
				snmp.Report
				Error string `json:"error,omitempty"`
			}
			meta.SourceSHA256, err = readBoundedJSON(path, &source, true, 1<<20)
			if err == nil && (source.Schema != 1 || source.Protocol != "snmpv2c" || source.Error != "" && source.EntityStatus != "failed") {
				err = errors.New("inconsistent SNMP report envelope")
			}
			if err == nil {
				observation, err = inventory.FromSNMP(meta, source.Report)
			}
		default:
			err = errors.New("inventory kind must be android or snmp")
		}
		if err != nil {
			return fmt.Errorf("inventory binding %d: %w", i+1, err)
		}
		bindings = append(bindings, inventory.Binding{Observation: observation, Addresses: entry.Addresses})
	}
	result, err := inventory.Apply(report, bindings)
	if err != nil {
		return err
	}
	if *savePath != "" {
		if err := scanner.Save(*savePath, result); err != nil {
			return err
		}
	}
	if *asJSON {
		e := json.NewEncoder(out)
		e.SetIndent("", "  ")
		return e.Encode(result)
	}
	var rendered bytes.Buffer
	u := &ui.UI{Out: &rendered, Width: 100}
	u.Report(result)
	if *details {
		u.Details(result)
	}
	_, err = out.Write(rendered.Bytes())
	return err
}
