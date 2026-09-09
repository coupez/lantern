package evaluation

import (
	"fmt"
	"sort"

	"github.com/coupez/lantern/pkg/scanner"
)

// FromLanternWithInventory adapts a scan and its explicitly bound inventory
// claims. Inventory can add reported-model candidates to an already observed
// address, but it never creates observations or changes scan presence fields.
func FromLanternWithInventory(report scanner.Report, bindings Bindings) (Run, error) {
	if err := scanner.ValidateSnapshot(report); err != nil {
		return Run{}, fmt.Errorf("invalid Lantern snapshot: %w", err)
	}
	run, err := FromLantern(report, bindings)
	if err != nil {
		return Run{}, err
	}
	byAddress := make(map[string]int, len(run.Observations))
	for i := range run.Observations {
		byAddress[run.Observations[i].ID] = i
	}
	models := make([]map[string]bool, len(run.Observations))
	for i := range models {
		models[i] = make(map[string]bool)
		for _, value := range run.Observations[i].Predictions[ReportedModel] {
			models[i][value] = true
		}
	}
	for _, device := range report.Devices {
		address := device.IP.String()
		for _, observation := range device.Inventory {
			index, mapped := byAddress[address]
			if !mapped {
				continue
			}
			for _, claim := range observation.Claims {
				if claim.Field == "model" {
					models[index][claim.Value] = true
				}
			}
		}
	}
	for i, values := range models {
		if len(values) == 0 {
			continue
		}
		candidates := make([]string, 0, len(values))
		for value := range values {
			candidates = append(candidates, value)
		}
		sort.Strings(candidates)
		if len(candidates) > maxAdapterCandidates {
			return Run{}, fmt.Errorf("Lantern report device %q has too many reported model candidates (%d)", run.Observations[i].ID, len(candidates))
		}
		if run.Observations[i].Predictions == nil {
			run.Observations[i].Predictions = make(map[string][]string)
		}
		run.Observations[i].Predictions[ReportedModel] = candidates
	}
	run.System = "lantern+inventory"
	run.DurationMS = nil
	run.Warnings = append(run.Warnings, "Inventory-assisted model evaluation; scan duration excludes inventory collection")
	if err := ValidateRun(run); err != nil {
		return Run{}, err
	}
	return run, nil
}
