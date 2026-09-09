// Package inventory attaches explicitly bound saved device observations to
// network snapshots without changing network identity or discovery evidence.
package inventory

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sort"

	"github.com/coupez/lantern/pkg/scanner"
)

// Binding declares which existing snapshot addresses an observation describes.
// Observation must be unbound; Apply sets BindingAddress on each independent copy.
type Binding struct {
	Observation scanner.InventoryObservation
	Addresses   []string
}

// Apply returns an independently mutable snapshot. Every declared address must
// already exist; no liveness, identity, counters or scan timestamps are changed.
// Reattaching the same ID and content is idempotent. A changed observation with
// an existing ID is rejected; use the original scan to replace an attachment.
func Apply(report scanner.Report, bindings []Binding) (scanner.Report, error) {
	if err := scanner.ValidateSnapshot(report); err != nil {
		return scanner.Report{}, err
	}
	if len(bindings) == 0 || len(bindings) > 128 {
		return scanner.Report{}, errors.New("inventory requires 1..128 bindings")
	}
	result := report
	result.Warnings = slices.Clone(report.Warnings)
	result.IncompleteMethods = slices.Clone(report.IncompleteMethods)
	result.Devices = make([]scanner.Device, len(report.Devices))
	if report.Coverage != nil {
		v := *report.Coverage
		v.TCPPorts = slices.Clone(v.TCPPorts)
		result.Coverage = &v
	}
	if report.ICMP != nil {
		v := *report.ICMP
		result.ICMP = &v
	}
	indices := map[netip.Addr]int{}
	for i, d := range report.Devices {
		indices[d.IP] = i
		result.Devices[i] = d.Clone()
	}
	ids := map[string]bool{}
	for _, binding := range bindings {
		observation := binding.Observation
		if observation.BindingAddress != "" || ids[observation.ID] || len(binding.Addresses) == 0 || len(binding.Addresses) > 32 {
			return scanner.Report{}, errors.New("invalid or repeated inventory binding")
		}
		ids[observation.ID] = true
		seen := map[netip.Addr]bool{}
		for _, address := range binding.Addresses {
			ip, err := netip.ParseAddr(address)
			if err != nil || ip.String() != address || seen[ip] {
				return scanner.Report{}, fmt.Errorf("invalid or repeated canonical inventory address %q", address)
			}
			seen[ip] = true
			i, exists := indices[ip]
			if !exists {
				return scanner.Report{}, fmt.Errorf("inventory address %q is absent from the snapshot", address)
			}
			bound := observation
			bound.BindingAddress = address
			bound.Claims = slices.Clone(observation.Claims)
			if err := scanner.ValidateInventoryObservation(bound); err != nil {
				return scanner.Report{}, err
			}
			duplicate := false
			for _, previous := range result.Devices[i].Inventory {
				if previous.ID == bound.ID {
					if !reflect.DeepEqual(previous, bound) {
						return scanner.Report{}, fmt.Errorf("inventory ID %q already has different content; apply changes to the original scan", bound.ID)
					}
					duplicate = true
				}
			}
			if !duplicate {
				result.Devices[i].Inventory = append(result.Devices[i].Inventory, bound)
			}
			sort.Slice(result.Devices[i].Inventory, func(a, b int) bool { return result.Devices[i].Inventory[a].ID < result.Devices[i].Inventory[b].ID })
		}
	}
	if err := scanner.ValidateSnapshot(result); err != nil {
		return scanner.Report{}, err
	}
	return result, nil
}
