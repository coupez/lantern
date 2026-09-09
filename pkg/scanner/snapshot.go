package scanner

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

// Save atomically writes a schema-1 report. Invalid or repeated device addresses
// are rejected before touching the destination.
func Save(path string, r Report) error {
	if err := validateSnapshot(r); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".lantern-*.json")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Load reads a schema-1 report with valid, unique native device addresses.
// On failure it returns a zero Report; optional legacy metadata may be absent.
func Load(path string) (Report, error) {
	var r Report
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(b, &r); err != nil {
		return Report{}, fmt.Errorf("snapshot %q: %w", path, err)
	}
	if err := validateSnapshot(r); err != nil {
		return Report{}, fmt.Errorf("snapshot %q: %w", path, err)
	}
	return r, nil
}

func validateSnapshot(r Report) error {
	if r.Schema != 1 {
		return fmt.Errorf("unsupported snapshot schema %d", r.Schema)
	}
	seen := make(map[netip.Addr]int, len(r.Devices))
	inventoryCount, inventoryBytes := 0, 0
	for i, device := range r.Devices {
		ip := device.IP
		if !ip.IsValid() || ip.Is4In6() || ip.WithZone("").IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("snapshot device %d has an invalid native unicast IP %q", i+1, ip.String())
		}
		if previous, exists := seen[ip]; exists {
			return fmt.Errorf("snapshot device %d repeats IP %q from device %d", i+1, ip.String(), previous)
		}
		seen[ip] = i + 1
		if len(device.Inventory) > 8 {
			return fmt.Errorf("snapshot device %d has too many inventories", i+1)
		}
		ids := map[string]bool{}
		for _, observation := range device.Inventory {
			if err := ValidateInventoryObservation(observation); err != nil {
				return fmt.Errorf("snapshot device %d inventory: %w", i+1, err)
			}
			if observation.BindingAddress != ip.String() || ids[observation.ID] {
				return fmt.Errorf("snapshot device %d has a mismatched or repeated inventory binding", i+1)
			}
			ids[observation.ID] = true
			inventoryCount++
			for _, c := range observation.Claims {
				inventoryBytes += len(c.Value) + len(c.Key) + len(c.Reference)
			}
		}
		if inventoryCount > 2048 || inventoryBytes > 4<<20 {
			return fmt.Errorf("snapshot inventory exceeds aggregate limit")
		}
	}
	return nil
}

// ValidateSnapshot checks snapshot addresses and attached inventory invariants
// without filesystem access or network activity.
func ValidateSnapshot(r Report) error { return validateSnapshot(r) }
