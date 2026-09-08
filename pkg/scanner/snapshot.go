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
	for i, device := range r.Devices {
		ip := device.IP
		if !ip.IsValid() || ip.Is4In6() || ip.WithZone("").IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("snapshot device %d has an invalid native unicast IP %q", i+1, ip.String())
		}
		if previous, exists := seen[ip]; exists {
			return fmt.Errorf("snapshot device %d repeats IP %q from device %d", i+1, ip.String(), previous)
		}
		seen[ip] = i + 1
	}
	return nil
}
