package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Change struct {
	Type   string `json:"type"`
	IP     string `json:"ip"`
	Detail string `json:"detail,omitempty"`
}

func Diff(before, after Report) []Change {
	// Partial scans cannot establish that an earlier device disappeared.
	out := []Change{}
	old := map[string]Device{}
	now := map[string]Device{}
	for _, d := range before.Devices {
		old[d.IP.String()] = d
	}
	for _, d := range after.Devices {
		now[d.IP.String()] = d
		previous, ok := old[d.IP.String()]
		if !ok {
			out = append(out, Change{"added", d.IP.String(), d.MAC})
			continue
		}
		if previous.MAC != d.MAC {
			out = append(out, Change{"changed", d.IP.String(), "MAC: " + previous.MAC + " → " + d.MAC})
		}
		if portKey(previous) != portKey(d) {
			out = append(out, Change{"changed", d.IP.String(), "ports: " + portKey(previous) + " → " + portKey(d)})
		}
	}
	for _, d := range before.Devices {
		if _, ok := now[d.IP.String()]; !ok && !after.Cancelled {
			out = append(out, Change{"missing", d.IP.String(), d.MAC})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP == out[j].IP {
			return out[i].Detail < out[j].Detail
		}
		return out[i].IP < out[j].IP
	})
	return out
}
func portKey(d Device) string {
	p := make([]int, 0, len(d.Ports))
	for _, v := range d.Ports {
		p = append(p, int(v.Number))
	}
	sort.Ints(p)
	s := make([]string, len(p))
	for i, v := range p {
		s[i] = fmt.Sprint(v)
	}
	return strings.Join(s, ",")
}
func Save(path string, r Report) error {
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
func Load(path string) (Report, error) {
	var r Report
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if r.Schema != 1 {
		return r, fmt.Errorf("unsupported snapshot schema %d", r.Schema)
	}
	return r, nil
}
