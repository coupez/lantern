package scanner

import (
	"math/rand"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"testing"
)

// Independent map-based oracle: order, duplicates and port metadata must not
// change the observed-number sets, including for legacy/custom core reports.
func expectedPortChanges(before, after Report) ([]string, []string) {
	allowed := func(p uint16) bool {
		return before.Coverage == nil || after.Coverage == nil ||
			(slices.Contains(before.Coverage.TCPPorts, p) && slices.Contains(after.Coverage.TCPPorts, p))
	}
	values := func(r Report) []string {
		set := map[uint16]bool{}
		for _, p := range r.Devices[0].Ports {
			if allowed(p.Number) {
				set[p.Number] = true
			}
		}
		numbers := make([]int, 0, len(set))
		for p := range set {
			numbers = append(numbers, int(p))
		}
		slices.Sort(numbers)
		var out []string
		for _, p := range numbers {
			out = append(out, strconv.Itoa(p))
		}
		return out
	}
	return values(before), values(after)
}

func checkPortDiff(t *testing.T, before, after Report) {
	t.Helper()
	oldPorts, newPorts := slices.Clone(before.Devices[0].Ports), slices.Clone(after.Devices[0].Ports)
	wantA, wantB := expectedPortChanges(before, after)
	changes := Diff(before, after)
	var portChanges []Change
	for _, c := range changes {
		if c.Field == "ports" {
			portChanges = append(portChanges, c)
		}
	}
	if slices.Equal(wantA, wantB) {
		if len(portChanges) != 0 {
			t.Fatal("equal port sets produced a change", portChanges)
		}
	} else if len(portChanges) != 1 || !slices.Equal(portChanges[0].Before, wantA) || !slices.Equal(portChanges[0].After, wantB) {
		t.Fatalf("wrong port change: got %v, want %v -> %v", portChanges, wantA, wantB)
	}
	if !reflect.DeepEqual(before.Devices[0].Ports, oldPorts) || !reflect.DeepEqual(after.Devices[0].Ports, newPorts) {
		t.Fatal("comparison modified caller-owned observations")
	}
	// Returned change slices must also be independent of input observations.
	if len(portChanges) > 0 && len(portChanges[0].Before) > 0 {
		portChanges[0].Before[0] = "mutated"
		if !slices.Equal(changesByField(Diff(before, after))["ports"].Before, wantA) {
			t.Fatal("caller mutation escaped the returned change")
		}
	}
}

func TestDiffPortSetsAgainstOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	pool := []uint16{0, 1, 22, 63, 64, 65, 443, 1023, 1024, 65534, 65535}
	for i := 0; i < 256; i++ {
		report := func() Report {
			d := Device{IP: netip.MustParseAddr("192.0.2.1")}
			for j, n := 0, rng.Intn(40); j < n; j++ {
				d.Ports = append(d.Ports, Port{Number: pool[rng.Intn(len(pool))], Service: "old label", Banner: "old banner"})
			}
			r := Report{Devices: []Device{d}}
			if rng.Intn(3) != 0 {
				r.Coverage = &ScanCoverage{}
				for j, n := 0, rng.Intn(24); j < n; j++ {
					r.Coverage.TCPPorts = append(r.Coverage.TCPPorts, pool[rng.Intn(len(pool))])
				}
			}
			return r
		}
		before, after := report(), report()
		if i%4 == 0 {
			after.Devices[0].Ports = slices.Clone(before.Devices[0].Ports)
			if i%8 == 0 {
				slices.Reverse(after.Devices[0].Ports)
			}
		}
		for j := range after.Devices[0].Ports {
			after.Devices[0].Ports[j].Service = "new label"
			after.Devices[0].Ports[j].Banner = "new banner"
		}
		checkPortDiff(t, before, after)
	}
}

func TestDiffFullObservedPortSet(t *testing.T) {
	d := Device{IP: netip.MustParseAddr("192.0.2.1"), Ports: make([]Port, 65536)}
	for i := range d.Ports {
		d.Ports[i].Number = uint16(i)
	}
	before := Report{Devices: []Device{d}}
	next := d.Clone()
	slices.Reverse(next.Ports)
	next.Ports = append(next.Ports, Port{Number: 65535}, Port{Number: 0})
	after := Report{Devices: []Device{next}}
	checkPortDiff(t, before, after)
	// Remove the upper boundary everywhere, retaining reversed/duplicate input.
	after.Devices[0].Ports = slices.DeleteFunc(after.Devices[0].Ports, func(p Port) bool { return p.Number == 65535 })
	checkPortDiff(t, before, after)
}
