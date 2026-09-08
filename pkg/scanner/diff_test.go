package scanner

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func diffDevice(ip string) Device { return Device{IP: netip.MustParseAddr(ip)} }
func changesByField(changes []Change) map[string]Change {
	out := map[string]Change{}
	for _, c := range changes {
		out[c.Field] = c
	}
	return out
}
func TestDiffIdentitiesAndStructuredValues(t *testing.T) {
	old := diffDevice("192.0.2.1")
	old.Names = []string{"old.local"}
	old.Identity = &Identity{Name: "Old", Manufacturer: "Vendor A", Model: "Model1", ModelNames: []string{"Product A"}}
	now := old
	now.Names = []string{"new.local"}
	now.Identity = &Identity{Name: "New", Manufacturer: "Vendor B", Model: "Model2", ModelNames: []string{"Product B", "Product C"}}
	now.Advertisements = []Advertisement{{Protocol: "netbios", Service: "workgroup", Properties: map[string]string{"name": "LAB"}}}
	changes := Diff(Report{Devices: []Device{old}}, Report{Devices: []Device{now}})
	fields := changesByField(changes)
	for _, key := range []string{"names", "identity.name", "identity.manufacturer", "identity.model", "identity.model_names", "workgroups"} {
		if fields[key].Type != "changed" || fields[key].IP != old.IP.String() {
			t.Fatal(key, changes)
		}
	}
	if !reflect.DeepEqual(fields["identity.model_names"].Before, []string{"Product A"}) || !reflect.DeepEqual(fields["identity.model_names"].After, []string{"Product B", "Product C"}) {
		t.Fatal(fields)
	}
	raw, err := json.Marshal(changes)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []Change
	if err = json.Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(changes, decoded) {
		t.Fatal(string(raw), err)
	}
}
func TestDiffIgnoresOrderingAndVolatileObservations(t *testing.T) {
	old := diffDevice("192.0.2.1")
	old.MAC = "00:11:22:aa:bb:cc"
	old.Evidence = []string{"tcp-open"}
	old.Names = []string{"Printer.LOCAL.", "other.local"}
	old.Ports = []Port{{Number: 443}, {Number: 80}}
	old.Identity = &Identity{ModelNames: []string{"B", "A"}, Claims: []IdentityClaim{{Value: "A"}}}
	now := old
	now.MAC = "00-11-22-AA-BB-CC"
	now.Names = []string{"other.local", "printer.local", "printer.local."}
	now.Ports = []Port{{Number: 80, Banner: "new server banner"}, {Number: 443}, {Number: 80}}
	now.LatencyMS = 99
	now.Evidence = []string{"icmp"}
	now.Identity = &Identity{ModelNames: []string{"A", "B", "A"}, Claims: []IdentityClaim{{Value: "B"}}}
	changes := Diff(Report{Devices: []Device{old}}, Report{Devices: []Device{now}})
	if len(changes) != 0 {
		t.Fatal(changes)
	}
}
func TestDiffInterruptedScanCannotEraseObservedValues(t *testing.T) {
	old := diffDevice("192.0.2.1")
	old.MAC = "00:11:22:33:44:55"
	old.Names = []string{"nas"}
	old.Ports = []Port{{Number: 445}}
	old.Identity = &Identity{Model: "NAS1"}
	now := diffDevice("192.0.2.1")
	changes := Diff(Report{Devices: []Device{old, diffDevice("192.0.2.2")}}, Report{Cancelled: true, Devices: []Device{now, diffDevice("192.0.2.3")}})
	if len(changes) != 1 || changes[0].Type != "added" || changes[0].IP != "192.0.2.3" {
		t.Fatal(changes)
	}
}
func TestDiffComparesOnlyCommonRequestedPorts(t *testing.T) {
	before := Report{Coverage: &ScanCoverage{TCPPorts: []uint16{443, 80}}, Devices: []Device{{IP: netip.MustParseAddr("192.0.2.1"), Ports: []Port{{Number: 443}, {Number: 80}}}}}
	after := Report{Coverage: &ScanCoverage{TCPPorts: []uint16{80, 22}}, Devices: []Device{{IP: netip.MustParseAddr("192.0.2.1"), Ports: []Port{{Number: 22}}}}}
	changes := changesByField(Diff(before, after))
	if len(changes) != 2 || changes["coverage"].Type != "scan" || !reflect.DeepEqual(changes["ports"].Before, []string{"80"}) || len(changes["ports"].After) != 0 {
		t.Fatal(changes)
	}
	after.Coverage.TCPPorts = []uint16{22}
	if changes := Diff(before, after); len(changes) != 1 || changes[0].Type != "scan" {
		t.Fatal(changes)
	}
}
func TestDiffCoverageDoesNotManufactureMissingNamesOrDevices(t *testing.T) {
	d := diffDevice("192.0.2.1")
	d.Names = []string{"nas.local"}
	d.Identity = &Identity{Model: "NAS1"}
	d.Advertisements = []Advertisement{{Protocol: "netbios", Service: "workgroup", Properties: map[string]string{"name": "LAB"}}}
	before := Report{Coverage: &ScanCoverage{Multicast: true, NetBIOS: true}, Devices: []Device{d, diffDevice("192.0.2.2")}}
	after := Report{Coverage: &ScanCoverage{}, Devices: []Device{diffDevice("192.0.2.1"), diffDevice("192.0.2.3")}}
	changes := Diff(before, after)
	if len(changes) != 1 || changes[0].Field != "coverage" {
		t.Fatal(changes)
	}
}
func TestDiffScopeAndNumericOrder(t *testing.T) {
	before := Report{Target: "192.0.2.0/24", Interface: "en0", Devices: []Device{diffDevice("192.0.2.10")}}
	after := Report{Target: "198.51.100.0/24", Interface: "en1", Devices: []Device{diffDevice("198.51.100.2")}}
	changes := Diff(before, after)
	if len(changes) != 2 || changes[0].Field != "interface" || changes[1].Field != "target" {
		t.Fatal(changes)
	}
	before = Report{Target: "192.0.2.0/24"}
	after = Report{Target: "192.0.2.17/24", Devices: []Device{diffDevice("192.0.2.10"), diffDevice("192.0.2.2")}}
	changes = Diff(before, after)
	if len(changes) != 2 || changes[0].IP != "192.0.2.2" || changes[1].IP != "192.0.2.10" {
		t.Fatal(changes)
	}
}
func TestDiffLegacySnapshotsAndSafeDetail(t *testing.T) {
	old := diffDevice("fe80::1%en0")
	old.Identity = &Identity{Name: "Old"}
	now := old
	now.Identity = &Identity{Name: "New\n\x1b[2J"}
	changes := Diff(Report{Devices: []Device{old}}, Report{Coverage: &ScanCoverage{}, Devices: []Device{now}})
	field := changesByField(changes)["identity.name"]
	if len(changes) != 2 || strings.ContainsAny(field.Detail, "\n\x1b") || field.After[0] != now.Identity.Name {
		t.Fatal(changes)
	}
	// Scoped addresses on separate interfaces must remain distinct observations.
	now = diffDevice("fe80::1%en1")
	if changes := Diff(Report{Devices: []Device{old}}, Report{Devices: []Device{now}}); len(changes) != 2 {
		t.Fatal(changes)
	}
}
func TestCoverageIsPersistedAndDoesNotAliasOptions(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("192.0.2.1/32")
	o.ICMP = false
	o.Multicast = false
	o.Resolve = false
	o.Ports = []uint16{443, 80, 443}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := (Engine{NeighborSource: noNeighbors}).Scan(ctx, o, nil)
	if err != nil || r.Coverage == nil || !reflect.DeepEqual(r.Coverage.TCPPorts, []uint16{80, 443}) {
		t.Fatal(r, err)
	}
	o.Ports[0] = 22
	if !reflect.DeepEqual(r.Coverage.TCPPorts, []uint16{80, 443}) {
		t.Fatal("coverage aliases caller memory")
	}
	path := t.TempDir() + "/snapshot.json"
	if err = Save(path, r); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || !reflect.DeepEqual(loaded.Coverage, r.Coverage) {
		t.Fatal(loaded.Coverage, err)
	}
}

func BenchmarkDiffFullPortCoverage(b *testing.B) {
	coverage := &ScanCoverage{TCPPorts: make([]uint16, 65535)}
	for i := range coverage.TCPPorts {
		coverage.TCPPorts[i] = uint16(i + 1)
	}
	report := Report{Coverage: coverage}
	for i := 0; i < 1024; i++ {
		report.Devices = append(report.Devices, Device{IP: netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)}), Ports: []Port{{Number: 443}}, Names: []string{"host.local"}})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(Diff(report, report)) != 0 {
			b.Fatal("unexpected changes")
		}
	}
}

func TestDiffReportsResponseLossWithoutDeclaringOffline(t *testing.T) {
	old := diffDevice("192.0.2.1")
	old.Evidence = []string{"icmp", "neighbor-cache"}
	now := old
	now.Evidence = []string{"neighbor-cache"}
	changes := Diff(Report{Devices: []Device{old}}, Report{Devices: []Device{now}})
	if len(changes) != 1 || changes[0].Field != "reachability" || changes[0].After[0] != "cached only" || strings.Contains(changes[0].Detail, "offline") {
		t.Fatal(changes)
	}
	changes = Diff(Report{Coverage: &ScanCoverage{ICMP: true}, Devices: []Device{old}}, Report{Coverage: &ScanCoverage{}, Devices: []Device{now}})
	if len(changes) != 1 || changes[0].Type != "scan" {
		t.Fatal(changes)
	}
}
func TestDiffDoesNotMergeIPv4IdentitiesAcrossInterfaces(t *testing.T) {
	old := diffDevice("192.0.2.1")
	old.MAC = "00:11:22:33:44:55"
	now := old
	now.MAC = "00:aa:bb:cc:dd:ee"
	changes := Diff(Report{Interface: "en0", Devices: []Device{old}}, Report{Interface: "en1", Devices: []Device{now}})
	if len(changes) != 1 || changes[0].Field != "interface" {
		t.Fatal(changes)
	}
}

func TestCoverageSummarizesLargePortRanges(t *testing.T) {
	ports := make([]uint16, 65535)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	key := coverageKey(&ScanCoverage{TCPPorts: ports})
	if key[0] != "tcp=1-65535" {
		t.Fatal(key[0])
	}
	if got := portRanges([]uint16{65535, 65534, 80, 22, 80, 23}); got != "22-23,80,65534-65535" {
		t.Fatal(got)
	}
}
