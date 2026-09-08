package scanner

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/coupez/lantern/pkg/vendors"
)

type partialErrorDialer struct{}

func (partialErrorDialer) Probe(_ context.Context, _ netip.Addr, p uint16, _ time.Duration) (bool, bool, time.Duration, error) {
	if p == 80 {
		return true, true, time.Millisecond, nil
	}
	return false, false, 0, fmt.Errorf("TCP fixture failure on port %d", p)
}

func TestIncompleteMethodsSurviveWarningCapAndPersistence(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("192.0.2.1/32")
	o.ICMP, o.Multicast, o.Resolve, o.Descriptions = false, false, false, false
	o.ARP, o.NetBIOS = true, true
	o.Ports = []uint16{80}
	for p := uint16(1000); p < 1030; p++ {
		o.Ports = append(o.Ports, p)
	}
	failure := fmt.Errorf("injected discovery failure")
	r, err := (Engine{
		Dialer: partialErrorDialer{},
		ARPSource: func(context.Context, Options, []netip.Addr) (ARPResult, error) {
			return ARPResult{}, failure
		},
		NetBIOSSource: func(context.Context, []netip.Addr, time.Duration) (NetBIOSResult, error) {
			return NetBIOSResult{}, failure
		},
		NeighborSource: func(context.Context) (map[netip.Addr]string, error) { return nil, failure },
	}).Scan(context.Background(), o, nil)
	want := []string{"arp", "neighbors", "netbios", "tcp"}
	if err != nil || r.Error != "" || r.Cancelled || !slices.Equal(r.IncompleteMethods, want) {
		t.Fatalf("report=%+v err=%v", r, err)
	}
	if len(r.Warnings) != 17 || !slices.Contains(r.Warnings, "additional probe errors omitted") || len(r.Devices) != 1 || len(r.Devices[0].Ports) != 1 {
		t.Fatalf("partial results or bounded warnings lost: %+v", r)
	}
	path := t.TempDir() + "/partial.json"
	if err := Save(path, r); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || !slices.Equal(loaded.IncompleteMethods, want) {
		t.Fatal(loaded, err)
	}
}

func TestNDPFailureMarksIncompleteWithoutDiscardingObservations(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("2001:db8::1/128")
	o.ICMP, o.Multicast, o.Resolve, o.Descriptions = false, false, false, false
	o.Ports, o.NDP = nil, true
	r, err := (Engine{
		NeighborSource: noNeighbors,
		NDPSource: func(context.Context, Options, []netip.Addr) (NDPResult, error) {
			return NDPResult{Neighbors: []Neighbor{{IP: o.Target.Addr(), MAC: "02:11:22:33:44:55"}}}, fmt.Errorf("partial NDP read failure")
		},
	}).Scan(context.Background(), o, nil)
	if err != nil || !slices.Equal(r.IncompleteMethods, []string{"ndp"}) || len(r.Devices) != 1 || r.Devices[0].MAC != "02:11:22:33:44:55" {
		t.Fatal(r, err)
	}
}

func TestCancellationIsSeparateFromDiscoveryFailure(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("192.0.2.1/32")
	o.ICMP, o.Multicast, o.Resolve = false, false, false
	o.Ports, o.ARP = nil, true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := (Engine{NeighborSource: noNeighbors, ARPSource: func(context.Context, Options, []netip.Addr) (ARPResult, error) {
		cancel()
		return ARPResult{}, context.Canceled
	}}).Scan(ctx, o, nil)
	if err != nil || !r.Cancelled || len(r.IncompleteMethods) != 0 {
		t.Fatal(r, err)
	}
}

func TestDiffIncompleteMethodsProtectDependentFields(t *testing.T) {
	old := Device{
		IP: netip.MustParseAddr("192.0.2.1"), MAC: "00:11:22:33:44:55", Vendor: vendors.Match{Name: "Vendor"},
		Ports: []Port{{Number: 80}}, Names: []string{"name.local"}, Kind: "printer", Evidence: []string{"icmp"},
		Identity:       &Identity{Name: "Name", Model: "Model", Firmware: "ESPHome", FirmwareVersion: "1"},
		Advertisements: []Advertisement{{Protocol: "netbios", Service: "workgroup", Properties: map[string]string{"name": "LAB"}}},
	}
	now := Device{IP: old.IP, Evidence: []string{"neighbor-cache"}}
	allFields := []string{"mac", "vendor", "ports", "names", "kind", "identity.name", "identity.model", "identity.firmware", "identity.firmware_version", "workgroups"}
	for _, tc := range []struct {
		method     string
		suppressed []string
	}{
		{"tcp", []string{"ports", "kind"}},
		{"arp", []string{"mac", "vendor"}},
		{"ndp", []string{"mac", "vendor"}},
		{"neighbors", []string{"mac", "vendor"}},
		{"multicast", []string{"names", "kind", "identity.name", "identity.model", "identity.firmware", "identity.firmware_version"}},
		{"netbios", []string{"names", "kind", "identity.name", "identity.model", "identity.firmware", "identity.firmware_version", "workgroups"}},
		{"icmp", nil}, {"candidates", nil}, {"future-method", allFields},
	} {
		t.Run(tc.method, func(t *testing.T) {
			before := Report{Devices: []Device{old, diffDevice("192.0.2.2")}}
			after := Report{Devices: []Device{now, diffDevice("192.0.2.3")}, IncompleteMethods: []string{tc.method}}
			changes := Diff(before, after)
			fields := changesByField(changes)
			if fields["incomplete_methods"].Type != "scan" || !slices.Equal(fields["incomplete_methods"].After, after.IncompleteMethods) {
				t.Fatal(changes)
			}
			for _, f := range allFields {
				_, got := fields[f]
				if got == slices.Contains(tc.suppressed, f) {
					t.Fatalf("field %s: %+v", f, changes)
				}
			}
			added := false
			for _, c := range changes {
				if c.Type == "missing" || c.Field == "reachability" {
					t.Fatal("incomplete scan manufactured negative presence evidence", changes)
				}
				added = added || c.Type == "added" && c.IP == "192.0.2.3"
			}
			if !added {
				t.Fatal("lost addition", changes)
			}
		})
	}
}

func TestDiffIncompleteMethodSetsAndRecovery(t *testing.T) {
	before := Report{IncompleteMethods: []string{"tcp", "multicast", "tcp"}, Devices: []Device{diffDevice("192.0.2.1")}}
	after := Report{IncompleteMethods: []string{"multicast", "tcp"}, Devices: []Device{diffDevice("192.0.2.1")}}
	after.Devices[0].Ports = []Port{{Number: 80}}
	after.Devices[0].Names = []string{"printer.local"}
	if changes := Diff(before, after); len(changes) != 0 {
		t.Fatal(changes)
	}
	if !reflect.DeepEqual(before.IncompleteMethods, []string{"tcp", "multicast", "tcp"}) {
		t.Fatal("mutated input")
	}
	after.IncompleteMethods = nil
	fields := changesByField(Diff(before, after))
	if len(fields) != 3 || fields["ports"].Type != "changed" || fields["names"].Type != "changed" || !slices.Equal(fields["incomplete_methods"].Before, []string{"multicast", "tcp"}) {
		t.Fatal(fields)
	}
}
