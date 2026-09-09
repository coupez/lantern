package inventory

import (
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coupez/lantern/pkg/scanner"
)

func applyFixtureReport() scanner.Report {
	return scanner.Report{
		Schema: 1, Target: "192.0.2.0/24", Interface: "en0", Started: time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC), DurationMS: 42, Targets: 2, Probed: 2,
		Coverage: &scanner.ScanCoverage{ICMP: true, Multicast: true, Descriptions: true},
		Devices: []scanner.Device{
			{IP: netip.MustParseAddr("192.0.2.8"), MAC: "02:00:00:00:00:08", Names: []string{"network-name"}, Evidence: []string{"icmp"}, Ports: []scanner.Port{{Number: 443, Service: "https"}}, Kind: "computer", Identity: &scanner.Identity{Model: "Network Model", Claims: []scanner.IdentityClaim{{Field: "model", Value: "Network Model"}}}},
			{IP: netip.MustParseAddr("fe80::8%en0"), Evidence: []string{"ndp"}},
		},
	}
}

func applyObservation(id, kind, model string) scanner.InventoryObservation {
	key, source, reference := "ro.product.model", "adb://127.0.0.1:5037/transport/1", "https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/core/java/android/os/Build.java"
	if kind == "snmp" {
		key, source, reference = "1.3.6.1.2.1.47.1.1.1.1.13.7", "snmpv2c://192.0.2.8:161", "https://www.rfc-editor.org/rfc/rfc4133.html"
	}
	return scanner.InventoryObservation{
		ID: id, Kind: kind, Source: source, SourceSHA256: strings.Repeat("a", 64), BindingSHA256: strings.Repeat("b", 64),
		ObservedAt: "2026-09-09T12:00:00Z", TimeBasis: map[string]string{"android": "collector", "snmp": "owner-supplied"}[kind], Status: "complete",
		Claims: []scanner.InventoryClaim{{Field: "model", Value: model, Key: key, Reference: reference}},
	}
}

func TestApplyExactBindingsPreserveNetworkSnapshotAndDiff(t *testing.T) {
	before := applyFixtureReport()
	bindings := []Binding{
		{Observation: applyObservation("android-1", "android", "Owner Model"), Addresses: []string{"192.0.2.8"}},
		{Observation: applyObservation("snmp-1", "snmp", "Router Chassis"), Addresses: []string{"fe80::8%en0"}},
	}
	after, err := Apply(before, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Devices) != len(before.Devices) || after.Devices[1].Inventory[0].BindingAddress != "fe80::8%en0" {
		t.Fatalf("did not retain exact scoped binding: %#v", after.Devices)
	}
	for i := range before.Devices {
		original, attached := before.Devices[i].Clone(), after.Devices[i].Clone()
		attached.Inventory = nil
		if !reflect.DeepEqual(original, attached) || before.Devices[i].Responsive() != after.Devices[i].Responsive() {
			t.Fatalf("network state changed for %s:\nwant %#v\ngot  %#v", before.Devices[i].IP, original, attached)
		}
	}
	if changes := scanner.Diff(before, after); len(changes) != 0 {
		t.Fatalf("inventory changed network diff: %#v", changes)
	}
}

func TestApplyRejectsAbsentAddressWithoutInventingDevice(t *testing.T) {
	before := applyFixtureReport()
	got, err := Apply(before, []Binding{{Observation: applyObservation("android-1", "android", "Owner Model"), Addresses: []string{"192.0.2.99"}}})
	if err == nil || !reflect.DeepEqual(got, scanner.Report{}) {
		t.Fatalf("got %#v, %v", got, err)
	}
	if !reflect.DeepEqual(before, applyFixtureReport()) {
		t.Fatal("failed apply mutated input snapshot")
	}
}

func TestApplyIdempotenceConflictsAndOwnership(t *testing.T) {
	before := applyFixtureReport()
	android := applyObservation("android-1", "android", "Owner Model")
	first, err := Apply(before, []Binding{{Observation: android, Addresses: []string{"192.0.2.8"}}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Apply(first, []Binding{{Observation: android, Addresses: []string{"192.0.2.8"}}})
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("idempotent apply = %#v, %v", second, err)
	}
	changed := android
	changed.Claims[0].Value = "Changed Model"
	if _, err := Apply(first, []Binding{{Observation: changed, Addresses: []string{"192.0.2.8"}}}); err == nil {
		t.Fatal("accepted changed observation under existing ID")
	}

	withConflict, err := Apply(first, []Binding{{Observation: applyObservation("snmp-1", "snmp", "Router Chassis"), Addresses: []string{"192.0.2.8"}}})
	if err != nil {
		t.Fatal(err)
	}
	if models := withConflict.Devices[0].InventoryModels(); !reflect.DeepEqual(models, []string{"Owner Model", "Router Chassis"}) || withConflict.Devices[0].Identity.Model != "Network Model" {
		t.Fatalf("model conflict was selected or lost: %#v %#v", models, withConflict.Devices[0].Identity)
	}

	// Applying copies both the source report and the unbound observation.
	android.Claims[0].Value = "mutated binding"
	withConflict.Devices[0].Inventory[0].Claims[0].Value = "mutated result"
	withConflict.Devices[0].Names[0] = "mutated result"
	if before.Devices[0].Names[0] != "network-name" || first.Devices[0].Inventory[0].Claims[0].Value != "Owner Model" || len(before.Devices[0].Inventory) != 0 {
		t.Fatalf("shared source/report/result ownership: before=%#v first=%#v", before.Devices[0], first.Devices[0])
	}
}

func TestApplyIsAtomicOnLaterBindingFailure(t *testing.T) {
	before := applyFixtureReport()
	valid := Binding{Observation: applyObservation("android-1", "android", "Owner Model"), Addresses: []string{"192.0.2.8"}}
	invalid := Binding{Observation: applyObservation("snmp-1", "snmp", "Router Chassis"), Addresses: []string{"192.0.2.99"}}
	got, err := Apply(before, []Binding{valid, invalid})
	if err == nil || !reflect.DeepEqual(got, scanner.Report{}) {
		t.Fatalf("got %#v, %v", got, err)
	}
	if len(before.Devices[0].Inventory) != 0 || len(before.Devices[1].Inventory) != 0 {
		t.Fatal("failed transaction retained a partial attachment")
	}
}

func TestApplySnapshotRoundTripAndCrossBindingRejection(t *testing.T) {
	attached, err := Apply(applyFixtureReport(), []Binding{{Observation: applyObservation("android-1", "android", "Owner Model"), Addresses: []string{"192.0.2.8"}}})
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/snapshot.json"
	if err := scanner.Save(path, attached); err != nil {
		t.Fatal(err)
	}
	loaded, err := scanner.Load(path)
	if err != nil || !reflect.DeepEqual(loaded, attached) {
		t.Fatalf("round trip = %#v, %v", loaded, err)
	}

	invalid := attached
	invalid.Devices = make([]scanner.Device, len(attached.Devices))
	for i := range attached.Devices {
		invalid.Devices[i] = attached.Devices[i].Clone()
	}
	invalid.Devices[0].Inventory[0].BindingAddress = "fe80::8%en0"
	if err := scanner.Save(path, invalid); err == nil {
		t.Fatal("saved cross-device inventory binding")
	}
	b, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Load(path); err == nil {
		t.Fatal("loaded cross-device inventory binding")
	}
}
