package evaluation

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/coupez/lantern/pkg/scanner"
)

func testInventory(address, value string) scanner.InventoryObservation {
	return scanner.InventoryObservation{
		ID: "adb-1", Kind: "android", Source: "adb://127.0.0.1:5037/transport/1",
		SourceSHA256:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BindingSHA256:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		BindingAddress: address, ObservedAt: "2026-09-09T10:00:00Z", TimeBasis: "collector", Status: "complete",
		Claims: []scanner.InventoryClaim{{Field: "model", Value: value, Key: "ro.product.model", Reference: "https://developer.android.com/reference/android/os/Build"}},
	}
}

func TestFromLanternWithInventoryAddsOnlyBoundModelClaims(t *testing.T) {
	bindings := validBindings()
	report := scanner.Report{Schema: 1, DurationMS: 12, Devices: []scanner.Device{
		{IP: netip.MustParseAddr("192.0.2.10"), Evidence: []string{"mdns"}, Identity: &scanner.Identity{Model: "network-code", ModelNames: []string{"Retail One"}}, Inventory: []scanner.InventoryObservation{testInventory("192.0.2.10", "adb-code")}},
		{IP: netip.MustParseAddr("192.0.2.99"), Inventory: []scanner.InventoryObservation{testInventory("192.0.2.99", "unmapped-code")}},
	}}
	run, err := FromLanternWithInventory(report, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if run.System != "lantern+inventory" || run.DurationMS != nil || len(run.Observations) != 1 || run.Observations[0].Responsive != true {
		t.Fatal(run)
	}
	if !reflect.DeepEqual(run.Observations[0].Predictions[ReportedModel], []string{"adb-code", "network-code"}) {
		t.Fatal(run.Observations[0].Predictions)
	}
	if !reflect.DeepEqual(run.Observations[0].Predictions[RetailModel], []string{"Retail One"}) {
		t.Fatal("inventory invented retail model", run.Observations[0].Predictions)
	}
	if len(run.Unmapped) != 1 || run.Unmapped[0] != "192.0.2.99" {
		t.Fatal("inventory created an observation", run)
	}
}

func TestFromLanternWithInventoryConflictsAreAmbiguous(t *testing.T) {
	bindings := validBindings()
	report := scanner.Report{Schema: 1, Devices: []scanner.Device{{IP: netip.MustParseAddr("192.0.2.10"), Identity: &scanner.Identity{Model: "network-model"}, Inventory: []scanner.InventoryObservation{testInventory("192.0.2.10", "inventory-model")}}}}
	run, err := FromLanternWithInventory(report, bindings)
	if err != nil {
		t.Fatal(err)
	}
	truth := Truth{Schema: 1, ID: bindings.Dataset, Kind: "physical", Cases: []Case{{ID: "printer-a", Class: "phone", Truth: map[string]Label{ReportedModel: {Accepted: []string{"inventory-model"}, SourceKind: "physical_label", Source: "fixture"}}}}}
	result, err := Evaluate(truth, run)
	if err != nil || result.Cases[0].Outcomes[ReportedModel] != "ambiguous" {
		t.Fatal(result, err)
	}
}

func TestFromLanternWithInventoryKeepsUnknownNetworkPresence(t *testing.T) {
	bindings := validBindings()
	report := scanner.Report{Schema: 1, Devices: []scanner.Device{{IP: netip.MustParseAddr("192.0.2.10"), Inventory: []scanner.InventoryObservation{testInventory("192.0.2.10", "authorized-model")}}}}
	run, err := FromLanternWithInventory(report, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Observations) != 1 || !run.Observations[0].Seen || run.Observations[0].Responsive {
		t.Fatal("inventory changed network presence", run)
	}
	if !reflect.DeepEqual(run.Observations[0].Predictions[ReportedModel], []string{"authorized-model"}) {
		t.Fatal(run.Observations[0].Predictions)
	}
}

func TestFromLanternWithInventoryRejectsWrongBindingAndBoundsCandidates(t *testing.T) {
	bindings := validBindings()
	report := scanner.Report{Schema: 1, Devices: []scanner.Device{{IP: netip.MustParseAddr("192.0.2.10"), Inventory: []scanner.InventoryObservation{testInventory("192.0.2.11", "wrong")}}}}
	if _, err := FromLanternWithInventory(report, bindings); err == nil {
		t.Fatal("accepted inventory bound to another device")
	}
	tooMany := make([]scanner.InventoryObservation, 9)
	for i := range tooMany {
		tooMany[i] = testInventory("192.0.2.10", "model")
		tooMany[i].ID = "adb-" + string(rune('a'+i))
	}
	report.Devices[0].Inventory = tooMany
	if _, err := FromLanternWithInventory(report, bindings); err == nil {
		t.Fatal("accepted too many inventory observations")
	}
}

func TestFromLanternIgnoresInventory(t *testing.T) {
	bindings := validBindings()
	report := scanner.Report{Schema: 1, Devices: []scanner.Device{{IP: netip.MustParseAddr("192.0.2.10"), Inventory: []scanner.InventoryObservation{testInventory("192.0.2.10", "inventory-model")}}}}
	run, err := FromLantern(report, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := run.Observations[0].Predictions[ReportedModel]; ok {
		t.Fatal("default adapter consumed inventory", run)
	}
}
