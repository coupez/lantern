package ui

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/coupez/lantern/pkg/scanner"
)

func inventoryFixture(models ...string) []scanner.InventoryObservation {
	claims := make([]scanner.InventoryClaim, 0, len(models)+2)
	for _, model := range models {
		claims = append(claims, scanner.InventoryClaim{Field: "model", Value: model, Key: "ro.product.model", Reference: "https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/core/java/android/os/Build.java"})
	}
	claims = append(claims,
		scanner.InventoryClaim{Field: "manufacturer", Value: "Inventory Maker", Key: "ro.product.manufacturer", Reference: "https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/core/java/android/os/Build.java"},
		scanner.InventoryClaim{Field: "device", Value: "board-codename", Key: "ro.product.device", Reference: "https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/core/java/android/os/Build.java"},
	)
	return []scanner.InventoryObservation{{
		Kind: "android", ID: "android-source", ObservedAt: "2026-09-09T12:00:00Z", TimeBasis: "collector", Status: "complete",
		Source: "adb://127.0.0.1:5037/transport/1", SourceSHA256: strings.Repeat("a", 64), BindingSHA256: strings.Repeat("b", 64), BindingAddress: "192.0.2.8", Claims: claims,
	}, {
		Kind: "snmp", ID: "snmp-source", ObservedAt: "2026-09-09T12:00:00Z", TimeBasis: "owner-supplied", Status: "complete",
		Source: "snmpv2c://192.0.2.8:161", SourceSHA256: strings.Repeat("c", 64), BindingSHA256: strings.Repeat("d", 64), BindingAddress: "192.0.2.8",
		Claims: []scanner.InventoryClaim{{Field: "component_model", Value: "Radio Board 7", Key: "1.3.6.1.2.1.47.1.1.1.1.13.7", Reference: "https://www.rfc-editor.org/rfc/rfc4133.html"}},
	}}
}

func TestInventoryUIModelFallbackAndNetworkPriority(t *testing.T) {
	base := scanner.Device{IP: netip.MustParseAddr("192.0.2.8"), Inventory: inventoryFixture("Owner Model")}
	if got := deviceName(base); got != "Inventory · Owner Model" {
		t.Fatalf("fallback = %q", got)
	}
	withNetwork := base.Clone()
	withNetwork.Identity = &scanner.Identity{Model: "Network Model"}
	if got := deviceName(withNetwork); got != "Network Model" {
		t.Fatalf("inventory replaced network model: %q", got)
	}
	var out bytes.Buffer
	(&UI{Out: &out, Width: 100}).Report(scanner.Report{Devices: []scanner.Device{withNetwork}})
	if !strings.Contains(out.String(), "Network Model") || !strings.Contains(out.String(), "Inventory · Owner Model") {
		t.Fatal(out.String())
	}
}

func TestInventoryUIMultipleModelsAndInspectorProvenance(t *testing.T) {
	d := scanner.Device{IP: netip.MustParseAddr("192.0.2.8"), Inventory: inventoryFixture("Model A", "Model B")}
	if got := deviceName(d); got != "Inventory · 2 reported models" {
		t.Fatal(got)
	}
	var out bytes.Buffer
	u := &UI{Out: &out, Width: 120}
	u.Report(scanner.Report{Devices: []scanner.Device{d}})
	if !strings.Contains(out.String(), "Inventory · 2 reported models") {
		t.Fatal(out.String())
	}
	out.Reset()
	u.Details(scanner.Report{Devices: []scanner.Device{d}})
	for _, want := range []string{"Inv. kind", "android", "Inv. ID", "android-source", "Observed at", "Time basis", "Inv. status", "Inv. source", "Source hash", "Binding hash", "Bind address", "Inv. claim", "Model A", "Model B", "component_model", "Radio Board 7", "Inv. key", "ro.product.model", "Inv. ref", "android.googlesource.com"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q from %q", want, out.String())
		}
	}
}

func TestWatchSearchIncludesInventoryClaimsAndProvenance(t *testing.T) {
	d := scanner.Device{IP: netip.MustParseAddr("192.0.2.8"), Inventory: inventoryFixture("Owner Model")}
	m := watchModel{}
	m.accept(scanner.Report{Devices: []scanner.Device{d}})
	for _, query := range []string{"owner model", "radio board 7", "inventory maker", "board-codename", "android-source", "source_sha256", "aaaaaaaa", "192.0.2.8", "ro.product.device", "rfc4133"} {
		m.query = query
		if len(m.devices()) != 1 {
			t.Errorf("inventory value not searchable: %q", query)
		}
	}
}
