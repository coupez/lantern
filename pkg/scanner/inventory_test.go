package scanner

import (
	"strings"
	"testing"
)

func inventoryObservation(kind string) InventoryObservation {
	o := InventoryObservation{ID: "saved", Kind: kind, SourceSHA256: strings.Repeat("a", 64), BindingSHA256: strings.Repeat("b", 64), BindingAddress: "192.0.2.1", ObservedAt: "2026-09-09T12:00:00Z", Status: "complete"}
	if kind == "android" {
		o.Source = "adb://127.0.0.1:5037/transport/7"
		o.TimeBasis = "collector"
		o.Claims = []InventoryClaim{{Field: "model", Value: "Pixel", Key: "ro.product.model", Reference: "https://example.test/build"}}
	} else {
		o.Source = "snmpv2c://192.0.2.1:161"
		o.TimeBasis = "owner-supplied"
		o.Claims = []InventoryClaim{{Field: "model", Value: "R7", Key: "1.3.6.1.2.1.47.1.1.1.1.13.7", Reference: "https://example.test/entity"}}
	}
	return o
}

func TestValidateInventoryObservationSourceConsistency(t *testing.T) {
	for _, kind := range []string{"android", "snmp"} {
		if err := ValidateInventoryObservation(inventoryObservation(kind)); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	tests := map[string]func(*InventoryObservation){
		"android owner time":   func(o *InventoryObservation) { o.TimeBasis = "owner-supplied" },
		"android source":       func(o *InventoryObservation) { o.Source = "snmpv2c://127.0.0.1:161" },
		"android malformed":    func(o *InventoryObservation) { o.Source = "adb://garbage/transport/garbage" },
		"android field":        func(o *InventoryObservation) { o.Claims[0].Field = "component_model" },
		"android key":          func(o *InventoryObservation) { o.Claims[0].Key = "ro.product.device" },
		"android truncated":    func(o *InventoryObservation) { o.Status = "truncated" },
		"android failed claim": func(o *InventoryObservation) { o.Status = "failed" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			o := inventoryObservation("android")
			mutate(&o)
			if err := ValidateInventoryObservation(o); err == nil {
				t.Fatal("accepted contradiction")
			}
		})
	}
}

func TestValidateSNMPClaimNamespaces(t *testing.T) {
	valid := []InventoryClaim{
		{Field: "system_description", Value: "router", Key: "1.3.6.1.2.1.1.1.0", Reference: "https://example.test"},
		{Field: "agent_object_id", Value: "1.3.6.1.4.1.9", Key: "1.3.6.1.2.1.1.2.0", Reference: "https://example.test"},
		{Field: "name", Value: "edge", Key: "1.3.6.1.2.1.1.5.0", Reference: "https://example.test"},
		{Field: "manufacturer", Value: "Acme", Key: "1.3.6.1.2.1.47.1.1.1.1.12.7", Reference: "https://example.test"},
		{Field: "component_model", Value: "board", Key: "1.3.6.1.2.1.47.1.1.1.1.13.8", Reference: "https://example.test"},
	}
	o := inventoryObservation("snmp")
	o.Claims = valid
	if err := ValidateInventoryObservation(o); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []InventoryClaim{{Field: "device", Value: "x", Key: "ro.product.device", Reference: "https://example.test"}, {Field: "model", Value: "x", Key: "1.3.6.1.2.1.47.1.1.1.1.12.7", Reference: "https://example.test"}, {Field: "component_model", Value: "x", Key: "1.3.6.1.2.1.47.1.1.1.1.13.0", Reference: "https://example.test"}, {Field: "component_model", Value: "x", Key: "1.3.6.1.2.1.47.1.1.1.1.13.2147483648", Reference: "https://example.test"}} {
		o := inventoryObservation("snmp")
		o.Claims = []InventoryClaim{bad}
		if err := ValidateInventoryObservation(o); err == nil {
			t.Fatalf("accepted %#v", bad)
		}
	}
	o = inventoryObservation("snmp")
	o.Source = "snmpv2c://garbage"
	if err := ValidateInventoryObservation(o); err == nil {
		t.Fatal("accepted malformed SNMP source")
	}
}
