package scanner

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func hapFixture(ci string) Advertisement {
	return Advertisement{Protocol: "mdns", Service: "_hap._tcp", Instance: "Living.room._hap._tcp.local", Properties: map[string]string{"md": "Fixture Light 7", "ci": ci, "id": "AA:BB:CC:DD:EE:FF"}}
}

func TestHomeKitRecognitionAndProvenance(t *testing.T) {
	a := hapFixture("5")
	before, _ := json.Marshal(a)
	id := identify([]Advertisement{a, a})
	if id == nil || id.Name != "Living.room" || id.Model != "Fixture Light 7" || id.Manufacturer != "" || len(id.ModelNames) != 0 || len(id.Claims) != 3 {
		t.Fatalf("%+v", id)
	}
	want := IdentityClaim{Field: "kind", Value: "light", Source: "mdns:Living.room._hap._tcp.local", Key: "ci", Basis: "protocol", Reference: homeKitCategoryReference, Identifier: "5"}
	if id.Claims[0] != want {
		t.Fatal(id.Claims)
	}
	d := Device{Advertisements: []Advertisement{a}, Identity: id}
	if inferKind(d) != "light" || d.MAC != "" {
		t.Fatal(d)
	}
	after, _ := json.Marshal(a)
	if string(before) != string(after) {
		t.Fatal("recognition mutated the advertisement")
	}
	// Model text belongs to HomeKit, so another protocol's catalog must not apply.
	a.Properties["md"] = "Chromecast Audio"
	if identify([]Advertisement{a}).Manufacturer != "" {
		t.Fatal("cross-protocol catalog match")
	}
	a.Properties["md"] = "Mac16,9"
	if identify([]Advertisement{a}).Manufacturer != "" {
		t.Fatal("HomeKit model assumed to be Apple hardware")
	}
}

func TestHomeKitInvalidAndConflictingCategories(t *testing.T) {
	for _, raw := range []string{"", "0", "37", "65536", "999999999999", "-5", "+5", " 5", "5 ", "5\x00", "5\n", "\u202e5", "5.0", "five"} {
		a := hapFixture(raw)
		if homeKitCategory(raw) != "" || inferKind(Device{Advertisements: []Advertisement{a}}) != "smart home device" {
			t.Fatalf("accepted %q", raw)
		}
		for _, claim := range identify([]Advertisement{a}).Claims {
			if claim.Field == "kind" {
				t.Fatalf("invented category for %q", raw)
			}
		}
	}
	for _, tc := range []struct{ code, kind string }{
		{"1", "smart home device"}, {"2", "smart home hub"}, {"005", "light"}, {"7", "outlet"}, {"9", "thermostat"}, {"17", "camera"}, {"18", "video doorbell"}, {"26", "speaker"}, {"31", "television"}, {"33", "router"}, {"36", "media player"},
	} {
		if got := inferKind(Device{Advertisements: []Advertisement{hapFixture(tc.code)}}); got != tc.kind {
			t.Fatalf("%s: %s", tc.code, got)
		}
	}
	a, b := hapFixture("5"), hapFixture("7")
	b.Instance = "Outlet._hap._tcp.local"
	one, two := []Advertisement{a, b}, []Advertisement{b, a}
	if inferKind(Device{Advertisements: one}) != "smart home device" || inferKind(Device{Advertisements: two}) != "smart home device" || !reflect.DeepEqual(identify(one), identify(two)) {
		t.Fatal("conflict resolved by packet order")
	}
	var kinds []string
	for _, c := range identify(one).Claims {
		if c.Field == "kind" {
			kinds = append(kinds, c.Value)
		}
	}
	if len(kinds) != 2 {
		t.Fatal("category conflict was discarded", kinds)
	}
}

func TestKindRequiresExactProtocolAndService(t *testing.T) {
	for _, a := range []Advertisement{
		{Protocol: "mdns", Service: "_fake_hap._tcp"},
		{Protocol: "mdns", Service: "_hap._tcp.evil"},
		{Protocol: "ssdp", Service: "_hap._tcp"},
		{Protocol: "unknown", Service: "_ipp._tcp"},
		{Protocol: "mdns", Service: "_ipp-backup._tcp"},
		{Protocol: "mdns", Service: "_http._tcp", Instance: "_ipp._tcp"},
		{Protocol: "ssdp", Service: "urn:example:device:InternetGatewayDevice:1"},
		{Protocol: "ssdp", Service: "urn:schemas-upnp-org:device:InternetGatewayDeviceEvil:1"},
		{Protocol: "ssdp", Service: "urn:schemas-upnp-org:device:InternetGatewayDevice:0"},
	} {
		if got := inferKind(Device{Advertisements: []Advertisement{a}}); got != "device" {
			t.Fatalf("%+v became %s", a, got)
		}
	}
	for _, a := range []Advertisement{{Protocol: "mdns", Service: "_pdl-datastream._tcp"}, {Protocol: "mdns", Service: "_IPPS._TCP"}} {
		if inferKind(Device{Advertisements: []Advertisement{a, hapFixture("5")}}) != "printer" {
			t.Fatal("printer precedence lost", a)
		}
	}
	if inferKind(Device{Advertisements: []Advertisement{{Protocol: "upnp", Service: "urn:schemas-upnp-org:device:InternetGatewayDevice:2"}}}) != "router" {
		t.Fatal("lost UPnP router")
	}
	if inferKind(Device{Advertisements: []Advertisement{{Protocol: "ssdp", Service: "urn:schemas-upnp-org:device:MediaRenderer:1"}}}) != "media" {
		t.Fatal("lost UPnP media")
	}
}

func TestHomeKitNamesPreserveInstanceLabels(t *testing.T) {
	for _, tc := range []struct{ instance, want string }{
		{"Living.room._hap._tcp.local", "Living.room"},
		{"Living._hap.room._HAP._TCP.LOCAL.", "Living._hap.room"},
		{"._hap._tcp.local", ""}, {"Invented.local", ""},
	} {
		if got := homeKitName(tc.instance); got != tc.want {
			t.Fatalf("%q: %q", tc.instance, got)
		}
	}
	a := hapFixture("5")
	a.Instance = "Unsafe\x1b\u202e._hap._tcp.local"
	a.Properties["md"] = "Fixture\x00 Light"
	id := identify([]Advertisement{a})
	if id.Name != "Unsafe" || strings.ContainsAny(id.Model, "\x00\x1b") {
		t.Fatal(id)
	}
}
