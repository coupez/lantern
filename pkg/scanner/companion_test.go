package scanner

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func companionFixture(model string) Advertisement {
	return Advertisement{Protocol: "mdns", Service: "_companion-link._tcp", Instance: "Rotating-ID._companion-link._tcp.local", Port: 49153, Properties: map[string]string{"rpmd": model, "rpvr": "715.2", "rpba": "02:00:00:00:00:01", "rphi": "rotating-id"}}
}

func TestCompanionModelIdentity(t *testing.T) {
	a := companionFixture("AppleTV6,2")
	before, _ := json.Marshal(a)
	id := identify([]Advertisement{a, a})
	if id == nil || id.Model != "AppleTV6,2" || id.Manufacturer != "Apple" || len(id.ModelNames) == 0 {
		t.Fatal(id)
	}
	if id.Name != "" || id.Firmware != "" || id.FirmwareVersion != "" {
		t.Fatal("inferred identity from unrelated fields", id)
	}
	for _, c := range id.Claims {
		if c.Field != "model" && c.Field != "model_name" && c.Field != "manufacturer" {
			t.Fatal(c)
		}
		if c.Key != "rpmd" || c.Source != "mdns:"+a.Instance {
			t.Fatal(c)
		}
		if c.Field == "model" && (c.Basis != "advertised" || c.Reference != companionReference) {
			t.Fatal(c)
		}
		if c.Basis == "catalog" && (c.Identifier != "AppleTV6,2" || !strings.Contains(c.Catalog, "littlebyteorg/appledb")) {
			t.Fatal(c)
		}
	}
	after, _ := json.Marshal(a)
	if string(before) != string(after) {
		t.Fatal("mutated advertisement")
	}
	d := Device{Advertisements: []Advertisement{a}, Identity: id}
	if d.MAC != "" || len(d.Ports) != 0 || inferKind(d) != "device" {
		t.Fatal("service alone inferred physical kind/MAC/open port", d)
	}
}

func TestCompanionModelBoundaries(t *testing.T) {
	for _, model := range []string{"", "Unknown999,1", "Chromecast Audio", "SNSW-001X16EU", "Mac16,\x009"} {
		a := companionFixture(model)
		id := identify([]Advertisement{a})
		if id != nil && (id.Manufacturer != "" || len(id.ModelNames) != 0) {
			t.Fatal("unknown/tainted or wrong-namespace model matched", model, id)
		}
	}
	for _, raw := range []string{"Mac16,\x009", "Mac16,\u202e9", strings.Repeat("x", 257), "Mac16,\xff9"} {
		if id := identify([]Advertisement{companionFixture(raw)}); id != nil {
			t.Fatal("tainted/overlong model became an identity", raw, id)
		}
	}
	for _, service := range []string{"_http._tcp", "_companion-link._udp", "_companion-link._tcp.evil", "_rdlink._tcp"} {
		a := companionFixture("Mac16,9")
		a.Service = service
		if identify([]Advertisement{a}) != nil {
			t.Fatal("wrong service interpreted", service)
		}
	}
	a := companionFixture("Mac16,9")
	a.Protocol = "ssdp"
	if identify([]Advertisement{a}) != nil {
		t.Fatal("wrong protocol interpreted")
	}
	a = companionFixture("Mac16,9")
	a.Service = "_COMPANION-LINK._TCP"
	if id := identify([]Advertisement{a}); id == nil || len(id.ModelNames) != 1 {
		t.Fatal(id)
	}
}

func TestCompanionDoesNotDisplaceExistingModel(t *testing.T) {
	a := companionFixture("Mac16,9")
	b := Advertisement{Protocol: "mdns", Service: "_device-info._tcp", Instance: "Other._device-info._tcp.local", Properties: map[string]string{"model": "Unknown999,1"}}
	left, right := identify([]Advertisement{a, b}), identify([]Advertisement{b, a})
	if !reflect.DeepEqual(left, right) || left.Model != "Unknown999,1" || left.Manufacturer != "" || len(left.ModelNames) != 0 {
		t.Fatal("competing model metadata crossed sources", left, right)
	}
	found := false
	for _, c := range left.Claims {
		if c.Field == "model_name" && c.Identifier == "Mac16,9" {
			found = true
		}
	}
	if !found {
		t.Fatal("competing catalog evidence lost", left)
	}
}
