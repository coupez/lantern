package scanner

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func matterAd(service string, props map[string]string) Advertisement {
	return Advertisement{Protocol: "mdns", Service: service, Instance: "DD200C20D25AE5F7." + service + ".local", Port: 5540, Properties: props}
}

func TestMatterIdentityAndProvenance(t *testing.T) {
	for _, service := range []string{"_matterc._udp", "_matterd._udp", "_MATTERC._UDP"} {
		a := matterAd(service, map[string]string{"dn": "Kitchen Light", "vp": "65521+32769", "dt": "256", "model": "not a model", "mac": "001122334455"})
		id := identify([]Advertisement{a})
		if id == nil || id.Name != "Kitchen Light" || id.Model != "" || id.Manufacturer != "" || id.Firmware != "" || len(id.ModelNames) != 0 {
			t.Fatal(id)
		}
		values := map[string]string{}
		for _, c := range id.Claims {
			values[c.Field] = c.Value
			if c.Source != "mdns:"+a.Instance || c.Reference == "" || c.Catalog != "" {
				t.Fatal("missing protocol provenance", c)
			}
			if c.Field == "device_type_name" && (c.Basis != "protocol" || c.Identifier != "256" || c.Reference != matterTypeReference) {
				t.Fatal(c)
			}
		}
		want := map[string]string{"name": "Kitchen Light", "protocol": "Matter", "discovery_role": matterRole(service), "matter_vendor_id": "65521", "matter_product_id": "32769", "matter_device_type": "256", "device_type_name": "On/Off Light", "kind": "on/off light"}
		if !reflect.DeepEqual(values, want) || inferKind(Device{Advertisements: []Advertisement{a}}) != "on/off light" {
			t.Fatal(values)
		}
	}
}

func TestMatterFieldBoundaries(t *testing.T) {
	for _, raw := range []string{"", "-1", "+1", "01", "0x100", " 256", "256 ", "256\x00", "２５６", "4294967296", strings.Repeat("1", 100)} {
		id := identify([]Advertisement{matterAd("_matterc._udp", map[string]string{"dt": raw})})
		if id == nil || len(id.Claims) != 2 {
			t.Fatal("invalid type acquired identity", raw, id)
		}
	}
	for _, raw := range []string{"+1", "65536+1", "1+65536", "1+", "1+2+3", "01+2", "1+-2", " 1+2", "1+02"} {
		id := identify([]Advertisement{matterAd("_matterc._udp", map[string]string{"vp": raw})})
		if len(id.Claims) != 2 {
			t.Fatal("malformed vendor/product accepted", raw, id)
		}
	}
	for _, raw := range []string{"0", "123", "65535"} {
		id := identify([]Advertisement{matterAd("_matterc._udp", map[string]string{"vp": raw})})
		if len(id.Claims) != 3 {
			t.Fatal("vendor-only value rejected", raw, id)
		}
	}
	for _, raw := range []string{strings.Repeat("a", 33), strings.Repeat("界", 11), "\xff"} {
		id := identify([]Advertisement{matterAd("_matterc._udp", map[string]string{"dn": raw})})
		if id.Name != "" {
			t.Fatal("oversized or invalid UTF-8 name accepted", raw, id)
		}
	}
	a := matterAd("_matterc._udp", map[string]string{"dn": strings.Repeat("a", 32), "dt": "4294967295"})
	id := identify([]Advertisement{a})
	if len(id.Name) != 32 || len(id.Claims) != 4 || inferKind(Device{Advertisements: []Advertisement{a}}) != "smart home device" {
		t.Fatal("valid unknown type or maximum-length name lost", id)
	}
}

func TestMatterRolesAndConflicts(t *testing.T) {
	props := map[string]string{"dn": "Should not be used", "dt": "256", "vp": "123+456"}
	a := matterAd("_matter._tcp", props)
	id := identify([]Advertisement{a})
	if len(id.Claims) != 2 || id.Name != "" || inferKind(Device{Advertisements: []Advertisement{a}}) != "smart home device" {
		t.Fatal("operational service interpreted commissioning fields", id)
	}
	for _, service := range []string{"_matter._udp", "_matterc._tcp", "_matterd._tcp", "_matterc-fake._udp", "_http._tcp"} {
		a := matterAd(service, props)
		if id := identify([]Advertisement{a}); id != nil {
			t.Fatal("lookalike recognized", service, id)
		}
	}
	a.Protocol = "ssdp"
	if len(matterClaims(a)) != 0 {
		t.Fatal("recognized wrong protocol")
	}
	light := matterAd("_matterc._udp", map[string]string{"dt": "256", "dn": "Light"})
	lock := matterAd("_matterc._udp", map[string]string{"dt": "10", "dn": "Lock"})
	lock.Instance = "Another." + lock.Service + ".local"
	if inferKind(Device{Advertisements: []Advertisement{light, lock}}) != "smart home device" || !reflect.DeepEqual(identify([]Advertisement{light, lock}), identify([]Advertisement{lock, light, light})) {
		t.Fatal("conflict resolution depends on arrival order or duplicates")
	}
	utility := matterAd("_matterc._udp", map[string]string{"dt": "22"})
	if inferKind(Device{Advertisements: []Advertisement{utility}}) != "smart home device" {
		t.Fatal("utility type became physical device category")
	}
}

func TestMatterEmbeddedTypes(t *testing.T) {
	var data struct {
		Types map[string]struct {
			Name        string
			Application bool
		}
	}
	if err := json.Unmarshal(matterTypeData, &data); err != nil || len(data.Types) != 65 {
		t.Fatal("invalid embedded type registry", err, len(data.Types))
	}
	for number, entry := range data.Types {
		name, kind := matterDeviceType(number)
		if !matterNumber(number, 16) || name == "" || name != entry.Name || (kind != "") != entry.Application {
			t.Fatal(number, entry, name, kind)
		}
	}
	if name, _ := matterDeviceType("4293984257"); name != "" {
		t.Fatal("vendor-specific example escaped selection", name)
	}
}
