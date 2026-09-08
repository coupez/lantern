package scanner

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func espHomeFixture() Advertisement {
	return Advertisement{Protocol: "mdns", Service: "_esphomelib._tcp", Instance: "Workshop.Sensor._esphomelib._tcp.local", Port: 6053, Properties: map[string]string{
		"friendly_name": "Workshop Air", "version": "2026.8.1", "board": "esp32dev", "platform": "ESP32",
		"project_name": "example.air-monitor", "project_version": "1.2.3", "mac": "001122334455",
		"network": "wifi", "api_encryption": "Noise_NNpsk0_25519_ChaChaPoly_SHA256", "package_import_url": "https://example.invalid/project",
	}}
}

func TestESPHomeIdentityAndProvenance(t *testing.T) {
	a := espHomeFixture()
	before, _ := json.Marshal(a)
	id := identify([]Advertisement{a, a})
	if id == nil || id.Name != "Workshop Air" || id.Firmware != "ESPHome" || id.FirmwareVersion != "2026.8.1" || id.Model != "" || id.Manufacturer != "" || len(id.ModelNames) != 0 {
		t.Fatal(id)
	}
	fields := map[string]string{}
	for _, claim := range id.Claims {
		if claim.Reference != espHomeReference || claim.Source != "mdns:"+a.Instance {
			t.Fatal(claim)
		}
		if claim.Field == "firmware" || claim.Field == "kind" {
			if claim.Basis != "protocol" || claim.Identifier != a.Service {
				t.Fatal(claim)
			}
		} else if claim.Basis != "advertised" {
			t.Fatal(claim)
		}
		fields[claim.Field] = claim.Value
	}
	for key, want := range map[string]string{"build_board": "esp32dev", "platform": "ESP32", "firmware_project": "example.air-monitor", "firmware_project_version": "1.2.3"} {
		if fields[key] != want {
			t.Fatal(key, fields)
		}
	}
	if len(id.Claims) != 9 {
		t.Fatal("lost or duplicated claims", id.Claims)
	}
	d := Device{Identity: id, Advertisements: []Advertisement{a}}
	if inferKind(d) != "smart home device" || d.MAC != "" || len(d.Ports) != 0 {
		t.Fatal(d)
	}
	after, _ := json.Marshal(a)
	if string(before) != string(after) {
		t.Fatal("mutated advertisement")
	}
}

func TestESPHomeServiceBoundariesAndNameFallback(t *testing.T) {
	for _, service := range []string{"_http._tcp", "_esphomelib._udp", "_esphomelib._tcp.evil", "_fake_esphomelib._tcp"} {
		a := espHomeFixture()
		a.Service = service
		if id := identify([]Advertisement{a}); id != nil {
			t.Fatal("lookalike identified", a, id)
		}
		if inferKind(Device{Advertisements: []Advertisement{a}}) != "device" {
			t.Fatal(a)
		}
	}
	a := espHomeFixture()
	a.Protocol = "ssdp"
	if identify([]Advertisement{a}) != nil || inferKind(Device{Advertisements: []Advertisement{a}}) != "device" {
		t.Fatal("wrong protocol")
	}
	a = espHomeFixture()
	a.Service = "_ESPHOMELIB._TCP"
	a.Instance = "Workshop.Sensor._ESPHOMELIB._TCP.LOCAL."
	delete(a.Properties, "friendly_name")
	if id := identify([]Advertisement{a}); id.Name != "Workshop.Sensor" || id.Firmware != "ESPHome" {
		t.Fatal(id)
	}
	a.Instance = "Invented.local"
	if id := identify([]Advertisement{a}); id.Name != "" {
		t.Fatal("unrelated instance became a name", id)
	}
	for _, board := range []string{"Mac16,9", "Chromecast Audio", "ESP32", "Shelly Plus 1"} {
		a.Properties["board"] = board
		id := identify([]Advertisement{a})
		if id.Model != "" || id.Manufacturer != "" || len(id.ModelNames) != 0 {
			t.Fatal("build board became retail identity", id)
		}
	}
}

func TestESPHomeRetainsCompetingFirmwareSources(t *testing.T) {
	a, b := espHomeFixture(), espHomeFixture()
	a.Instance = "A._esphomelib._tcp.local"
	delete(a.Properties, "version")
	b.Instance = "B._esphomelib._tcp.local"
	b.Properties["version"] = "2099.1.0"
	one, two := identify([]Advertisement{a, b}), identify([]Advertisement{b, a})
	if !reflect.DeepEqual(one, two) || one.Firmware != "ESPHome" || one.FirmwareVersion != "" {
		t.Fatal("version mixed across instances", one, two)
	}
	versions := 0
	for _, c := range one.Claims {
		if c.Field == "firmware_version" && c.Value == "2099.1.0" {
			versions++
		}
	}
	if versions != 1 {
		t.Fatal("competing version lost", one)
	}
	for _, ad := range []Advertisement{hapFixture("5"), {Protocol: "mdns", Service: "_ipp._tcp"}, {Protocol: "mdns", Service: "_home-assistant._tcp"}} {
		want := inferKind(Device{Advertisements: []Advertisement{ad}})
		if got := inferKind(Device{Advertisements: []Advertisement{a, ad}}); got != want {
			t.Fatal("generic firmware type overrode specific kind", want, got)
		}
	}
}

func TestESPHomeFirmwareDiffAndClone(t *testing.T) {
	a := espHomeFixture()
	d := Device{IP: netip.MustParseAddr("192.0.2.1"), Identity: identify([]Advertisement{a})}
	old := Report{Coverage: &ScanCoverage{Multicast: true}, Devices: []Device{d}}
	changed := d.Clone()
	changed.Identity.FirmwareVersion = "2026.9.0"
	new := Report{Coverage: &ScanCoverage{Multicast: true}, Devices: []Device{changed}}
	changes := Diff(old, new)
	if len(changes) != 1 || changes[0].Field != "identity.firmware_version" || changes[0].Before[0] != "2026.8.1" || changes[0].After[0] != "2026.9.0" {
		t.Fatal(changes)
	}
	new.Coverage.Multicast = false
	for _, c := range Diff(old, new) {
		if c.Field == "identity.firmware_version" {
			t.Fatal("incomparable firmware reported as changed", c)
		}
	}
	a.Properties["friendly_name"] = "Name\x1b\u202e"
	a.Properties["version"] = strings.Repeat("v", 300) + "\x00"
	id := identify([]Advertisement{a})
	if id.Name != "Name" || len([]rune(id.FirmwareVersion)) != 256 || strings.ContainsAny(id.FirmwareVersion, "\x1b\x00\u202e") {
		t.Fatal(id)
	}
}
