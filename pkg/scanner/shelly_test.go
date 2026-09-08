package scanner

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// Synthetic identity with the fields documented by Shelly.GetDeviceInfo.
const shellyFixture = `{"name":"Workshop relay","id":"shellyplus1-001122334455","model":"SNSW-001X16EU","gen":2,"fw_id":"fixture-build","ver":"1.4.0","app":"Plus1","profile":"switch","mac":"001122334455","auth_en":true,"auth_domain":"fixture","future":{"data":[1,2,3]}}`

func TestShellyDescriptionParsing(t *testing.T) {
	fields, err := parseShellyDescription([]byte(shellyFixture))
	if err != nil || fields["gen"] != "2" || fields["model"] != "SNSW-001X16EU" || len(fields) != 9 {
		t.Fatal(fields, err)
	}
	for _, raw := range []string{
		strings.Replace(shellyFixture, `"gen":2`, `"gen":4`, 1),
		strings.Replace(shellyFixture, `"name":"Workshop relay"`, `"name":null`, 1),
		" \n" + shellyFixture + "\n ",
	} {
		if _, err := parseShellyDescription([]byte(raw)); err != nil {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range []string{
		`{}`, `null`, `[]`, `{"gen":2,"id":"fixture"}`, shellyFixture + `{}`, shellyFixture + `x`,
		strings.Replace(shellyFixture, `"gen":2`, `"gen":1`, 1),
		strings.Replace(shellyFixture, `"gen":2`, `"gen":"2"`, 1),
		strings.Replace(shellyFixture, `"gen":2`, `"gen":2.0`, 1),
		strings.Replace(shellyFixture, `"gen":2`, `"gen":4294967296`, 1),
		strings.Replace(shellyFixture, `"gen":2`, `"gen":null`, 1),
		strings.Replace(shellyFixture, `"gen":2`, `"gen":2,"gen":3`, 1),
		strings.Replace(shellyFixture, `"gen":2`, `"gen":2,"g\u0065n":3`, 1),
		strings.Replace(shellyFixture, `"model":"SNSW-001X16EU"`, `"model":null`, 1),
		strings.Replace(shellyFixture, `"model":"SNSW-001X16EU"`, `"model":123`, 1),
		strings.Replace(shellyFixture, `SNSW-001X16EU`, strings.Repeat("x", 2049), 1),
		strings.Replace(shellyFixture, `SNSW-001X16EU`, "\xff", 1),
		strings.Replace(shellyFixture, `SNSW-001X16EU`, " ", 1),
		shellyFixture[:len(shellyFixture)-1], strings.Repeat(" ", maxShellyBytes) + shellyFixture,
	} {
		if _, err := parseShellyDescription([]byte(raw)); err == nil {
			t.Fatalf("accepted malformed document %.200q", raw)
		}
	}
}

func TestShellyIdentityAndSourceIsolation(t *testing.T) {
	fields, _ := parseShellyDescription([]byte(shellyFixture))
	fields["location"] = "http://192.0.2.1:80/shelly"
	ad := Advertisement{Protocol: "shelly", Service: "device-info", Instance: fields["id"], Properties: fields}
	mdns := Advertisement{Protocol: "mdns", Service: "_shelly._tcp", Instance: "Shelly._shelly._tcp.local", Port: 80, Properties: map[string]string{"gen": "2", "model": "Mac16,9", "ver": "wrong"}}
	before, _ := json.Marshal([]Advertisement{ad, mdns})
	id := identify([]Advertisement{mdns, ad, ad})
	if id == nil || id.Name != "Workshop relay" || id.Model != "SNSW-001X16EU" || id.Firmware != "Shelly" || id.FirmwareVersion != "1.4.0" || id.Manufacturer != "Shelly" || len(id.ModelNames) != 1 || id.ModelNames[0] != "Shelly Plus 1" {
		t.Fatal(id)
	}
	claims := map[string]string{}
	for _, c := range id.Claims {
		claims[c.Field] = c.Value
		if strings.HasPrefix(c.Source, "shelly:") && ((c.Basis != "catalog" && c.Reference != shellyInfoReference) || c.Source != "shelly:"+fields["location"]+"#"+ad.Instance) {
			t.Fatal(c)
		}
	}
	for key, want := range map[string]string{"application": "Plus1", "generation": "2", "reported_mac": "001122334455", "profile": "switch", "firmware_build": "fixture-build"} {
		if claims[key] != want {
			t.Fatal(key, claims)
		}
	}
	if _, ok := claims["auth_en"]; ok {
		t.Fatal("claimed security state", id)
	}
	other := ad
	other.Properties = map[string]string{"location": "http://192.0.2.1:81/shelly", "ver": "9.9.9"}
	delete(fields, "ver")
	a, b := identify([]Advertisement{ad, other}), identify([]Advertisement{other, ad})
	if !reflect.DeepEqual(a, b) || a.FirmwareVersion != "" {
		t.Fatal("mixed versions across endpoints", a, b)
	}
	fields["ver"] = "1.4.0"
	after, _ := json.Marshal([]Advertisement{ad, mdns})
	if string(before) != string(after) {
		t.Fatal("mutated source")
	}
	d := Device{IP: netip.MustParseAddr("192.0.2.1"), Advertisements: []Advertisement{mdns, ad}, Identity: id}
	if inferKind(d) != "smart home device" || d.MAC != "" || len(d.Ports) != 0 {
		t.Fatal(d)
	}
}

func TestShellyDiscoveryBoundaries(t *testing.T) {
	ad := Advertisement{Protocol: "mdns", Service: "_SHELLY._TCP", Instance: "Office.Relay._SHELLY._TCP.LOCAL.", Port: 80, Properties: map[string]string{"gen": "3", "model": "Mac16,9", "ver": "unexpected"}}
	id := identify([]Advertisement{ad})
	if id == nil || id.Name != "Office.Relay" || id.Model != "" || id.Firmware != "" || id.FirmwareVersion != "" {
		t.Fatal(id)
	}
	for _, service := range []string{"_http._tcp", "_shelly._udp", "_shelly._tcp.evil", "_fake_shelly._tcp"} {
		bad := ad
		bad.Service = service
		if shellyDescriptionURL(netip.MustParseAddr("192.0.2.1"), bad) != "" || identify([]Advertisement{bad}) != nil || inferKind(Device{Advertisements: []Advertisement{bad}}) != "device" {
			t.Fatal(bad)
		}
	}
	for _, peer := range []string{"192.0.2.1", "2001:db8::1", "fe80::1%test0"} {
		ip := netip.MustParseAddr(peer)
		u, err := descriptionURL(shellyDescriptionURL(ip, ad), ip)
		if err != nil || u.Path != "/shelly" || u.RawQuery != "" || u.Port() != "80" || u.Hostname() != peer {
			t.Fatal(u, err)
		}
	}
	ad.Port = 0
	if shellyDescriptionURL(netip.MustParseAddr("192.0.2.1"), ad) != "" {
		t.Fatal("zero port accepted")
	}
	ad.Port, ad.Protocol = 80, "ssdp"
	if shellyDescriptionURL(netip.MustParseAddr("192.0.2.1"), ad) != "" || identify([]Advertisement{ad}) != nil {
		t.Fatal("wrong protocol")
	}
}

func TestShellyCatalogRequiresMatchingGenerationAndModelSource(t *testing.T) {
	fields, _ := parseShellyDescription([]byte(shellyFixture))
	fields["location"] = "http://192.0.2.1/shelly"
	ad := Advertisement{Protocol: "shelly", Service: "device-info", Instance: fields["id"], Properties: fields}
	for _, generation := range []string{"", "0", "1", "3", "5", "2\x00"} {
		fields["gen"] = generation
		id := identify([]Advertisement{ad})
		if id.Model != fields["model"] || id.Manufacturer != "" || len(id.ModelNames) != 0 {
			t.Fatal(generation, id)
		}
	}
	fields["gen"] = "2"
	for _, model := range []string{"Mac16,9", "SNSW-001X16EU\x00", "SNSW-001X16EU-extra"} {
		fields["model"] = model
		id := identify([]Advertisement{ad})
		if id.Manufacturer != "" || len(id.ModelNames) != 0 {
			t.Fatal(model, id)
		}
	}
	fields["model"] = "SNSW-001X16EU"
	for _, service := range []string{"_airplay._tcp", "_device-info._tcp", "_raop._tcp"} {
		id := identify([]Advertisement{{Protocol: "mdns", Service: service, Properties: map[string]string{"model": fields["model"], "am": fields["model"]}}})
		if id.Manufacturer != "" || len(id.ModelNames) != 0 {
			t.Fatal("cross-catalog protocol match", service, id)
		}
	}
	id := identify([]Advertisement{ad, {Protocol: "upnp", Instance: "uuid:other", Properties: map[string]string{"location": "http://192.0.2.1/device", "modelName": "Other device"}}})
	if id.Model != "Other device" || id.Manufacturer != "" || len(id.ModelNames) != 0 {
		t.Fatal("unselected model leaked catalog data", id)
	}
	retained := false
	for _, claim := range id.Claims {
		retained = retained || claim.Field == "model_name" && claim.Value == "Shelly Plus 1" && claim.Basis == "catalog"
	}
	if !retained {
		t.Fatal("lost competing claim", id)
	}
}
