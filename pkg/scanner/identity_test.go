package scanner

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestIdentityClaimsAreSpecificAndDeterministic(t *testing.T) {
	a := Advertisement{Protocol: "mdns", Instance: "Office._ipp._tcp.local", Service: "_ipp._tcp", Properties: map[string]string{"usb_mfg": "Example Print", "usb_mdl": "Laser 42", "ty": "Example Print Laser 42", "product": "(Laser 42)"}}
	b := Advertisement{Protocol: "upnp", Instance: "uuid:device", Properties: map[string]string{"location": "http://192.168.1.2/device.xml", "friendlyName": "Office", "manufacturer": "Different Brand", "modelName": "Other Model"}}
	one := identify([]Advertisement{a, b, a})
	two := identify([]Advertisement{b, a})
	x, _ := json.Marshal(one)
	y, _ := json.Marshal(two)
	if string(x) != string(y) || len(one.Claims) != 7 || one.Manufacturer != "Example Print" || one.Model != "Laser 42" {
		t.Fatal(string(x), string(y))
	}
	if one.Name != "Office" {
		t.Fatal(one)
	}
	if identify([]Advertisement{{Protocol: "mdns", Service: "_http._tcp", Properties: map[string]string{"model": "invented"}}}) != nil {
		t.Fatal("interpreted arbitrary TXT key as a model")
	}
	a.Properties["usb_mdl"] = "Bad\x1b[2J\r\n"
	if strings.Contains(identify([]Advertisement{a}).Model, "\x1b") {
		t.Fatal("control sequence in identity")
	}
}
func TestDescriptionURLStaysOnDevice(t *testing.T) {
	peer := netip.MustParseAddr("192.168.1.5")
	for _, raw := range []string{"http://192.168.1.5/device.xml", "http://192.168.1.5:49152/device.xml?x=1"} {
		if _, err := descriptionURL(raw, peer); err != nil {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range []string{"http://127.0.0.1/", "http://169.254.169.254/", "http://192.168.1.6/", "http://example.com/", "file:///tmp/x", "https://192.168.1.5/", "http://u:p@192.168.1.5/", "http://192.168.1.5:0/", "http://192.168.1.5:65536/", "http://192.168.1.5/#x", "http://192.168.1.5.example.com/"} {
		if _, err := descriptionURL(raw, peer); err == nil {
			t.Fatal("accepted off-device/invalid URL", raw)
		}
	}
}

const descriptionFixture = `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>Home &amp; Office</friendlyName><manufacturer>Example Networks</manufacturer><modelName>Router 42</modelName><UDN>uuid:root</UDN><deviceList><device><friendlyName>Embedded bridge</friendlyName><manufacturer>Bridge Inc</manufacturer><modelName>Bridge 7</modelName><UDN>uuid:child</UDN></device></deviceList></device></root>`

func TestDescriptionPreservesEmbeddedIdentity(t *testing.T) {
	d, err := parseDescription(descriptionFixture)
	if err != nil || len(d) != 2 || d[0]["modelName"] != "Router 42" || d[1]["modelName"] != "Bridge 7" || d[0]["friendlyName"] != "Home & Office" {
		t.Fatal(d, err)
	}
}
func TestDescriptionRejectsMalformedAndOversized(t *testing.T) {
	for _, s := range []string{"<root>", "<root><device/></root>", descriptionFixture + "<extra/>", strings.Repeat("x", maxDescriptionBytes+1), `<root xmlns="urn:schemas-upnp-org:device-1-0">` + strings.Repeat("<d>", 40) + strings.Repeat("</d>", 40) + "</root>", `<!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/passwd">]><root xmlns="urn:schemas-upnp-org:device-1-0"><device><modelName>&x;</modelName></device></root>`} {
		if _, err := parseDescription(s); err == nil {
			t.Fatal("accepted malformed document")
		}
	}
}
func FuzzDescription(f *testing.F) {
	f.Add(descriptionFixture)
	f.Add("<root/>")
	f.Fuzz(func(t *testing.T, s string) { parseDescription(s) })
}

func TestCastModelCatalogRequiresExactProtocolAndModel(t *testing.T) {
	ad := Advertisement{Protocol: "mdns", Instance: "Living Room._googlecast._tcp.local", Service: "_googlecast._tcp", Properties: map[string]string{"md": "Chromecast Audio", "fn": "Living Room"}}
	id := identify([]Advertisement{ad})
	if id == nil || id.Name != "Living Room" || id.Model != "Chromecast Audio" || id.Manufacturer != "Google Inc." {
		t.Fatal(id)
	}
	found := false
	for _, claim := range id.Claims {
		if claim.Field == "manufacturer" {
			found = claim.Basis == "catalog" && strings.Contains(claim.Catalog, "8f7f3bfaa3142614b04f04e885b43e7810872adb")
		}
	}
	if !found {
		t.Fatal("catalog provenance missing")
	}
	ad.Properties["md"] = "Chromecast Audio Impersonator"
	if got := identify([]Advertisement{ad}); got.Manufacturer != "" {
		t.Fatal("fuzzy model match", got)
	}
	ad.Service = "_http._tcp"
	if got := identify([]Advertisement{ad}); got != nil {
		t.Fatal("wrong protocol matched", got)
	}
}
