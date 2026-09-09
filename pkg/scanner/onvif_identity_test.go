package scanner

import "testing"

func TestONVIFIdentitySources(t *testing.T) {
	a := Advertisement{Protocol: "onvif", Service: "device-information", Instance: "urn:uuid:fixture-a", Properties: map[string]string{"location": "http://192.0.2.1/service-a", "Model": "Camera 7", "Manufacturer": "Example", "FirmwareVersion": "1.2", "authentication": "none", "transport": "tls-unverified"}}
	b := Advertisement{Protocol: "onvif", Service: "device-information", Instance: "urn:uuid:fixture-b", Properties: map[string]string{"location": "http://192.0.2.1/service-b", "Model": "Recorder 9", "Manufacturer": "Other", "FirmwareVersion": "9.0"}}
	id := identify([]Advertisement{b, a})
	if id == nil || id.Model != "Camera 7" || id.Manufacturer != "Example" || id.FirmwareVersion != "1.2" || id.Firmware != "" || id.Name != "" {
		t.Fatal(id)
	}
	found := map[string]bool{}
	for _, c := range id.Claims {
		found[c.Value] = true
		if c.Value == "1.2" && c.Source != "onvif:http://192.0.2.1/service-a#urn:uuid:fixture-a" {
			t.Fatal(c)
		}
	}
	for _, v := range []string{"Recorder 9", "Other", "9.0", "No credentials supplied", "TLS certificate not verified"} {
		if !found[v] {
			t.Fatal("lost claim", v, id)
		}
	}
	local := identifyWithLocalModel([]Advertisement{a}, "Mac16,9")
	if local.Model != "Mac16,9" || local.Manufacturer != "Apple" || local.FirmwareVersion != "" {
		t.Fatal(local)
	}
	a.Properties["Manufacturer"] = ""
	a.Properties["FirmwareVersion"] = ""
	id = identify([]Advertisement{a, b})
	if id.Manufacturer != "" || id.FirmwareVersion != "" {
		t.Fatal("borrowed competing endpoint metadata", id)
	}
}
func TestONVIFIdentityRejectsWrongServiceAndTaintedValues(t *testing.T) {
	a := Advertisement{Protocol: "onvif", Service: "device-information", Properties: map[string]string{"Model": "bad\x1bmodel", "Manufacturer": "bad\u202emaker", "FirmwareVersion": "bad\x00version"}}
	if id := identify([]Advertisement{a}); id != nil {
		t.Fatal(id)
	}
	a.Properties["Model"] = "Camera 7"
	a.Service = "other"
	if id := identify([]Advertisement{a}); id != nil {
		t.Fatal(id)
	}
}
