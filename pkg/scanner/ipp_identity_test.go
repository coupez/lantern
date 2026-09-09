package scanner

import (
	"strings"
	"testing"
)

func TestIPPDeviceIDSubsetAndConflict(t *testing.T) {
	p := map[string]string{"printer-device-id": "MFG:Example;MDL:Laser 42;SN:private-serial;UUID:private-uuid;CMD:PCL;"}
	retainIPPDeviceID(p)
	if p["printer-device-id"] != "" || p["device-id-model"] != "Laser 42" || p["device-id-manufacturer"] != "Example" {
		t.Fatal(p)
	}
	for _, v := range p {
		if strings.Contains(v, "private") {
			t.Fatal("unrequested identifier retained", p)
		}
	}
	p = map[string]string{"printer-device-id": "MFG:Example;MANUFACTURER:Other;MDL:One;MODEL:Two;"}
	retainIPPDeviceID(p)
	if p["device-id-model"] != "" || p["device-id-manufacturer"] != "" {
		t.Fatal("ambiguous aliases selected", p)
	}
	if !strings.Contains(p["device-id-identity"], "MDL:One;MODEL:Two;") {
		t.Fatal("discarded conflicting model evidence", p)
	}
}
func TestIPPIdentityEndpointLinkage(t *testing.T) {
	first := Advertisement{Protocol: "ipp", Service: "printer-attributes", Instance: "Queue", Properties: map[string]string{"location": "http://192.0.2.1:631/ipp/one", "device-id-model": "Laser 42", "device-id-manufacturer": "Example", "printer-name": "Queue name", "printer-make-and-model": "Example Laser"}}
	second := Advertisement{Protocol: "ipp", Service: "printer-attributes", Instance: "Queue2", Properties: map[string]string{"location": "http://192.0.2.1:631/ipp/two", "device-id-model": "Other 9", "device-id-manufacturer": "Other"}}
	id := identify([]Advertisement{second, first})
	if id.Model != "Laser 42" || id.Manufacturer != "Example" || id.Name != "" {
		t.Fatal(id)
	}
	rawOther, queue := false, false
	for _, c := range id.Claims {
		if c.Value == "Other 9" {
			rawOther = true
		}
		if c.Field == "printer_name" && c.Value == "Queue name" {
			queue = true
		}
	}
	if !rawOther || !queue {
		t.Fatal(id.Claims)
	}
	local := identifyWithLocalModel([]Advertisement{first}, "Mac16,9")
	if local.Model != "Mac16,9" || local.Manufacturer != "Apple" {
		t.Fatal(local)
	}
	fallback := first
	fallback.Properties = map[string]string{"location": "http://192.0.2.1:631/ipp/one", "printer-make-and-model": "Example Laser", "printer-name": "Queue"}
	id = identify([]Advertisement{fallback, second})
	if id.Model != "Example Laser" || id.Manufacturer != "" {
		t.Fatal("mixed printer endpoint identity", id)
	}
}
func TestIPPIdentityRejectsUnsafeModel(t *testing.T) {
	ad := Advertisement{Protocol: "ipp", Service: "printer-attributes", Instance: "Queue", Properties: map[string]string{"device-id-model": "Bad\x00Model", "printer-make-and-model": "Safe model"}}
	id := identify([]Advertisement{ad})
	if id.Model != "Safe model" {
		t.Fatal(id)
	}
	ad.Service = "jobs"
	if identify([]Advertisement{ad}) != nil {
		t.Fatal("unrelated IPP operation produced identity")
	}
}
