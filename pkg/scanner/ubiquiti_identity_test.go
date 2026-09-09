package scanner

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/coupez/lantern/pkg/ubiquiti"
)

func ubiquitiObservation(version uint8, fields ...ubiquiti.Field) ubiquiti.Observation {
	return ubiquiti.Observation{Version: version, Command: 6, Fields: fields}
}

func TestUbiquitiHitUsesSocketAddressAndProtocolTags(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.8")
	hit := ubiquitiHit(ip, ubiquitiObservation(2,
		ubiquiti.Field{Tag: 0x03, Value: "build-7"}, ubiquiti.Field{Tag: 0x0c, Value: "platform-1"},
		ubiquiti.Field{Tag: 0x14, Value: "Model A"}, ubiquiti.Field{Tag: 0x15, Value: "Model B"}, ubiquiti.Field{Tag: 0x16, Value: "1.2.3"},
		ubiquiti.Field{Tag: 0x99, Value: "not-retained"},
	))
	if hit.IP != ip || hit.Evidence != "ubiquiti" || len(hit.Ads) != 1 {
		t.Fatalf("%#v", hit)
	}
	ad := hit.Ads[0]
	if ad.Protocol != "ubiquiti" || ad.Service != ubiquitiDiscoveryService || ad.Instance != "192.0.2.8#v2" || ad.Port != 10001 || ad.Properties["location"] != "udp://192.0.2.8:10001" || ad.Properties["protocol_version"] != "2" {
		t.Fatalf("%#v", ad)
	}
	if ad.Properties["0x03"] != "build-7" || ad.Properties["0x0c"] != "platform-1" || ad.Properties["0x14"] != "Model A" || ad.Properties["0x15"] != "Model B" || ad.Properties["0x16"] != "1.2.3" || ad.Properties["0x99"] != "" {
		t.Fatalf("%#v", ad.Properties)
	}
	if got := ubiquitiHit(netip.MustParseAddr("224.0.0.1"), ubiquitiObservation(1, ubiquiti.Field{Tag: 0x14, Value: "ignored"})); !reflect.DeepEqual(got, discoveryHit{}) {
		t.Fatalf("accepted invalid socket peer: %#v", got)
	}
}

func TestUbiquitiIdentityPreservesConflictsAndSourcePairing(t *testing.T) {
	first := ubiquitiHit(netip.MustParseAddr("192.0.2.8"), ubiquitiObservation(1,
		ubiquiti.Field{Tag: 0x14, Value: "Model V1"}, ubiquiti.Field{Tag: 0x16, Value: "1.0.0"}, ubiquiti.Field{Tag: 0x03, Value: "build-v1"},
	)).Ads[0]
	second := ubiquitiHit(netip.MustParseAddr("192.0.2.8"), ubiquitiObservation(2,
		ubiquiti.Field{Tag: 0x15, Value: "Model V2"}, ubiquiti.Field{Tag: 0x16, Value: "2.0.0"}, ubiquiti.Field{Tag: 0x0c, Value: "Platform 2"},
	)).Ads[0]
	one, two := identify([]Advertisement{first, second}), identify([]Advertisement{second, first})
	if !reflect.DeepEqual(one, two) || one == nil || one.Model != "Model V1" || one.Manufacturer != "Ubiquiti" || one.Firmware != "" || one.FirmwareVersion != "1.0.0" {
		t.Fatalf("one=%#v two=%#v", one, two)
	}
	models, manufacturers := map[string]bool{}, map[string]bool{}
	for _, claim := range one.Claims {
		if claim.Reference != ubiquiti.ProtocolReference {
			t.Fatalf("missing protocol reference: %#v", claim)
		}
		if claim.Field == "model" {
			models[claim.Value] = true
		}
		if claim.Field == "manufacturer" {
			manufacturers[claim.Source] = true
		}
	}
	if !models["Model V1"] || !models["Model V2"] || len(manufacturers) != 2 {
		t.Fatalf("claims=%#v", one.Claims)
	}
}

func TestUbiquitiPlatformDoesNotBecomeModel(t *testing.T) {
	ad := ubiquitiHit(netip.MustParseAddr("192.0.2.8"), ubiquitiObservation(2, ubiquiti.Field{Tag: 0x0c, Value: "Edge platform"})).Ads[0]
	id := identify([]Advertisement{ad})
	if id == nil || id.Model != "" || id.Manufacturer != "" || id.Firmware != "" || id.FirmwareVersion != "" {
		t.Fatalf("platform invented display identity: %#v", id)
	}
	if len(id.Claims) != 2 || id.Claims[0].Field != "manufacturer" || id.Claims[1].Field != "platform" {
		t.Fatalf("platform claim not retained: %#v", id.Claims)
	}
}

func TestUbiquitiSelectedModelDoesNotInheritUnrelatedManufacturer(t *testing.T) {
	ubiquitiAd := ubiquitiHit(netip.MustParseAddr("192.0.2.8"), ubiquitiObservation(2, ubiquiti.Field{Tag: 0x14, Value: "U6-Pro"})).Ads[0]
	printerAd := Advertisement{Protocol: "mdns", Service: "_ipp._tcp", Instance: "Unrelated printer._ipp._tcp.local", Properties: map[string]string{"usb_mfg": "Acme Printer Co."}}
	id := identify([]Advertisement{printerAd, ubiquitiAd})
	if id == nil || id.Model != "U6-Pro" || id.Manufacturer != "Ubiquiti" {
		t.Fatalf("unrelated manufacturer paired with Ubiquiti model: %#v", id)
	}
	foundAcme, foundUbiquiti := false, false
	for _, claim := range id.Claims {
		if claim.Field != "manufacturer" {
			continue
		}
		foundAcme = foundAcme || claim.Value == "Acme Printer Co."
		foundUbiquiti = foundUbiquiti || claim.Value == "Ubiquiti"
	}
	if !foundAcme || !foundUbiquiti {
		t.Fatalf("competing manufacturer claims lost: %#v", id.Claims)
	}
}

func TestUbiquitiUnknownModelRemainsRawEvidence(t *testing.T) {
	ad := ubiquitiHit(netip.MustParseAddr("192.0.2.8"), ubiquitiObservation(2, ubiquiti.Field{Tag: 0x15, Value: "UNKNOWN"})).Ads[0]
	id := identify([]Advertisement{ad})
	if ad.Properties["0x15"] != "UNKNOWN" || id != nil && id.Model != "" {
		t.Fatal(id, ad)
	}
}

func TestUbiquitiReportedHostname(t *testing.T) {
	ad := ubiquitiHit(netip.MustParseAddr("192.0.2.8"), ubiquitiObservation(2, ubiquiti.Field{Tag: 0x0b, Value: "fixture-switch"})).Ads[0]
	id := identify([]Advertisement{ad})
	if id == nil || id.Name != "fixture-switch" || id.Model != "" {
		t.Fatal(id)
	}
	for _, c := range id.Claims {
		if c.Field == "name" && (c.Key != "0x0b" || c.Basis != "advertised" || c.Reference == "") {
			t.Fatal(c)
		}
	}
}
