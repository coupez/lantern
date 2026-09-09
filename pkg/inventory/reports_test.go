package inventory

import (
	"strings"
	"testing"
	"time"

	"github.com/coupez/lantern/pkg/android"
	"github.com/coupez/lantern/pkg/snmp"
)

func testMeta() Meta {
	return Meta{ID: "observation", SourceSHA256: strings.Repeat("a", 64), BindingSHA256: strings.Repeat("b", 64), ObservedAt: "2026-09-09T12:00:00Z"}
}

func TestFromAndroidRebuildsRawClaims(t *testing.T) {
	r := android.Report{Schema: 1, Source: "adb", Server: "127.0.0.1:5037", TransportID: 7, CollectedAt: "2026-09-09T12:00:00Z", Complete: true, Properties: android.Properties{Manufacturer: "Google", Model: "Pixel", Device: "husky", BuildFingerprint: "unknown"}, Claims: []android.Claim{{Field: "model", Value: "forged", Key: "x", Reference: "x"}}, Unavailable: []string{"forged"}}
	got, err := FromAndroid(testMeta(), r)
	if err != nil {
		t.Fatal(err)
	}
	if got.BindingAddress != "" || got.Status != "complete" || len(got.Claims) != 3 || got.Claims[1].Value != "Pixel" || got.Source != "adb://127.0.0.1:5037/transport/7" {
		t.Fatalf("%#v", got)
	}
}

func TestFromAndroidRejectsProvenanceAndFailedFields(t *testing.T) {
	base := android.Report{Schema: 1, Source: "adb", Server: "[::1]:5037", TransportID: 1, CollectedAt: "2026-09-09T12:00:00Z"}
	tests := map[string]android.Report{"schema": func() android.Report { x := base; x.Schema = 2; return x }(), "source": func() android.Report { x := base; x.Source = "fake"; return x }(), "server": func() android.Report { x := base; x.Server = "192.0.2.1:5037"; return x }(), "transport": func() android.Report { x := base; x.TransportID = 0; return x }(), "failed fields": func() android.Report { x := base; x.Properties.Model = "Pixel"; return x }()}
	for n, r := range tests {
		t.Run(n, func(t *testing.T) {
			if _, e := FromAndroid(testMeta(), r); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	m := testMeta()
	m.ObservedAt = "2026-09-09T12:00:01Z"
	if _, e := FromAndroid(m, base); e == nil {
		t.Fatal("timestamp mismatch")
	}
}

func snmpBase() snmp.Report {
	p := int64(0)
	return snmp.Report{Target: "192.0.2.1:161", EntityStatus: "complete", System: snmp.System{Description: "router", ObjectID: "1.3.6.1.4.1.9", Name: "edge"}, Entities: []snmp.Entity{{Index: 7, Class: 3, Parent: &p, Manufacturer: "Acme", Model: "R7"}}, Manufacturer: "Acme", Model: "R7", ManufacturerOID: mfgOID + ".7", ModelOID: modelOID + ".7"}
}

func TestFromSNMPRecomputesRootAndClaims(t *testing.T) {
	got, err := FromSNMP(testMeta(), snmpBase())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "complete" || got.TimeBasis != "owner-supplied" || got.BindingAddress != "" || len(got.Claims) != 7 || got.Claims[len(got.Claims)-2].Field != "model" {
		t.Fatalf("%#v", got)
	}
}

func TestFromSNMPRootSelectionRules(t *testing.T) {
	tests := map[string]func(*snmp.Report){
		"duplicate index": func(r *snmp.Report) { r.Entities = append(r.Entities, r.Entities[0]) },
		"wrong class":     func(r *snmp.Report) { r.Entities[0].Class = 0 },
		"missing parent":  func(r *snmp.Report) { r.Entities[0].Parent = nil },
		"ambiguous roots": func(r *snmp.Report) {
			p := int64(0)
			r.Entities = append(r.Entities, snmp.Entity{Index: 8, Class: 3, Parent: &p, Model: "R8"})
		},
		"truncated promotes": func(r *snmp.Report) { r.EntityStatus = "truncated" },
		"inconsistent model": func(r *snmp.Report) { r.Model = "forged" },
	}
	for n, mutate := range tests {
		t.Run(n, func(t *testing.T) {
			r := snmpBase()
			mutate(&r)
			if _, e := FromSNMP(testMeta(), r); e == nil {
				t.Fatal("accepted inconsistent report")
			}
		})
	}
}

func TestFromSNMPUnknownRawRootValidatedButOmitted(t *testing.T) {
	r := snmpBase()
	r.Entities[0].Model = "unknown"
	r.Model = "unknown"
	got, err := FromSNMP(testMeta(), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got.Claims {
		if c.Field == "model" {
			t.Fatal("unknown promoted", got)
		}
	}
}

func TestFromSNMPRootModelWithoutManufacturer(t *testing.T) {
	r := snmpBase()
	r.Entities[0].Manufacturer = ""
	r.Manufacturer, r.ManufacturerOID = "", ""
	got, err := FromSNMP(testMeta(), r)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got.Claims {
		if c.Field == "manufacturer" || c.Field == "component_manufacturer" {
			t.Fatal("invented manufacturer", got)
		}
	}
}

func TestMetaValidation(t *testing.T) {
	m := testMeta()
	m.ID = " bad "
	if _, e := FromSNMP(m, snmpBase()); e == nil {
		t.Fatal("bad ID")
	}
	m = testMeta()
	m.SourceSHA256 = strings.Repeat("A", 64)
	if _, e := FromSNMP(m, snmpBase()); e == nil {
		t.Fatal("uppercase hash")
	}
	m = testMeta()
	m.ObservedAt = time.Time{}.Format(time.RFC3339Nano)
	if _, e := FromSNMP(m, snmpBase()); e == nil {
		t.Fatal("zero time")
	}
}
