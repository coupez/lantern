package snmp

import (
	"net/netip"
	"strconv"
	"testing"
)

func TestInventoryTargetValidation(t *testing.T) {
	for _, raw := range []string{"127.0.0.1:161", "169.254.1.2:161", "[fe80::1%en0]:161", "[2001:db8::1%en0]:161"} {
		target, err := netip.ParseAddrPort(raw)
		if err != nil || !validTarget(target) {
			t.Fatalf("validTarget(%q) = false", raw)
		}
	}
	for _, raw := range []string{"0.0.0.0:161", "255.255.255.255:161", "[::]:161", "[fe80::1]:161", "[::ffff:192.0.2.1]:161"} {
		target, err := netip.ParseAddrPort(raw)
		if err == nil && validTarget(target) {
			t.Fatalf("validTarget(%q) = true", raw)
		}
	}
}

func TestParseClassesBoundsAndCompletion(t *testing.T) {
	rows := []Value{{OID: classOID + ".1", Kind: "integer", Integer: 3}, {OID: classOID + ".2", Kind: "integer", Integer: 9}, {OID: "1.3.6.1.2.1.47.1.1.1.1.6.1", Kind: "octets", Bytes: []byte("next column")}}
	entities, status, err := parseClasses(rows)
	if err != nil || status != "complete" || len(entities) != 2 {
		t.Fatal(entities, status, err)
	}
	rows = rows[:2]
	_, status, err = parseClasses(rows)
	if err != nil || status != "truncated" {
		t.Fatal(status, err)
	}
	rows = []Value{{OID: classOID, Kind: "end-of-mib"}}
	_, status, err = parseClasses(rows)
	if err != nil || status != "complete" {
		t.Fatal(status, err)
	}
	rows = make([]Value, 33)
	for i := range rows {
		rows[i] = Value{OID: classOID + "." + strconv.Itoa(i+1), Kind: "integer", Integer: 3}
	}
	entities, status, err = parseClasses(rows)
	if err != nil || status != "truncated" || len(entities) != 32 {
		t.Fatal(len(entities), status, err)
	}
}

func TestPromoteOnlyOneKnownRoot(t *testing.T) {
	parent := int64(0)
	report := Report{EntityStatus: "complete", Entities: []Entity{{Index: 7, Class: 3, Parent: &parent, Manufacturer: "Example", Model: "Router 7"}}}
	promote(&report)
	if report.Model != "Router 7" || report.Manufacturer != "Example" || report.ModelOID != modelOID+".7" || report.ManufacturerOID != mfgOID+".7" {
		t.Fatal(report)
	}
	second := int64(0)
	report.Entities = append(report.Entities, Entity{Index: 8, Class: 3, Parent: &second, Model: "Other"})
	report.Model, report.Manufacturer, report.ModelOID, report.ManufacturerOID = "", "", "", ""
	promote(&report)
	if report.Model != "" || report.Manufacturer != "" {
		t.Fatal("ambiguous roots promoted", report)
	}
}

func TestFillChassisRetainsAvailableFieldsWhenOneIsUnsupported(t *testing.T) {
	entities := []Entity{{Index: 1, Class: 3}}
	chassis := []int{0}
	oids := []string{parentOID + ".1", mfgOID + ".1", modelOID + ".1"}
	if err := fillChassis(entities, chassis, []Value{{OID: oids[0], Kind: "integer", Integer: 0}, {OID: oids[1], Kind: "octets", Bytes: []byte("Example")}, {OID: oids[2], Kind: "no-such-object"}}, oids); err != nil || entities[0].Manufacturer != "Example" || entities[0].Model != "" {
		t.Fatal("available field lost", entities, err)
	}
}

func TestFillChassisMissingParentSuppressesPromotion(t *testing.T) {
	entities := []Entity{{Index: 1, Class: 3}}
	chassis := []int{0}
	oids := []string{parentOID + ".1", mfgOID + ".1", modelOID + ".1"}
	values := []Value{{OID: oids[0], Kind: "no-such-object"}, {OID: oids[1], Kind: "octets", Bytes: []byte("Example")}, {OID: oids[2], Kind: "octets", Bytes: []byte("Router")}}
	if err := fillChassis(entities, chassis, values, oids); err != nil || entities[0].Parent != nil || entities[0].Model != "Router" {
		t.Fatal(entities, err)
	}
	report := Report{EntityStatus: "complete", Entities: entities}
	promote(&report)
	if report.Model != "" {
		t.Fatal("unknown parent promoted", report)
	}
}
