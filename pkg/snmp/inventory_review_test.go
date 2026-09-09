package snmp

import (
	"strconv"
	"testing"
)

func TestClassResponseRejectsFalseCompletion(t *testing.T) {
	for _, oid := range []string{classOID, classOID + ".0", classOID + ".2147483648", classOID + ".1.2", "1.3.6.1.2.1.47.1.1.1.1.4.7"} {
		if _, _, err := parseClasses([]Value{{OID: oid, Kind: "integer", Integer: 3}}); err == nil {
			t.Fatalf("malformed or earlier OID accepted as completion: %s", oid)
		}
	}
	for _, rows := range [][]Value{
		{{OID: classOID + ".7", Kind: "integer", Integer: 3}, {OID: classOID + ".6", Kind: "integer", Integer: 3}},
		{{OID: classOID + ".7", Kind: "integer", Integer: -3}},
		{{OID: classOID, Kind: "end-of-mib"}, {OID: classOID + ".7", Kind: "integer", Integer: 3}},
		{{OID: classOID + ".7", Kind: "integer", Integer: 3}, {OID: classOID + ".8", Kind: "end-of-mib"}},
	} {
		if _, _, err := parseClasses(rows); err == nil {
			t.Fatal("accepted invalid class response", rows)
		}
	}
}

func TestBulkFullResponseCanProveCompletion(t *testing.T) {
	// A server may fill all 33 repetitions by continuing beyond this column.
	rows := []Value{{OID: classOID + ".7", Kind: "integer", Integer: 3}}
	for i := 1; i <= 32; i++ {
		rows = append(rows, Value{OID: "1.3.6.1.2.1.47.1.1.1.1.6." + strconv.Itoa(i), Kind: "integer", Integer: -1})
	}
	entities, status, err := parseClasses(rows)
	if err != nil || status != "complete" || len(entities) != 1 {
		t.Fatal(entities, status, err)
	}
	rows = rows[:1]
	for i := 0; i < 32; i++ {
		rows = append(rows, Value{OID: classOID + ".7", Kind: "end-of-mib"})
	}
	entities, status, err = parseClasses(rows)
	if err != nil || status != "complete" || len(entities) != 1 {
		t.Fatal(entities, status, err)
	}
}

func TestScalarAndChassisEvidenceStaySeparate(t *testing.T) {
	values := []Value{{OID: sysNameOID, Kind: "no-such-instance"}, {OID: sysDescrOID, Kind: "octets", Bytes: []byte("Free-form router description")}, {OID: sysObjectOID, Kind: "oid", Text: "1.3.6.1.4.1.8072"}}
	system, missing, err := parseSystem(values)
	if err != nil || !missing || system.Description == "" || system.ObjectID == "" || system.Name != "" {
		t.Fatal(system, missing, err)
	}
	values[0].OID = sysDescrOID
	if _, _, err := parseSystem(values); err == nil {
		t.Fatal("exception masked duplicate OID")
	}
	zero := int64(0)
	r := Report{System: system, EntityStatus: "truncated", Entities: []Entity{{Index: 7, Class: 3, Parent: &zero, Model: "Example"}}}
	promote(&r)
	if r.Model != "" {
		t.Fatal("truncated inventory promoted", r)
	}
	r.EntityStatus = "complete"
	promote(&r)
	if r.Model != "Example" || r.ManufacturerOID != "" {
		t.Fatal("invented manufacturer source", r)
	}
	stackParent := int64(8)
	r = Report{EntityStatus: "complete", Entities: []Entity{{Index: 8, Class: 11}, {Index: 7, Class: 3, Parent: &stackParent, Model: "Member"}}}
	promote(&r)
	if r.Model != "" {
		t.Fatal("stack member promoted", r)
	}
}
