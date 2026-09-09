package snmp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func responseFor(community string, id int32, values ...[]byte) []byte {
	var vbs []byte
	for i, value := range values {
		oid, _ := encOID(fmt.Sprintf("1.3.6.1.2.1.1.%d.0", i+1))
		vbs = append(vbs, tlv(0x30, append(oid, value...))...)
	}
	pdu := append(append(encInt(int64(id)), encInt(0)...), append(encInt(0), tlv(0x30, vbs)...)...)
	return tlv(0x30, append(append(encInt(1), tlv(4, []byte(community))...), tlv(0xa2, pdu)...))
}

func TestCredentialsRedacted(t *testing.T) {
	if _, err := NewCredentials(""); err == nil {
		t.Fatal("empty accepted")
	}
	c, err := NewCredentials("private-secret")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(c)
	for _, rendered := range []string{c.String(), fmt.Sprintf("%#v", c), string(b)} {
		if strings.Contains(rendered, "private-secret") || !strings.Contains(rendered, "REDACTED") {
			t.Fatal(rendered)
		}
	}
	if _, err := ParseResponse(responseFor("wrong", 7), c, 7); err == nil || strings.Contains(err.Error(), "private-secret") {
		t.Fatal(err)
	}
}

func TestBuildRequests(t *testing.T) {
	c, _ := NewCredentials("public")
	get, err := BuildGet(c, 9, []string{"1.3.6.1.2.1.1.1.0", "2.999.4294967295"})
	if err != nil || !bytes.Contains(get, []byte{0xa0}) {
		t.Fatal(err)
	}
	bulk, err := BuildBulk(c, 10, "1.3.6.1.2.1", 33)
	if err != nil || !bytes.Contains(bulk, []byte{0xa5}) {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "1", "3.1", "1.40", "1.03", "1.x"} {
		if _, err := BuildGet(c, 1, []string{bad}); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := BuildBulk(c, 1, "1.3", 34); err == nil {
		t.Fatal("bulk limit")
	}
}

func TestParseResponseValuesAndOwnership(t *testing.T) {
	c, _ := NewCredentials("public")
	in := responseFor("public", 12, tlv(4, []byte("camera")), encInt(-129), func() []byte { x, _ := encOID("2.999.4294967295"); return x }(), []byte{0x80, 0})
	got, err := ParseResponse(in, c, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0].Kind != "octets" || string(got[0].Bytes) != "camera" || got[1].Integer != -129 || got[2].Text != "2.999.4294967295" || got[3].Kind != "no-such-object" {
		t.Fatalf("%#v", got)
	}
	in[len(in)-1] = 9
	if string(got[0].Bytes) != "camera" {
		t.Fatal("bytes alias input")
	}
}

func TestParseRejectsFramingAndBounds(t *testing.T) {
	c, _ := NewCredentials("public")
	good := responseFor("public", 1, tlv(5, nil))
	tests := map[string][]byte{
		"trailing":          append(append([]byte(nil), good...), 0),
		"wrong id":          responseFor("public", 2, tlv(5, nil)),
		"unknown value":     responseFor("public", 1, tlv(0x45, []byte{1, 2, 3, 4})),
		"indefinite length": {0x30, 0x80, 0, 0},
		"oversized":         make([]byte, maxMessage+1),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseResponse(in, c, 1); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestPermittedPaddedDefiniteLength(t *testing.T) {
	c, _ := NewCredentials("public")
	good := responseFor("public", 1, tlv(5, nil))
	r := reader{b: good}
	_, content, err := r.readTLV()
	if err != nil {
		t.Fatal(err)
	}
	padded := append([]byte{0x30, 0x84, 0, 0, 0, byte(len(content))}, content...)
	if _, err := ParseResponse(padded, c, 1); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationValues(t *testing.T) {
	c, _ := NewCredentials("public")
	in := responseFor("public", 1,
		tlv(0x40, []byte{192, 0, 2, 1}),
		tlv(0x41, []byte{0, 0xff, 0xff, 0xff, 0xff}),
		tlv(0x42, []byte{1}), tlv(0x43, []byte{0x7f}),
		tlv(0x46, []byte{0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		tlv(0x44, []byte{1, 2, 3}),
	)
	got, err := ParseResponse(in, c, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ip-address", "counter32", "gauge32", "time-ticks", "counter64", "opaque"}
	for i := range want {
		if got[i].Kind != want[i] || len(got[i].Bytes) == 0 {
			t.Fatalf("%d: %#v", i, got[i])
		}
	}
	bad := [][]byte{tlv(0x40, []byte{1, 2, 3}), tlv(0x41, []byte{0x80}), tlv(0x42, []byte{0, 1}), tlv(0x43, []byte{0, 1, 2, 3, 4, 5}), tlv(0x46, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9})}
	for i, v := range bad {
		if _, err := ParseResponse(responseFor("public", 1, v), c, 1); err == nil {
			t.Fatalf("accepted application value %d", i)
		}
	}
}

func TestOversizedGetRejectedBeforeWrapping(t *testing.T) {
	c, _ := NewCredentials(strings.Repeat("c", 255))
	oid := "2." + strings.TrimSuffix(strings.Repeat("4294967295.", 127), ".")
	oids := make([]string, 128)
	for i := range oids {
		oids[i] = oid
	}
	if _, err := BuildGet(c, 1, oids); err == nil {
		t.Fatal("oversized request accepted")
	}
}

func TestOIDCanonicalBase128(t *testing.T) {
	if _, err := decOID([]byte{0x80, 0x2b}); err == nil {
		t.Fatal("accepted overlong first combined arc")
	}
	if got, err := decOID([]byte{0x88, 0x37, 0x8f, 0xff, 0xff, 0xff, 0x7f}); err != nil || got != "2.999.4294967295" {
		t.Fatal(got, err)
	}
}

func FuzzParseResponse(f *testing.F) {
	c, _ := NewCredentials("public")
	f.Add(responseFor("public", 1, tlv(4, []byte("x"))))
	f.Add([]byte("x"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseResponse(b, c, 1) })
}
