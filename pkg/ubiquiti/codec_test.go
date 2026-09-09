package ubiquiti

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func packet(version, command byte, fields ...[]byte) []byte {
	var body []byte
	for _, f := range fields {
		body = append(body, f...)
	}
	b := []byte{version, command, 0, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(len(body)))
	return append(b, body...)
}
func tlv(tag byte, value []byte) []byte {
	b := []byte{tag, byte(len(value) >> 8), byte(len(value))}
	return append(b, value...)
}

func TestQuery(t *testing.T) {
	for _, x := range []struct {
		v    byte
		want []byte
	}{{1, []byte{1, 0, 0, 0}}, {2, []byte{2, 8, 0, 0}}} {
		got, e := Query(x.v)
		if e != nil || !reflect.DeepEqual(got, x.want) {
			t.Fatal(got, e)
		}
		got[0] = 9
		again, _ := Query(x.v)
		if again[0] != x.v {
			t.Fatal("query aliases input")
		}
	}
	if _, e := Query(3); e == nil {
		t.Fatal("accepted version")
	}
}

func TestParseRetainsSortedDistinctModels(t *testing.T) {
	in := packet(2, 6, tlv(0x15, []byte(" UCK-v2\r\n")), tlv(1, []byte("SECRET-MAC")), tlv(0x03, []byte("firmware")), tlv(0x0b, []byte("fixture-switch")), tlv(0x14, []byte("legacy-model")), tlv(0x0c, []byte("platform")), tlv(0x16, []byte("5.9.29")))
	got, e := Parse(in)
	if e != nil {
		t.Fatal(e)
	}
	want := []Field{{3, "firmware"}, {11, "fixture-switch"}, {12, "platform"}, {20, "legacy-model"}, {21, "UCK-v2"}, {22, "5.9.29"}}
	if got.Version != 2 || got.Command != 6 || !reflect.DeepEqual(got.Fields, want) {
		t.Fatalf("%#v", got)
	}
	for _, f := range got.Fields {
		if strings.Contains(f.Value, "SECRET") {
			t.Fatal("private unknown field retained")
		}
	}
}

func TestParseVersionsAndEmptyRetained(t *testing.T) {
	for _, h := range [][2]byte{{1, 0}, {2, 6}, {2, 9}, {2, 11}} {
		got, e := Parse(packet(h[0], h[1], tlv(3, nil), tlv(12, []byte(" product "))))
		if e != nil || len(got.Fields) != 1 || got.Fields[0].Value != "product" {
			t.Fatal(h, got, e)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	valid := packet(1, 0, tlv(0x14, []byte("model")))
	tests := map[string][]byte{
		"short": {1, 0, 0}, "wrong version": packet(3, 0, tlv(20, []byte("x"))), "wrong command": packet(1, 6, tlv(20, []byte("x"))),
		"length": append(append([]byte(nil), valid...), 0), "field header": {1, 0, 0, 1, 20}, "field value": {1, 0, 0, 4, 20, 0, 2, 'x'},
		"duplicate": packet(1, 0, tlv(20, []byte("a")), tlv(20, []byte("b"))), "only unknown": packet(1, 0, tlv(1, []byte("mac"))),
		"control": packet(1, 0, tlv(20, []byte("a\nb"))), "format": packet(1, 0, tlv(20, []byte("a\xe2\x80\x8eb"))), "replacement": packet(1, 0, tlv(20, []byte("a\xef\xbf\xbdb"))), "utf8": packet(1, 0, tlv(20, []byte{0xff})),
		"large text": packet(1, 0, tlv(20, []byte(strings.Repeat("x", 1025)))), "datagram": make([]byte, 8193),
	}
	var many [][]byte
	for range 129 {
		many = append(many, tlv(1, nil))
	}
	tests["field count"] = packet(1, 0, many...)
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if got, e := Parse(in); e == nil {
				t.Fatalf("accepted %#v", got)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add(packet(1, 0, tlv(20, []byte("ER-X"))))
	f.Add(packet(2, 9, tlv(21, []byte("UCK-v2"))))
	f.Add(packet(2, 6, tlv(0x0b, []byte("fixture-switch"))))
	f.Add([]byte("x"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Parse(b) })
}
