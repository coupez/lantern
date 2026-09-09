package ipp

import (
	"encoding/binary"
	"strings"
	"testing"
)

func rec(t byte, n string, v []byte) []byte {
	b := []byte{t, byte(len(n) >> 8), byte(len(n))}
	b = append(b, n...)
	b = append(b, byte(len(v)>>8), byte(len(v)))
	return append(b, v...)
}
func resp(status uint16, id int32, r ...[]byte) []byte {
	return respCharset(status, id, "utf-8", r...)
}
func respCharset(status uint16, id int32, charset string, r ...[]byte) []byte {
	b := []byte{1, 1, byte(status >> 8), byte(status), 0, 0, 0, 0, 1}
	binary.BigEndian.PutUint32(b[4:8], uint32(id))
	b = append(b, rec(0x47, "attributes-charset", []byte(charset))...)
	b = append(b, rec(0x48, "attributes-natural-language", []byte("en"))...)
	for _, x := range r {
		b = append(b, x...)
	}
	return append(b, 3)
}
func lang(l, s string) []byte {
	b := []byte{0, byte(len(l))}
	b = append(b, l...)
	b = append(b, 0, byte(len(s)))
	return append(b, s...)
}
func TestRequest(t *testing.T) {
	b, e := Request("ipp://printer.local/ipp/print", 7)
	if e != nil || binary.BigEndian.Uint16(b[2:4]) != 0xb || b[len(b)-1] != 3 {
		t.Fatal(e, b)
	}
	for _, s := range []string{"utf-8", "printer-uri", "printer-make-and-model", "printer-name", "printer-device-id"} {
		if !strings.Contains(string(b), s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"", "http://x/", " ipp://x/", "ipp://u:p@x/"} {
		if _, e := Request(s, 1); e == nil {
			t.Fatal(s)
		}
	}
	if _, e := Request("ipp://x/", 0); e == nil {
		t.Fatal("zero id")
	}
}
func TestParse(t *testing.T) {
	b := resp(2, 9, []byte{4}, rec(0x41, "printer-make-and-model", []byte("Laser 7")), rec(0x36, "printer-name", lang("en", "Office")), rec(0x41, "printer-device-id", []byte("MFG:X;MDL:Y;")), rec(0x21, "ignored", []byte{0, 0, 0, 1}))
	b[0] = 2
	b[1] = 2
	g, e := ParseResponse(b, 9)
	if e != nil || len(g) != 3 || g["printer-name"] != "Office" {
		t.Fatal(g, e)
	}
}
func TestCollectionExtensionAndOutOfBand(t *testing.T) {
	c := rec(0x34, "other", nil)
	c = append(c, rec(0x4a, "", []byte("member"))...)
	c = append(c, rec(0x21, "", []byte{0, 0, 0, 1})...)
	c = append(c, rec(0x37, "", nil)...)
	ext := append([]byte{0x7f, 0, 1, 2, 3}, rec(0x41, "extension", []byte("x"))[1:]...)
	g, e := ParseResponse(resp(0, 1, []byte{4}, rec(0x12, "printer-name", nil), c, ext, rec(0x41, "printer-make-and-model", []byte("Model"))), 1)
	if e != nil || g["printer-name"] != "" || g["printer-make-and-model"] != "Model" {
		t.Fatal(g, e)
	}
}
func TestReject(t *testing.T) {
	valid := resp(0, 3, []byte{4}, rec(0x42, "printer-name", []byte("One")))
	cases := [][]byte{resp(0x400, 3), append(valid, 0), resp(0, 3, []byte{4}, rec(0x42, "printer-name", []byte("One")), rec(0x42, "", []byte("Two"))), resp(0, 3, []byte{4}, rec(0x34, "printer-name", nil), rec(0x4a, "", []byte("x")), rec(0x42, "", []byte("value")), rec(0x37, "", nil), rec(0x42, "printer-name", []byte("duplicate"))), resp(0, 3, []byte{4}, rec(0x41, "printer-name", []byte("wrong syntax"))), resp(0, 3, []byte{4}, rec(0x42, "printer-name", []byte("bad\x00"))), resp(0, 3, rec(0x47, "attributes-charset", []byte("utf-8"))), resp(0, 3, []byte{4}, rec(0x12, "printer-name", []byte{1})), resp(0, 3, []byte{4}, rec(0x34, "other", nil), rec(0x4a, "", []byte("member")), rec(0x37, "", nil))}
	for _, b := range cases {
		if _, e := ParseResponse(b, 3); e == nil {
			t.Fatalf("accepted %x", b)
		}
	}
	if _, e := ParseResponse(valid, 4); e == nil {
		t.Fatal("id")
	}
	if _, e := ParseResponse(valid[:len(valid)-1], 3); e == nil {
		t.Fatal("truncated")
	}
}
func TestCharsetAndBounds(t *testing.T) {
	b := resp(0, 1, []byte{4})
	i := strings.Index(string(b), "utf-8")
	copy(b[i:i+5], "latin")
	if _, e := ParseResponse(b, 1); e == nil {
		t.Fatal("charset")
	}
	if _, e := ParseResponse(respCharset(0, 1, "us-ascii", []byte{4}, rec(0x42, "printer-name", []byte("Café"))), 1); e == nil {
		t.Fatal("accepted non-ASCII text under us-ascii")
	}
	if _, e := ParseResponse(make([]byte, maxMessage+1), 1); e == nil {
		t.Fatal("size")
	}
	r := [][]byte{{4}}
	for i := 0; i <= maxAttributes; i++ {
		r = append(r, rec(0x21, "x", nil))
	}
	if _, e := ParseResponse(resp(0, 1, r...), 1); e == nil {
		t.Fatal("count")
	}
}

func nestedCollection(depth int) []byte {
	b := rec(0x34, "collection", nil)
	for i := 1; i < depth; i++ {
		b = append(b, rec(0x4a, "", []byte("member"))...)
		b = append(b, rec(0x34, "", nil)...)
	}
	b = append(b, rec(0x4a, "", []byte("leaf"))...)
	b = append(b, rec(0x21, "", []byte{0, 0, 0, 1})...)
	for i := 0; i < depth; i++ {
		b = append(b, rec(0x37, "", nil)...)
	}
	return b
}

func TestStrictFramingBoundaries(t *testing.T) {
	header := []byte{1, 1, 0, 0, 0, 0, 0, 1}
	namedBeforeGroup := append(append([]byte{}, header...), rec(0x42, "printer-name", []byte("bad"))...)
	namedBeforeGroup = append(namedBeforeGroup, resp(0, 1, []byte{4}, rec(0x42, "printer-name", []byte("good")))[8:]...)
	delimiterInCollection := rec(0x34, "other", nil)
	delimiterInCollection = append(delimiterInCollection, rec(0x4a, "", []byte("member"))...)
	delimiterInCollection = append(delimiterInCollection, []byte{4, 0, 0, 0, 0}...)
	delimiterInCollection = append(delimiterInCollection, rec(0x37, "", nil)...)
	malformedLanguage := []byte{0, 3, 'e', 'n', 0, 1, 'x'}
	oversized := strings.Repeat("x", maxField+1)
	cases := map[string][]byte{
		"named-before-group":      namedBeforeGroup,
		"delimiter-in-collection": resp(0, 1, []byte{4}, delimiterInCollection, rec(0x41, "printer-make-and-model", []byte("Model"))),
		"depth-nine":              resp(0, 1, []byte{4}, nestedCollection(9)),
		"truncated-extension":     resp(0, 1, []byte{4}, []byte{0x7f, 0, 1}),
		"malformed-language":      resp(0, 1, []byte{4}, rec(0x36, "printer-name", malformedLanguage)),
		"oversized-field":         resp(0, 1, []byte{4}, rec(0x42, "printer-name", []byte(oversized))),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseResponse(b, 1); err == nil {
				t.Fatal("accepted malformed response")
			}
		})
	}
	t.Run("depth-eight", func(t *testing.T) {
		got, err := ParseResponse(resp(0, 1, []byte{4}, nestedCollection(8), rec(0x42, "printer-name", []byte("After"))), 1)
		if err != nil || got["printer-name"] != "After" {
			t.Fatal(got, err)
		}
	})
}

func FuzzParseResponse(f *testing.F) {
	f.Add(resp(0, 1, []byte{4}, rec(0x41, "printer-make-and-model", []byte("Model"))))
	f.Add([]byte{1, 1, 0, 0, 0, 0, 0, 1, 3})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseResponse(b, 1) })
}
