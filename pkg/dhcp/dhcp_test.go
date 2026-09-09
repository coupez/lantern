package dhcp

import (
	"encoding/binary"
	"strings"
	"testing"
)

func opt4(code byte, data string) []byte {
	return append([]byte{code, byte(len(data))}, []byte(data)...)
}
func packet4(main, file, sname []byte) []byte {
	b := make([]byte, 240)
	b[0], b[1], b[2] = 1, 1, 6
	copy(b[4:8], []byte{1, 2, 3, 4})
	copy(b[12:16], []byte{192, 0, 2, 2})
	copy(b[16:20], []byte{192, 0, 2, 9})
	copy(b[24:28], []byte{192, 0, 2, 1})
	copy(b[28:34], []byte{0, 1, 2, 3, 4, 5})
	copy(b[44:108], sname)
	copy(b[108:236], file)
	copy(b[236:], []byte{99, 130, 83, 99})
	return append(b, main...)
}
func TestParse4(t *testing.T) {
	main := append(opt4(53, "\x01"), opt4(12, "host-")...)
	main = append(main, opt4(55, "\x01\x03")...)
	main = append(main, opt4(61, "\x01client")...)
	main = append(main, 255)
	m, err := Parse4(packet4(main, nil, nil))
	if err != nil || m.Type != 1 || m.TransactionID != "01020304" || m.ClientHardwareAddress != "00:01:02:03:04:05" || m.ClientIP != "192.0.2.2" || m.AssignedIP != "192.0.2.9" || m.RelayIP != "192.0.2.1" || m.Hints.Hostname != "host-" || len(m.Hints.RequestedOptions) != 2 || string(m.Hints.ClientID) != "\x01client" {
		t.Fatal(m, err)
	}
}
func TestParse4RetainsOpaqueOptionalHints(t *testing.T) {
	main := append(opt4(53, "\x09"), opt4(12, "bad\x00name")...)
	main = append(main, opt4(60, "\xff\x00")...)
	main = append(main, 255)
	m, err := Parse4(packet4(main, nil, nil))
	if err != nil || m.Type != 9 || m.Hints.Hostname != "" || m.Hints.VendorClass != "" || len(m.Options) != 3 || string(m.Options[1].Data) != "bad\x00name" || string(m.Options[2].Data) != "\xff\x00" {
		t.Fatal(m, err)
	}
}
func TestParse4OverloadAndConcatenation(t *testing.T) {
	main := append(opt4(53, "\x01"), opt4(52, "\x03")...)
	main = append(main, opt4(60, "MS")...)
	main = append(main, 255)
	file := append(opt4(60, "FT"), 255)
	sname := append(opt4(12, "host"), 255)
	m, err := Parse4(packet4(main, file, sname))
	if err != nil || m.Hints.VendorClass != "MSFT" || m.Hints.Hostname != "host" || len(m.Options) != 5 {
		t.Fatal(m, err)
	}
}
func TestParse4RejectsMalformed(t *testing.T) {
	valid := packet4(append(opt4(53, "\x01"), 255), nil, nil)
	for _, b := range [][]byte{valid[:239], packet4([]byte{53, 2, 1, 2, 255}, nil, nil), packet4(append(opt4(53, "\x01"), opt4(52, "\x04")...), nil, nil), packet4(append(opt4(53, "\x01"), opt4(52, "\x01")...), []byte{12, 5, 'x', 255}, nil)} {
		if _, err := Parse4(b); err == nil {
			t.Fatal("accepted malformed DHCPv4")
		}
	}
	tooMany := []byte{}
	for i := 0; i < maxOptions+1; i++ {
		tooMany = append(tooMany, 1, 0)
	}
	tooMany = append(tooMany, 255)
	if _, err := Parse4(packet4(tooMany, nil, nil)); err == nil {
		t.Fatal("accepted too many DHCPv4 options")
	}
}

func opt6(code uint16, data []byte) []byte {
	b := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(b, code)
	binary.BigEndian.PutUint16(b[2:], uint16(len(data)))
	copy(b[4:], data)
	return b
}
func msg6(typ byte, opts ...[]byte) []byte {
	b := []byte{typ, 1, 2, 3}
	for _, o := range opts {
		b = append(b, o...)
	}
	return b
}
func relay6(typ byte, inner []byte) []byte {
	b := make([]byte, 34)
	b[0], b[1] = typ, 2
	copy(b[2:18], []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(b[18:34], []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	return append(b, opt6(9, inner)...)
}
func TestParse6AndRelay(t *testing.T) {
	fqdn := []byte{0, 4, 'h', 'o', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0}
	vendor := append([]byte{0, 0, 0, 42, 0, 3}, []byte("abc")...)
	inner := msg6(1, opt6(1, []byte{0, 1, 2}), opt6(6, []byte{0, 23, 0, 24}), opt6(39, fqdn), opt6(16, vendor))
	m, err := Parse6(relay6(12, inner))
	if err != nil || m.Type != 1 || m.TransactionID != "010203" || len(m.Relays) != 1 || m.Relays[0].Type != 12 || m.Relays[0].LinkAddress != "2001:db8::1" || m.Hints.Hostname != "host.local" || len(m.Hints.ClientID) != 3 || len(m.Hints.RequestedOptions) != 2 || m.Hints.EnterpriseID == nil || *m.Hints.EnterpriseID != 42 {
		t.Fatal(m, err)
	}
	unknown, err := Parse6(msg6(99))
	if err != nil || unknown.Type != 99 {
		t.Fatal(unknown, err)
	}
}
func TestParse6OmitsAmbiguousAndEmptyOptionalHints(t *testing.T) {
	m, err := Parse6(msg6(1,
		opt6(1, []byte{1}), opt6(1, []byte{2}),
		opt6(6, []byte{0, 23}), opt6(6, []byte{0, 24}),
		opt6(39, []byte{0}), opt6(39, []byte{0}),
		opt6(16, []byte{0, 0, 0, 1}), opt6(16, []byte{0, 0, 0, 2}),
	))
	if err != nil || len(m.Options) != 8 || len(m.Hints.ClientID) != 0 || len(m.Hints.RequestedOptions) != 0 || m.Hints.Hostname != "" || m.Hints.EnterpriseID != nil {
		t.Fatal(m, err)
	}
	flagsOnly, err := Parse6(msg6(1, opt6(39, []byte{0})))
	if err != nil || flagsOnly.Hints.Hostname != "" {
		t.Fatal(flagsOnly, err)
	}
}
func TestParse6RejectsMalformed(t *testing.T) {
	for _, b := range [][]byte{nil, {1, 2, 3}, msg6(0), msg6(1, []byte{0, 1, 0, 4, 1}), msg6(1, opt6(6, []byte{1})), msg6(1, opt6(16, []byte{0, 0, 0, 1, 0, 2, 1})), relay6(12, nil)} {
		if _, err := Parse6(b); err == nil {
			t.Fatal("accepted malformed DHCPv6")
		}
	}
	tooLongName := append([]byte{0}, make([]byte, 256)...)
	if _, err := Parse6(msg6(1, opt6(39, tooLongName))); err == nil {
		t.Fatal("accepted oversized DHCPv6 FQDN")
	}
	unsupportedName, err := Parse6(msg6(1, opt6(39, []byte{0, 0xc0, 1})))
	if err != nil || unsupportedName.Hints.Hostname != "" || len(unsupportedName.Options) != 1 {
		t.Fatal(unsupportedName, err)
	}
	deep := msg6(1)
	for i := 0; i < 5; i++ {
		deep = relay6(12, deep)
	}
	if _, err := Parse6(deep); err == nil {
		t.Fatal("accepted excessive relay depth")
	}
	too := msg6(1)
	for i := 0; i < maxOptions+1; i++ {
		too = append(too, opt6(100, nil)...)
	}
	if _, err := Parse6(too); err == nil {
		t.Fatal("accepted too many options")
	}
}
func FuzzParse4(f *testing.F) {
	f.Add(packet4(append(opt4(53, "\x01"), 255), nil, nil))
	f.Fuzz(func(t *testing.T, b []byte) { Parse4(b) })
}
func FuzzParse6(f *testing.F) {
	f.Add(msg6(1, opt6(1, []byte{1})))
	f.Fuzz(func(t *testing.T, b []byte) { Parse6(b) })
}
func TestPayloadBound(t *testing.T) {
	if _, err := Parse4([]byte(strings.Repeat("x", maxPayload+1))); err == nil {
		t.Fatal("v4 bound")
	}
	if _, err := Parse6([]byte(strings.Repeat("x", maxPayload+1))); err == nil {
		t.Fatal("v6 bound")
	}
}

func TestOpaqueUnicodeControlsRetainedWithoutHint(t *testing.T) {
	for _, value := range []string{"hello\u009b31m", "host\u202eevil"} {
		input := packet4(append(append(opt4(53, "\x01"), opt4(60, value)...), 255), nil, nil)
		m, err := Parse4(input)
		if err != nil || m.Hints.VendorClass != "" || string(m.Options[1].Data) != value {
			t.Fatalf("%+v %v", m, err)
		}
	}
}
