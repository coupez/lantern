package observe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/coupez/lantern/pkg/capture"
)

func message4() []byte {
	b := make([]byte, 240)
	b[0] = 2
	b[1] = 1
	b[2] = 6
	copy(b[4:8], []byte{1, 2, 3, 4})
	copy(b[16:20], []byte{192, 0, 2, 9})
	copy(b[28:34], []byte{2, 1, 2, 3, 4, 5})
	copy(b[236:], []byte{99, 130, 83, 99})
	return append(b, 53, 1, 2, 55, 3, 1, 3, 6, 255)
}
func udp(src, dst uint16, payload []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b, src)
	binary.BigEndian.PutUint16(b[2:], dst)
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(payload)))
	return append(b, payload...)
}
func ipv4(payload []byte) []byte {
	b := make([]byte, 20)
	b[0] = 0x45
	b[8] = 61
	b[9] = 17
	binary.BigEndian.PutUint16(b[2:], uint16(20+len(payload)))
	copy(b[12:16], []byte{192, 0, 2, 1})
	copy(b[16:20], []byte{255, 255, 255, 255})
	return append(b, payload...)
}
func ipv6(payload []byte, next byte) []byte {
	b := make([]byte, 40)
	b[0] = 0x60
	b[6] = next
	b[7] = 64
	binary.BigEndian.PutUint16(b[4:], uint16(len(payload)))
	b[8] = 0xfe
	b[9] = 0x80
	b[23] = 1
	b[24] = 0xff
	b[25] = 2
	b[39] = 2
	return append(b, payload...)
}
func ethernet(payload []byte, typ uint16) []byte {
	b := make([]byte, 14)
	copy(b[6:12], []byte{2, 9, 8, 7, 6, 5})
	binary.BigEndian.PutUint16(b[12:], typ)
	return append(b, payload...)
}
func pcap(packets ...[]byte) []byte {
	b := new(bytes.Buffer)
	for _, x := range []any{uint32(0xa1b2c3d4), uint16(2), uint16(4), uint32(0), uint32(0), uint32(65535), uint32(1)} {
		binary.Write(b, binary.LittleEndian, x)
	}
	for _, p := range packets {
		for _, x := range []uint32{1700000000, 123456, uint32(len(p)), uint32(len(p))} {
			binary.Write(b, binary.LittleEndian, x)
		}
		b.Write(p)
	}
	return b.Bytes()
}
func TestDecodeSourceIsNotClient(t *testing.T) {
	wire := ethernet(ipv4(udp(67, 68, message4())), 0x0800)
	stamp := time.Unix(1700000000, 123456000)
	o, err := Decode(capture.Packet{Data: wire, LinkType: 1, Section: 2, Interface: 7, Timestamp: stamp, Truncated: true})
	if err != nil {
		t.Fatal(err)
	}
	if o.SourceIP != "192.0.2.1" || o.EthernetSource != "02:09:08:07:06:05" || o.Message.ClientHardwareAddress != "02:01:02:03:04:05" || o.Message.AssignedIP != "192.0.2.9" {
		t.Fatalf("source/client conflated: %+v", o)
	}
	if o.Section != 2 || o.Interface != 7 || !o.Timestamp.Equal(stamp) || !o.CapturedTruncated || o.IPHopLimit != 61 {
		t.Fatalf("lost provenance: %+v", o)
	}
	if !reflect.DeepEqual(o.Message.Hints.RequestedOptions, []uint16{1, 3, 6}) {
		t.Fatal(o.Message.Hints)
	}
}
func TestDecodeEncapsulations(t *testing.T) {
	ip := ipv4(udp(67, 68, message4()))
	sll := make([]byte, 16)
	binary.BigEndian.PutUint16(sll[14:], 0x0800)
	sll2 := make([]byte, 20)
	binary.BigEndian.PutUint16(sll2, 0x0800)
	tags := append([]byte{0, 42, 0x81, 0, 0, 7, 8, 0}, ip...)
	cases := []struct {
		link  uint16
		data  []byte
		vlans []uint16
	}{
		{101, ip, nil}, {228, ip, nil}, {0, append([]byte{2, 0, 0, 0}, ip...), nil}, {0, append([]byte{0, 0, 0, 2}, ip...), nil},
		{108, append([]byte{0, 0, 0, 2}, ip...), nil}, {113, append(sll, ip...), nil}, {276, append(sll2, ip...), nil},
		{1, ethernet(tags, 0x88a8), []uint16{42, 7}},
	}
	for _, tt := range cases {
		o, err := Decode(capture.Packet{LinkType: tt.link, Data: tt.data})
		if err != nil || o.Message.Type != 2 || !reflect.DeepEqual(o.VLANs, tt.vlans) {
			t.Fatalf("link %d: %+v %v", tt.link, o, err)
		}
	}
}
func TestDecodeIPv6RelayAndExtensions(t *testing.T) {
	inner := []byte{1, 1, 2, 3, 0, 6, 0, 4, 0, 23, 0, 24}
	relay := make([]byte, 34)
	relay[0] = 12
	relay[1] = 1
	relay[2] = 0x20
	relay[3] = 1
	relay[17] = 1
	relay[18] = 0xfe
	relay[19] = 0x80
	relay[33] = 9
	relay = append(relay, 0, 9, 0, byte(len(inner)))
	relay = append(relay, inner...)
	// Hop-by-hop -> atomic fragment -> UDP.
	exts := []byte{44, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 1}
	wire := ipv6(append(exts, udp(547, 547, relay)...), 0)
	o, err := Decode(capture.Packet{LinkType: 229, Data: wire})
	if err != nil || o.SourceIP != "fe80::1" || o.Message.Version != 6 || o.Message.Type != 1 || o.IPHopLimit != 64 || len(o.Message.Relays) != 1 || o.Message.Relays[0].PeerAddress != "fe80::9" {
		t.Fatalf("%+v %v", o, err)
	}
	if o.Message.ClientHardwareAddress != "" {
		t.Fatal("invented hardware identity")
	}
	wire[40+8+3] = 1
	if _, err := Decode(capture.Packet{LinkType: 229, Data: wire}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}
func TestDecodeRejectsInvalidLengthsAndFragments(t *testing.T) {
	good := ipv4(udp(67, 68, message4()))
	for _, mutate := range []func([]byte){
		func(b []byte) { b[0] = 0x44 }, func(b []byte) { binary.BigEndian.PutUint16(b[2:], 65535) },
		func(b []byte) { binary.BigEndian.PutUint16(b[24:], 7) }, func(b []byte) { binary.BigEndian.PutUint16(b[24:], 65535) },
	} {
		b := append([]byte(nil), good...)
		mutate(b)
		if _, err := Decode(capture.Packet{LinkType: 101, Data: b}); !errors.Is(err, ErrMalformed) {
			t.Fatal(err)
		}
	}
	good[6] = 0x20
	if _, err := Decode(capture.Packet{LinkType: 101, Data: good}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := Decode(capture.Packet{LinkType: 999, Data: good}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := Decode(capture.Packet{LinkType: 101, Data: ipv4(udp(68, 999, message4()))}); !errors.Is(err, ErrNotDHCP) {
		t.Fatal(err)
	}
}
func TestReadPartialCapture(t *testing.T) {
	wire := ethernet(ipv4(udp(67, 68, message4())), 0x0800)
	other := ethernet(make([]byte, 28), 0x0806)
	fragmented := append([]byte(nil), wire...)
	fragmented[14+6] = 0x20
	input := pcap(wire, other, fragmented, []byte{1})
	var got []Observation
	summary, err := Read(context.Background(), bytes.NewReader(input), func(o Observation) error { got = append(got, o); return nil })
	if err != nil || len(got) != 1 || summary.Capture.Packets != 4 || summary.Ignored != 1 || summary.Unsupported != 1 || summary.Malformed != 1 || !summary.Incomplete {
		t.Fatalf("%+v %v", summary, err)
	}
	if got[0].Packet != 1 || got[0].Timestamp.Unix() != 1700000000 || got[0].Timestamp.Nanosecond() != 123456000 {
		t.Fatal(got)
	}
	summary, err = Read(context.Background(), bytes.NewReader(append(pcap(wire), 1, 2)), nil)
	if err == nil || summary.Observations != 1 || !summary.Incomplete || summary.Error == "" {
		t.Fatalf("%+v %v", summary, err)
	}
	stop := errors.New("stop")
	_, err = Read(context.Background(), bytes.NewReader(pcap(wire)), func(Observation) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatal(err)
	}
}
func FuzzDecode(f *testing.F) {
	f.Add(uint16(1), ethernet(ipv4(udp(67, 68, message4())), 0x0800))
	f.Add(uint16(229), ipv6(udp(546, 547, []byte{1, 1, 2, 3}), 17))
	f.Fuzz(func(t *testing.T, link uint16, b []byte) { Decode(capture.Packet{LinkType: link, Data: b}) })
}
