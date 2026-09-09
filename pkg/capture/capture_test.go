package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"
)

func put16(b []byte, o binary.ByteOrder, v uint16) { o.PutUint16(b, v) }
func put32(b []byte, o binary.ByteOrder, v uint32) { o.PutUint32(b, v) }
func put64(b []byte, o binary.ByteOrder, v uint64) { o.PutUint64(b, v) }

func classic(o binary.ByteOrder, nano bool, packets ...[]byte) []byte {
	b := make([]byte, 24)
	magic := []byte{0xd4, 0xc3, 0xb2, 0xa1}
	if o == binary.BigEndian {
		magic = []byte{0xa1, 0xb2, 0xc3, 0xd4}
	}
	if nano && o == binary.LittleEndian {
		magic = []byte{0x4d, 0x3c, 0xb2, 0xa1}
	}
	if nano && o == binary.BigEndian {
		magic = []byte{0xa1, 0xb2, 0x3c, 0x4d}
	}
	copy(b, magic)
	put16(b[4:], o, 2)
	put16(b[6:], o, 4)
	put32(b[16:], o, maxPacket)
	put32(b[20:], o, 1)
	for i, p := range packets {
		h := make([]byte, 16)
		put32(h, o, uint32(10+i))
		put32(h[4:], o, 123456)
		put32(h[8:], o, uint32(len(p)))
		put32(h[12:], o, uint32(len(p)+i))
		b = append(b, h...)
		b = append(b, p...)
	}
	return b
}

func block(o binary.ByteOrder, typ uint32, body []byte) []byte {
	total := uint32(12 + len(body))
	b := make([]byte, total)
	put32(b, o, typ)
	put32(b[4:], o, total)
	copy(b[8:], body)
	put32(b[len(b)-4:], o, total)
	return b
}

func shb(o binary.ByteOrder) []byte {
	body := make([]byte, 16)
	put32(body, o, 0x1a2b3c4d)
	put16(body[4:], o, 1)
	put16(body[6:], o, 0)
	put64(body[8:], o, ^uint64(0))
	return block(o, 0x0a0d0d0a, body)
}

func option(o binary.ByteOrder, code uint16, value []byte) []byte {
	b := make([]byte, 4+(len(value)+3)&^3)
	put16(b, o, code)
	put16(b[2:], o, uint16(len(value)))
	copy(b[4:], value)
	return b
}

func idb(o binary.ByteOrder, link uint16, snap uint32, opts ...[]byte) []byte {
	body := make([]byte, 8)
	put16(body, o, link)
	put32(body[4:], o, snap)
	for _, v := range opts {
		body = append(body, v...)
	}
	return block(o, 1, body)
}

func epb(o binary.ByteOrder, iface uint32, ticks uint64, data []byte, original uint32) []byte {
	body := make([]byte, 20+(len(data)+3)&^3)
	put32(body, o, iface)
	put32(body[4:], o, uint32(ticks>>32))
	put32(body[8:], o, uint32(ticks))
	put32(body[12:], o, uint32(len(data)))
	put32(body[16:], o, original)
	copy(body[20:], data)
	return block(o, 6, body)
}

func obsoletePacket(o binary.ByteOrder, iface uint16, ticks uint64, data []byte, original uint32) []byte {
	body := make([]byte, 20+(len(data)+3)&^3)
	put16(body, o, iface)
	put16(body[2:], o, 0xffff)
	put32(body[4:], o, uint32(ticks>>32))
	put32(body[8:], o, uint32(ticks))
	put32(body[12:], o, uint32(len(data)))
	put32(body[16:], o, original)
	copy(body[20:], data)
	return block(o, 2, body)
}

func TestClassicPCAPFormatsAndOwnership(t *testing.T) {
	for _, tc := range []struct {
		o    binary.ByteOrder
		nano bool
	}{{binary.LittleEndian, false}, {binary.BigEndian, false}, {binary.LittleEndian, true}, {binary.BigEndian, true}} {
		input := classic(tc.o, tc.nano, []byte{1, 2}, []byte{3})
		var got []Packet
		stats, err := Read(context.Background(), bytes.NewReader(input), func(p Packet) error { got = append(got, p); return nil })
		if err != nil || stats != (Stats{Format: "pcap", Packets: 2, Bytes: int64(len(input))}) {
			t.Fatal(stats, err)
		}
		wantNsec := 123456000
		if tc.nano {
			wantNsec = 123456
		}
		if got[0].Timestamp != time.Unix(10, int64(wantNsec)).UTC() || got[0].Section != 0 || got[0].Interface != 0 || got[0].LinkType != 1 || got[0].OriginalLength != 2 || got[0].Truncated || !reflect.DeepEqual(got[0].Data, []byte{1, 2}) || !got[1].Truncated {
			t.Fatal(got)
		}
		got[0].Data[0] = 9
		if got[1].Data[0] != 3 {
			t.Fatal("callback packets share data")
		}
	}
}

func TestPCAPNGSectionsInterfacesAndTimestamps(t *testing.T) {
	le, be := binary.LittleEndian, binary.BigEndian
	res := option(le, 9, []byte{0x83}) // 2^-3 second ticks
	off := make([]byte, 8)
	put64(off, le, uint64(2))
	input := append(shb(le), idb(le, 1, 64, res, option(le, 14, off))...)
	input = append(input, epb(le, 0, 13, []byte{1, 2, 3}, 5)...)
	input = append(input, shb(be)...)
	input = append(input, idb(be, 101, 0)...)
	input = append(input, epb(be, 0, 2_500_000, []byte{4}, 1)...)
	var got []Packet
	stats, err := Read(context.Background(), bytes.NewReader(input), func(p Packet) error { got = append(got, p); return nil })
	if err != nil || stats.Packets != 2 || stats.Bytes != int64(len(input)) {
		t.Fatal(stats, err)
	}
	if got[0].Section != 0 || got[0].Interface != 0 || got[0].LinkType != 1 || got[0].Timestamp != time.Unix(3, 625_000_000).UTC() || !got[0].Truncated {
		t.Fatal(got[0])
	}
	if got[1].Section != 1 || got[1].LinkType != 101 || got[1].Timestamp != time.Unix(2, 500_000_000).UTC() {
		t.Fatal(got[1])
	}
}

func TestPCAPNGSimplePacket(t *testing.T) {
	o := binary.LittleEndian
	body := make([]byte, 8)
	put32(body, o, 7)
	copy(body[4:], []byte{1, 2, 3})
	input := append(shb(o), idb(o, 1, 3)...)
	input = append(input, block(o, 3, body)...)
	var got Packet
	_, err := Read(context.Background(), bytes.NewReader(input), func(p Packet) error { got = p; return nil })
	if err != nil || !reflect.DeepEqual(got.Data, []byte{1, 2, 3}) || got.OriginalLength != 7 || !got.Truncated || !got.Timestamp.IsZero() {
		t.Fatal(got, err)
	}
}

func TestPCAPNGObsoletePacketAndUnspecifiedPadding(t *testing.T) {
	o := binary.LittleEndian
	packet := obsoletePacket(o, 0, 1_500_000, []byte{1}, 2)
	packet[8+20+1] = 0xa5 // Packet padding has no specified value.
	input := append(shb(o), idb(o, 1, 64, option(o, 2, []byte{1}))...)
	// The three bytes following the one-byte option value are unspecified too.
	input[len(shb(o))+8+8+4+1] = 0x5a
	input = append(input, packet...)
	var got Packet
	stats, err := Read(context.Background(), bytes.NewReader(input), func(p Packet) error { got = p; return nil })
	if err != nil || stats.Packets != 1 || !reflect.DeepEqual(got.Data, []byte{1}) || !got.Truncated || got.Timestamp != time.Unix(1, 500_000_000).UTC() {
		t.Fatal(got, stats, err)
	}
}

func TestErrorsCancellationAndCallback(t *testing.T) {
	callbackErr := errors.New("stop")
	stats, err := Read(context.Background(), bytes.NewReader(classic(binary.LittleEndian, false, []byte{1})), func(Packet) error { return callbackErr })
	if !errors.Is(err, callbackErr) || stats.Packets != 1 {
		t.Fatal(stats, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Read(ctx, bytes.NewReader(classic(binary.LittleEndian, false)), func(Packet) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, input := range [][]byte{{}, {1, 2, 3}, classic(binary.LittleEndian, false, []byte{1})[:len(classic(binary.LittleEndian, false, []byte{1}))-1]} {
		if _, err := Read(context.Background(), bytes.NewReader(input), func(Packet) error { return nil }); err == nil {
			t.Fatal("accepted truncated input")
		}
	}
	br := &boundedReader{r: bytes.NewReader([]byte{1}), n: maxInput}
	if _, err := br.Read(make([]byte, 1)); err == nil {
		t.Fatal("input bound not enforced")
	}
	br = &boundedReader{r: bytes.NewReader(nil), n: maxInput}
	if _, err := br.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("exact input bound did not permit EOF", err)
	}
}

func TestPCAPNGRejectsMalformedBlocks(t *testing.T) {
	o := binary.LittleEndian
	unknownIface := append(append(shb(o), idb(o, 1, 64)...), epb(o, 1, 1, []byte{1}, 1)...)
	badTrailer := shb(o)
	badTrailer[len(badTrailer)-1]++
	duplicateResolution := append(shb(o), idb(o, 1, 64, option(o, 9, []byte{6}), option(o, 9, []byte{9}))...)
	offsetValue := make([]byte, 8)
	duplicateOffset := append(shb(o), idb(o, 1, 64, option(o, 14, offsetValue), option(o, 14, offsetValue))...)
	duplicateEnd := append(shb(o), idb(o, 1, 64, option(o, 0, nil), option(o, 0, nil))...)
	for _, input := range [][]byte{badTrailer, unknownIface, duplicateResolution, duplicateOffset, duplicateEnd, block(o, 1, make([]byte, 8))} {
		if _, err := Read(context.Background(), bytes.NewReader(input), func(Packet) error { return nil }); err == nil {
			t.Fatal("accepted malformed PCAPNG")
		}
	}
}

func TestPCAPNGRejectsTimestampOutsideJSONRange(t *testing.T) {
	if _, err := ngTime(0, ngInterface{denom: 1, offset: 253402300800}); err == nil {
		t.Fatal("accepted year 10000 timestamp")
	}
}

func TestReaderIOError(t *testing.T) {
	want := errors.New("read failure")
	r := io.MultiReader(bytes.NewReader([]byte{0xd4, 0xc3, 0xb2, 0xa1}), errorReader{want})
	if _, err := Read(context.Background(), r, func(Packet) error { return nil }); !errors.Is(err, want) {
		t.Fatal(err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func FuzzRead(f *testing.F) {
	f.Add(classic(binary.LittleEndian, false, []byte{1, 2, 3}))
	f.Add(classic(binary.BigEndian, true, []byte{4}))
	le := binary.LittleEndian
	ng := append(shb(le), idb(le, 1, 64, option(le, 9, []byte{6}))...)
	ng = append(ng, epb(le, 0, 1_500_000, []byte{5, 6}, 3)...)
	f.Add(ng)
	legacy := append(shb(le), idb(le, 101, 0)...)
	legacy = append(legacy, obsoletePacket(le, 0, 2, []byte{7}, 1)...)
	f.Add(legacy)
	f.Add([]byte{0x0a, 0x0d, 0x0d, 0x0a})
	f.Add([]byte{0xd4, 0xc3, 0xb2, 0xa1})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Read(context.Background(), bytes.NewReader(data), func(p Packet) error {
			if len(p.Data) > 0 {
				p.Data[0] ^= 0xff
			}
			return nil
		})
	})
}
