// Package capture reads bounded classic PCAP and PCAPNG packet streams.
package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"time"
)

const (
	maxInput      = 128 << 20
	maxPackets    = 1_000_000
	maxPacket     = 1 << 20
	maxBlock      = 1 << 20
	maxInterfaces = 1024
)

type Packet struct {
	Timestamp      time.Time
	Section        uint32
	Interface      uint32
	LinkType       uint16
	Data           []byte
	OriginalLength uint32
	Truncated      bool
}

type Stats struct {
	Format  string `json:"format"`
	Packets int    `json:"packets"` // Fully read records, including a rejected callback.
	Bytes   int64  `json:"bytes"`
}

type boundedReader struct {
	r io.Reader
	n int64
}

func (r *boundedReader) Read(p []byte) (int, error) {
	if r.n >= maxInput {
		// A one-byte lookahead distinguishes a stream ending exactly at the
		// limit from one exceeding it. The lookahead is not exposed or counted.
		var probe [1]byte
		n, err := r.r.Read(probe[:])
		if n == 0 && err == io.EOF {
			return 0, io.EOF
		}
		return 0, errors.New("capture exceeds 128 MiB input limit")
	}
	if int64(len(p)) > maxInput-r.n {
		p = p[:maxInput-r.n]
	}
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}

// Read streams packets to emit. Context cancellation is checked between input
// operations and callbacks; it cannot interrupt an arbitrary blocking Reader.
func Read(ctx context.Context, input io.Reader, emit func(Packet) error) (Stats, error) {
	var stats Stats
	if input == nil || emit == nil {
		return stats, errors.New("capture reader and callback are required")
	}
	br := &boundedReader{r: input}
	first := make([]byte, 4)
	if err := readFull(ctx, br, first); err != nil {
		stats.Bytes = br.n
		return stats, err
	}
	var err error
	if binary.BigEndian.Uint32(first) == 0x0a0d0d0a {
		stats.Format = "pcapng"
		err = readPCAPNG(ctx, br, first, emit, &stats)
	} else {
		stats.Format = "pcap"
		err = readPCAP(ctx, br, first, emit, &stats)
	}
	stats.Bytes = br.n
	return stats, err
}

func readFull(ctx context.Context, r io.Reader, p []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := io.ReadFull(r, p)
	return err
}

func nextHeader(ctx context.Context, r io.Reader, p []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	n, err := io.ReadFull(r, p)
	if err == io.EOF && n == 0 {
		return false, nil
	}
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, io.ErrUnexpectedEOF
		}
		return false, err
	}
	return true, nil
}

func complete(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

func deliver(ctx context.Context, emit func(Packet) error, p Packet, stats *Stats) error {
	if stats.Packets >= maxPackets {
		return errors.New("capture exceeds packet record limit")
	}
	// Packets counts complete records consumed from the input, including a
	// record whose callback returns an error.
	stats.Packets++
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := emit(p); err != nil {
		return err
	}
	return nil
}

func readPCAP(ctx context.Context, r io.Reader, magic []byte, emit func(Packet) error, stats *Stats) error {
	var order binary.ByteOrder
	nanos := false
	switch [4]byte(magic) {
	case [4]byte{0xd4, 0xc3, 0xb2, 0xa1}:
		order = binary.LittleEndian
	case [4]byte{0xa1, 0xb2, 0xc3, 0xd4}:
		order = binary.BigEndian
	case [4]byte{0x4d, 0x3c, 0xb2, 0xa1}:
		order, nanos = binary.LittleEndian, true
	case [4]byte{0xa1, 0xb2, 0x3c, 0x4d}:
		order, nanos = binary.BigEndian, true
	default:
		return errors.New("unrecognized capture format")
	}
	header := make([]byte, 20)
	if err := readFull(ctx, r, header); err != nil {
		return complete(err)
	}
	if order.Uint16(header[0:2]) != 2 || order.Uint16(header[2:4]) != 4 {
		return errors.New("unsupported PCAP version")
	}
	snaplen := order.Uint32(header[12:16])
	link := order.Uint32(header[16:20])
	if snaplen == 0 || link > math.MaxUint16 {
		return errors.New("invalid PCAP snaplen or link type")
	}
	for {
		h := make([]byte, 16)
		ok, err := nextHeader(ctx, r, h)
		if err != nil || !ok {
			return err
		}
		sec, sub := order.Uint32(h[0:4]), order.Uint32(h[4:8])
		captured, original := order.Uint32(h[8:12]), order.Uint32(h[12:16])
		limit := uint32(1_000_000)
		if nanos {
			limit = 1_000_000_000
		}
		if sub >= limit || captured > original || captured > snaplen || captured > maxPacket {
			return errors.New("invalid PCAP packet header")
		}
		data := make([]byte, captured)
		if err := readFull(ctx, r, data); err != nil {
			return complete(err)
		}
		nsec := int64(sub) * 1000
		if nanos {
			nsec = int64(sub)
		}
		if err := deliver(ctx, emit, Packet{Timestamp: time.Unix(int64(sec), nsec).UTC(), LinkType: uint16(link), Data: data, OriginalLength: original, Truncated: captured < original}, stats); err != nil {
			return err
		}
	}
}

type ngInterface struct {
	link   uint16
	snap   uint32
	denom  uint64
	offset int64
}

func readPCAPNG(ctx context.Context, r io.Reader, first []byte, emit func(Packet) error, stats *Stats) error {
	interfaces := []ngInterface(nil)
	var section uint32
	sectionSeen := false
	var order binary.ByteOrder
	pending := first
	for {
		var typBytes, lenBytes []byte
		if pending != nil {
			typBytes = pending
			lenBytes = make([]byte, 4)
			if err := readFull(ctx, r, lenBytes); err != nil {
				return complete(err)
			}
		} else {
			h := make([]byte, 8)
			ok, err := nextHeader(ctx, r, h)
			if err != nil || !ok {
				return err
			}
			typBytes, lenBytes = h[:4], h[4:]
		}
		isSHB := binary.BigEndian.Uint32(typBytes) == 0x0a0d0d0a
		var prefix []byte
		if isSHB {
			bom := make([]byte, 4)
			if err := readFull(ctx, r, bom); err != nil {
				return complete(err)
			}
			switch [4]byte(bom) {
			case [4]byte{0x4d, 0x3c, 0x2b, 0x1a}:
				order = binary.LittleEndian
			case [4]byte{0x1a, 0x2b, 0x3c, 0x4d}:
				order = binary.BigEndian
			default:
				return errors.New("invalid PCAPNG byte-order magic")
			}
			prefix = bom
		} else if order == nil {
			return errors.New("PCAPNG must begin with a section header")
		}
		total := order.Uint32(lenBytes)
		min := uint32(12)
		if isSHB {
			min = 28
		}
		if total < min || total%4 != 0 || total > maxBlock {
			return errors.New("invalid or oversized PCAPNG block length")
		}
		consumed := 8 + len(prefix)
		rest := make([]byte, int(total)-consumed)
		if err := readFull(ctx, r, rest); err != nil {
			return complete(err)
		}
		body := append(prefix, rest[:len(rest)-4]...)
		if order.Uint32(rest[len(rest)-4:]) != total {
			return errors.New("PCAPNG block length trailer mismatch")
		}
		typ := order.Uint32(typBytes)
		switch typ {
		case 0x0a0d0d0a:
			if len(body) < 16 || order.Uint16(body[4:6]) != 1 || order.Uint16(body[6:8]) != 0 {
				return errors.New("unsupported PCAPNG section version")
			}
			if _, err := parseOptions(body[16:], order, nil); err != nil {
				return fmt.Errorf("section options: %w", err)
			}
			if sectionSeen {
				section++
			}
			sectionSeen = true
			interfaces = nil
		case 1:
			if len(body) < 8 || len(interfaces) >= maxInterfaces {
				return errors.New("invalid or excessive PCAPNG interfaces")
			}
			iface := ngInterface{link: order.Uint16(body[:2]), snap: order.Uint32(body[4:8]), denom: 1_000_000}
			seenResolution, seenOffset := false, false
			_, err := parseOptions(body[8:], order, func(code uint16, value []byte) error {
				switch code {
				case 9:
					if seenResolution {
						return errors.New("duplicate if_tsresol")
					}
					seenResolution = true
					if len(value) != 1 {
						return errors.New("invalid if_tsresol")
					}
					n := value[0] & 0x7f
					if value[0]&0x80 != 0 {
						if n > 63 {
							return errors.New("unsupported binary timestamp resolution")
						}
						iface.denom = uint64(1) << n
					} else {
						iface.denom = 1
						for i := byte(0); i < n; i++ {
							if iface.denom > math.MaxUint64/10 {
								return errors.New("unsupported decimal timestamp resolution")
							}
							iface.denom *= 10
						}
					}
				case 14:
					if seenOffset {
						return errors.New("duplicate if_tsoffset")
					}
					seenOffset = true
					if len(value) != 8 {
						return errors.New("invalid if_tsoffset")
					}
					iface.offset = int64(order.Uint64(value))
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("interface options: %w", err)
			}
			interfaces = append(interfaces, iface)
		case 6:
			if len(body) < 20 {
				return errors.New("short PCAPNG enhanced packet block")
			}
			id, captured, original := order.Uint32(body[:4]), order.Uint32(body[12:16]), order.Uint32(body[16:20])
			if int(id) >= len(interfaces) {
				return errors.New("PCAPNG packet references unknown interface")
			}
			iface := interfaces[id]
			if captured > original || captured > maxPacket || (iface.snap != 0 && captured > iface.snap) {
				return errors.New("invalid PCAPNG packet lengths")
			}
			padded := (uint64(captured) + 3) &^ uint64(3)
			if padded > uint64(len(body)-20) {
				return errors.New("short PCAPNG packet data")
			}
			if _, err := parseOptions(body[20+padded:], order, nil); err != nil {
				return fmt.Errorf("packet options: %w", err)
			}
			ts := uint64(order.Uint32(body[4:8]))<<32 | uint64(order.Uint32(body[8:12]))
			tm, err := ngTime(ts, iface)
			if err != nil {
				return err
			}
			data := append([]byte(nil), body[20:20+captured]...)
			if err := deliver(ctx, emit, Packet{Timestamp: tm, Section: section, Interface: id, LinkType: iface.link, Data: data, OriginalLength: original, Truncated: captured < original}, stats); err != nil {
				return err
			}
		case 2: // Obsolete Packet Block; still present in older capture files.
			if len(body) < 20 {
				return errors.New("short PCAPNG packet block")
			}
			id := uint32(order.Uint16(body[:2]))
			captured, original := order.Uint32(body[12:16]), order.Uint32(body[16:20])
			if int(id) >= len(interfaces) {
				return errors.New("PCAPNG packet references unknown interface")
			}
			iface := interfaces[id]
			if captured > original || captured > maxPacket || (iface.snap != 0 && captured > iface.snap) {
				return errors.New("invalid PCAPNG packet lengths")
			}
			padded := (uint64(captured) + 3) &^ uint64(3)
			if padded > uint64(len(body)-20) {
				return errors.New("short PCAPNG packet data")
			}
			if _, err := parseOptions(body[20+padded:], order, nil); err != nil {
				return fmt.Errorf("packet options: %w", err)
			}
			ts := uint64(order.Uint32(body[4:8]))<<32 | uint64(order.Uint32(body[8:12]))
			tm, err := ngTime(ts, iface)
			if err != nil {
				return err
			}
			data := append([]byte(nil), body[20:20+captured]...)
			if err := deliver(ctx, emit, Packet{Timestamp: tm, Section: section, Interface: id, LinkType: iface.link, Data: data, OriginalLength: original, Truncated: captured < original}, stats); err != nil {
				return err
			}
		case 3:
			if len(interfaces) == 0 || len(body) < 4 {
				return errors.New("simple packet block without interface")
			}
			original := order.Uint32(body[:4])
			captured := original
			if interfaces[0].snap != 0 && captured > interfaces[0].snap {
				captured = interfaces[0].snap
			}
			if captured > maxPacket {
				return errors.New("oversized PCAPNG simple packet")
			}
			padded := (uint64(captured) + 3) &^ uint64(3)
			if uint64(len(body)-4) != padded {
				return errors.New("invalid PCAPNG simple packet length")
			}
			data := append([]byte(nil), body[4:4+captured]...)
			if err := deliver(ctx, emit, Packet{Section: section, Interface: 0, LinkType: interfaces[0].link, Data: data, OriginalLength: original, Truncated: captured < original}, stats); err != nil {
				return err
			}
		}
		pending = nil
	}
}

func parseOptions(b []byte, order binary.ByteOrder, visit func(uint16, []byte) error) (bool, error) {
	for len(b) > 0 {
		if len(b) < 4 {
			return false, errors.New("short option header")
		}
		code, size := order.Uint16(b[:2]), int(order.Uint16(b[2:4]))
		b = b[4:]
		if code == 0 {
			if size != 0 {
				return false, errors.New("invalid end-of-options")
			}
			if len(b) != 0 {
				return false, errors.New("data after end-of-options")
			}
			return true, nil
		}
		padded := (size + 3) &^ 3
		if padded > len(b) {
			return false, errors.New("short option value")
		}
		if visit != nil {
			if err := visit(code, b[:size]); err != nil {
				return false, err
			}
		}
		b = b[padded:]
	}
	return false, nil
}

func ngTime(ticks uint64, iface ngInterface) (time.Time, error) {
	if iface.denom == 0 {
		return time.Time{}, errors.New("invalid timestamp resolution")
	}
	seconds := ticks / iface.denom
	if seconds > math.MaxInt64 || (iface.offset > 0 && seconds > uint64(math.MaxInt64-iface.offset)) {
		return time.Time{}, errors.New("PCAPNG timestamp overflows")
	}
	sec := int64(seconds)
	if iface.offset < 0 && sec < math.MinInt64-iface.offset {
		return time.Time{}, errors.New("PCAPNG timestamp overflows")
	}
	sec += iface.offset
	hi, lo := bits.Mul64(ticks%iface.denom, 1_000_000_000)
	nanos, _ := bits.Div64(hi, lo, iface.denom)
	tm := time.Unix(sec, int64(nanos)).UTC()
	if year := tm.Year(); year < 0 || year > 9999 {
		return time.Time{}, errors.New("PCAPNG timestamp is not JSON representable")
	}
	return tm, nil
}
