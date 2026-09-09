// Package snmp implements a bounded SNMPv2c BER codec.
package snmp

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const maxMessage = 64 << 10

// Credentials contains an immutable SNMPv2c community value.
type Credentials struct{ community string }

// NewCredentials validates and copies a community value.
func NewCredentials(s string) (Credentials, error) {
	if len(s) == 0 || len(s) > 255 {
		return Credentials{}, errors.New("SNMP community must contain 1..255 bytes")
	}
	return Credentials{community: string(append([]byte(nil), s...))}, nil
}
func (Credentials) String() string               { return "[REDACTED]" }
func (Credentials) GoString() string             { return "snmp.Credentials{[REDACTED]}" }
func (Credentials) MarshalJSON() ([]byte, error) { return json.Marshal("[REDACTED]") }

// Value is one decoded SNMP variable binding.
type Value struct {
	OID     string `json:"oid"`
	Kind    string `json:"kind"`
	Text    string `json:"text,omitempty"`
	Integer int64  `json:"integer,omitempty"`
	Bytes   []byte `json:"bytes,omitempty"`
}

func tlv(tag byte, value []byte) []byte {
	out := []byte{tag}
	out = append(out, encLen(len(value))...)
	return append(out, value...)
}
func encLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var a [8]byte
	i := len(a)
	for n > 0 {
		i--
		a[i] = byte(n)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(a)-i)}, a[i:]...)
}
func encInt(v int64) []byte {
	var a [8]byte
	u := uint64(v)
	for i := 7; i >= 0; i-- {
		a[i] = byte(u)
		u >>= 8
	}
	i := 0
	for i < 7 && ((a[i] == 0 && a[i+1]&0x80 == 0) || (a[i] == 0xff && a[i+1]&0x80 != 0)) {
		i++
	}
	return tlv(0x02, a[i:])
}

func parseOID(s string) ([]uint32, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 128 {
		return nil, errors.New("invalid OID arc count")
	}
	a := make([]uint32, len(parts))
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return nil, errors.New("invalid OID")
		}
		for j := range p {
			if p[j] < '0' || p[j] > '9' {
				return nil, errors.New("invalid OID")
			}
		}
		n, e := strconv.ParseUint(p, 10, 32)
		if e != nil {
			return nil, errors.New("invalid OID")
		}
		a[i] = uint32(n)
	}
	if a[0] > 2 || (a[0] < 2 && a[1] > 39) {
		return nil, errors.New("invalid OID root")
	}
	return a, nil
}
func base128(v uint64) []byte {
	x := []byte{byte(v & 127)}
	for v >>= 7; v > 0; v >>= 7 {
		x = append([]byte{byte(v&127) | 128}, x...)
	}
	return x
}
func encOID(s string) ([]byte, error) {
	a, e := parseOID(s)
	if e != nil {
		return nil, e
	}
	b := base128(uint64(a[0])*40 + uint64(a[1]))
	for _, v := range a[2:] {
		b = append(b, base128(uint64(v))...)
	}
	return tlv(0x06, b), nil
}

// BuildGet constructs an SNMPv2c GetRequest.
func BuildGet(c Credentials, id int32, oids []string) ([]byte, error) {
	if id <= 0 {
		return nil, errors.New("request ID must be positive")
	}
	if len(c.community) == 0 {
		return nil, errors.New("invalid credentials")
	}
	if len(oids) == 0 || len(oids) > 128 {
		return nil, errors.New("invalid OID count")
	}
	var list []byte
	for _, s := range oids {
		o, e := encOID(s)
		if e != nil {
			return nil, e
		}
		list = append(list, tlv(0x30, append(o, 0x05, 0x00))...)
	}
	return request(c, id, 0xa0, append(append(encInt(int64(id)), encInt(0)...), append(encInt(0), tlv(0x30, list)...)...))
}

// BuildBulk constructs a single-column SNMPv2c GetBulkRequest.
func BuildBulk(c Credentials, id int32, oid string, maxRepetitions int) ([]byte, error) {
	if id <= 0 || maxRepetitions < 1 || maxRepetitions > 33 {
		return nil, errors.New("invalid bulk parameters")
	}
	if len(c.community) == 0 {
		return nil, errors.New("invalid credentials")
	}
	o, e := encOID(oid)
	if e != nil {
		return nil, e
	}
	vb := tlv(0x30, append(o, 0x05, 0))
	body := append(append(encInt(int64(id)), encInt(0)...), append(encInt(int64(maxRepetitions)), tlv(0x30, vb)...)...)
	return request(c, id, 0xa5, body)
}
func request(c Credentials, id int32, pdu byte, body []byte) ([]byte, error) {
	// Check before wrapping so no BER length can be truncated or create an
	// oversized intermediate request.
	if len(body)+len(c.community)+32 > maxMessage {
		return nil, errors.New("SNMP message too large")
	}
	m := tlv(0x30, append(append(encInt(1), tlv(0x04, []byte(c.community))...), tlv(pdu, body)...))
	if len(m) > maxMessage {
		return nil, errors.New("SNMP message too large")
	}
	return m, nil
}

type reader struct {
	b []byte
	n int
}

func (r *reader) readTLV() (byte, []byte, error) {
	if r.n >= len(r.b) {
		return 0, nil, errors.New("truncated BER")
	}
	tag := r.b[r.n]
	r.n++
	if r.n >= len(r.b) {
		return 0, nil, errors.New("truncated BER length")
	}
	x := r.b[r.n]
	r.n++
	l := 0
	if x&128 == 0 {
		l = int(x)
	} else {
		k := int(x & 127)
		if k == 0 || k > 127 || r.n+k > len(r.b) {
			return 0, nil, errors.New("invalid BER length")
		}
		for i := 0; i < k; i++ {
			// RFC 3417 permits padded definite-long lengths. The enclosing
			// message limit makes any value above maxMessage impossible here.
			if l > maxMessage>>8 {
				return 0, nil, errors.New("BER length exceeds message limit")
			}
			l = l<<8 | int(r.b[r.n])
			r.n++
		}
		if l > maxMessage {
			return 0, nil, errors.New("BER length exceeds message limit")
		}
	}
	if l > len(r.b)-r.n {
		return 0, nil, errors.New("truncated BER value")
	}
	v := r.b[r.n : r.n+l]
	r.n += l
	return tag, v, nil
}
func only(tag byte, b []byte) ([]byte, error) {
	r := reader{b: b}
	t, v, e := r.readTLV()
	if e != nil || t != tag || r.n != len(b) {
		return nil, errors.New("unexpected BER framing")
	}
	return v, nil
}
func decInt(b []byte) (int64, error) {
	if len(b) == 0 || len(b) > 8 {
		return 0, errors.New("invalid BER integer")
	}
	if len(b) > 1 && ((b[0] == 0 && b[1]&128 == 0) || (b[0] == 255 && b[1]&128 != 0)) {
		return 0, errors.New("non-canonical BER integer")
	}
	v := int64(int8(b[0]))
	for _, x := range b[1:] {
		v = v<<8 | int64(x)
	}
	return v, nil
}
func decOID(b []byte) (string, error) {
	if len(b) == 0 {
		return "", errors.New("empty OID")
	}
	var a []uint32
	for i := 0; i < len(b); {
		start := i
		var v uint64
		for {
			if i >= len(b) || i-start > 4 {
				return "", errors.New("invalid OID")
			}
			x := b[i]
			i++
			if i-start > 1 && b[start] == 0x80 {
				return "", errors.New("non-canonical OID")
			}
			v = v<<7 | uint64(x&127)
			if v > uint64(^uint32(0))+80 {
				return "", errors.New("OID arc overflow")
			}
			if x&128 == 0 {
				break
			}
		}
		if len(a) == 0 {
			if v < 40 {
				a = append(a, 0, uint32(v))
			} else if v < 80 {
				a = append(a, 1, uint32(v-40))
			} else {
				if v-80 > uint64(^uint32(0)) {
					return "", errors.New("OID arc overflow")
				}
				a = append(a, 2, uint32(v-80))
			}
		} else {
			if v > uint64(^uint32(0)) {
				return "", errors.New("OID arc overflow")
			}
			a = append(a, uint32(v))
		}
	}
	if len(a) > 128 {
		return "", errors.New("too many OID arcs")
	}
	s := make([]string, len(a))
	for i, v := range a {
		s[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(s, "."), nil
}

// ParseResponse validates and decodes a matching SNMPv2c GetResponse.
func ParseResponse(b []byte, c Credentials, id int32) ([]Value, error) {
	if id <= 0 || len(c.community) == 0 || len(b) == 0 || len(b) > maxMessage {
		return nil, errors.New("invalid SNMP response parameters")
	}
	outer, e := only(0x30, b)
	if e != nil {
		return nil, e
	}
	r := reader{b: outer}
	t, v, e := r.readTLV()
	if e != nil || t != 2 {
		return nil, errors.New("missing SNMP version")
	}
	n, e := decInt(v)
	if e != nil || n != 1 {
		return nil, errors.New("not SNMPv2c")
	}
	t, v, e = r.readTLV()
	if e != nil || t != 4 || subtle.ConstantTimeCompare(v, []byte(c.community)) != 1 {
		return nil, errors.New("SNMP community mismatch")
	}
	t, pdu, e := r.readTLV()
	if e != nil || t != 0xa2 || r.n != len(r.b) {
		return nil, errors.New("expected GetResponse PDU")
	}
	pr := reader{b: pdu}
	readI := func() (int64, error) {
		t, v, e := pr.readTLV()
		if e != nil || t != 2 {
			return 0, errors.New("invalid response integer")
		}
		return decInt(v)
	}
	rid, e := readI()
	if e != nil || rid != int64(id) {
		return nil, errors.New("SNMP request ID mismatch")
	}
	status, e := readI()
	if e != nil {
		return nil, e
	}
	index, e := readI()
	if e != nil {
		return nil, e
	}
	if status != 0 || index != 0 {
		return nil, errors.New("SNMP agent returned an error")
	}
	t, list, e := pr.readTLV()
	if e != nil || t != 0x30 || pr.n != len(pr.b) {
		return nil, errors.New("invalid varbind list")
	}
	lr := reader{b: list}
	out := []Value{}
	for lr.n < len(lr.b) {
		if len(out) >= 128 {
			return nil, errors.New("too many varbinds")
		}
		t, vb, e := lr.readTLV()
		if e != nil || t != 0x30 {
			return nil, errors.New("invalid varbind")
		}
		vr := reader{b: vb}
		t, ob, e := vr.readTLV()
		if e != nil || t != 6 {
			return nil, errors.New("invalid varbind OID")
		}
		oid, e := decOID(ob)
		if e != nil {
			return nil, e
		}
		t, val, e := vr.readTLV()
		if e != nil || vr.n != len(vr.b) || len(val) > 2048 {
			return nil, errors.New("invalid varbind value")
		}
		x := Value{OID: oid}
		switch t {
		case 0x04:
			x.Kind = "octets"
			x.Bytes = append([]byte(nil), val...)
		case 0x06:
			x.Kind = "oid"
			x.Text, e = decOID(val)
		case 0x02:
			x.Kind = "integer"
			x.Integer, e = decInt(val)
		case 0x05:
			if len(val) != 0 {
				e = errors.New("invalid NULL")
			}
			x.Kind = "null"
		case 0x80:
			if len(val) != 0 {
				e = errors.New("invalid exception")
			}
			x.Kind = "no-such-object"
		case 0x81:
			if len(val) != 0 {
				e = errors.New("invalid exception")
			}
			x.Kind = "no-such-instance"
		case 0x82:
			if len(val) != 0 {
				e = errors.New("invalid exception")
			}
			x.Kind = "end-of-mib"
		case 0x40:
			if len(val) != 4 {
				e = errors.New("invalid IP address")
			}
			x.Kind = "ip-address"
			x.Bytes = append([]byte(nil), val...)
		case 0x41, 0x42, 0x43:
			if e = validUnsigned(val, 4); e == nil {
				x.Bytes = append([]byte(nil), val...)
			}
			x.Kind = map[byte]string{0x41: "counter32", 0x42: "gauge32", 0x43: "time-ticks"}[t]
		case 0x46:
			e = validUnsigned(val, 8)
			if e == nil {
				x.Bytes = append([]byte(nil), val...)
			}
			x.Kind = "counter64"
		case 0x44:
			x.Kind = "opaque"
			x.Bytes = append([]byte(nil), val...)
		default:
			e = fmt.Errorf("unsupported SNMP value tag 0x%02x", t)
		}
		if e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, nil
}

func validUnsigned(b []byte, width int) error {
	if len(b) == 0 || len(b) > width+1 || b[0]&0x80 != 0 {
		return errors.New("invalid unsigned SNMP application value")
	}
	if len(b) > 1 && b[0] == 0 && b[1]&0x80 == 0 {
		return errors.New("non-canonical unsigned SNMP application value")
	}
	if len(b) == width+1 && b[0] != 0 {
		return errors.New("unsigned SNMP application value overflow")
	}
	return nil
}
