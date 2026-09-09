// Package dhcp parses offline DHCPv4 and DHCPv6 messages into wire-faithful
// observations. It neither sends packets nor classifies operating systems.
package dhcp

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxPayload    = 65535
	maxRelayDepth = 4
	maxOptions    = 1024
)

type Option struct {
	Code uint16 `json:"code"`
	Data []byte `json:"data"`
	Area string `json:"area"`
}
type Relay struct {
	Type        uint8    `json:"type"`
	HopCount    uint8    `json:"hop_count"`
	LinkAddress string   `json:"link_address,omitempty"`
	PeerAddress string   `json:"peer_address,omitempty"`
	Options     []Option `json:"options"`
}
type Hints struct {
	Hostname         string   `json:"hostname,omitempty"`
	VendorClass      string   `json:"vendor_class,omitempty"`
	RequestedOptions []uint16 `json:"requested_options,omitempty"`
	ClientID         []byte   `json:"client_id,omitempty"`
	EnterpriseID     *uint32  `json:"enterprise_id,omitempty"`
}
type Message struct {
	Version               int      `json:"version"`
	Type                  uint8    `json:"type"`
	TransactionID         string   `json:"transaction_id"`
	ClientHardwareAddress string   `json:"client_hardware_address,omitempty"`
	ClientIP              string   `json:"client_ip,omitempty"`
	AssignedIP            string   `json:"assigned_ip,omitempty"`
	RelayIP               string   `json:"relay_ip,omitempty"`
	Options               []Option `json:"options"`
	Relays                []Relay  `json:"relays,omitempty"`
	Hints                 Hints    `json:"hints,omitempty"`
}

func Parse4(b []byte) (Message, error) {
	if len(b) < 240 || len(b) > maxPayload {
		return Message{}, errors.New("invalid DHCPv4 message size")
	}
	if b[0] != 1 && b[0] != 2 {
		return Message{}, errors.New("invalid DHCPv4 BOOTP op")
	}
	if string(b[236:240]) != "\x63\x82\x53\x63" {
		return Message{}, errors.New("missing DHCPv4 cookie")
	}
	m := Message{Version: 4, TransactionID: hex.EncodeToString(b[4:8])}
	if b[1] == 1 && b[2] == 6 {
		m.ClientHardwareAddress = net.HardwareAddr(b[28:34]).String()
	}
	m.ClientIP, m.AssignedIP, m.RelayIP = v4addr(b[12:16]), v4addr(b[16:20]), v4addr(b[24:28])
	count := 0
	main, err := parse4Options(b[240:], "options", &count)
	if err != nil {
		return Message{}, err
	}
	m.Options = append(m.Options, main...)
	joined := join4(m.Options)
	if overload, ok := joined[52]; ok {
		if len(overload) != 1 || overload[0] < 1 || overload[0] > 3 {
			return Message{}, errors.New("invalid DHCPv4 option overload")
		}
		if overload[0]&1 != 0 {
			o, err := parse4Options(b[108:236], "file", &count)
			if err != nil {
				return Message{}, err
			}
			m.Options = append(m.Options, o...)
		}
		if overload[0]&2 != 0 {
			o, err := parse4Options(b[44:108], "sname", &count)
			if err != nil {
				return Message{}, err
			}
			m.Options = append(m.Options, o...)
		}
	}
	joined = join4(m.Options)
	typ, ok := joined[53]
	// IANA's DHCP Message Type 53 registry permits assignments beyond the
	// original RFC 2131 values. Retain every nonzero wire value:
	// https://www.iana.org/assignments/bootp-dhcp-parameters/
	if !ok || len(typ) != 1 || typ[0] == 0 {
		return Message{}, errors.New("invalid DHCPv4 message type")
	}
	m.Type = typ[0]
	hints4(&m.Hints, joined)
	return m, nil
}

func parse4Options(b []byte, area string, count *int) ([]Option, error) {
	var out []Option
	for i := 0; i < len(b); {
		code := b[i]
		i++
		if code == 0 {
			continue
		}
		if code == 255 {
			return out, nil
		}
		if i >= len(b) {
			return nil, errors.New("truncated DHCPv4 option")
		}
		n := int(b[i])
		i++
		if n > len(b)-i {
			return nil, errors.New("truncated DHCPv4 option data")
		}
		*count = *count + 1
		if *count > maxOptions {
			return nil, errors.New("too many DHCP options")
		}
		out = append(out, Option{Code: uint16(code), Data: append([]byte(nil), b[i:i+n]...), Area: area})
		i += n
	}
	return nil, errors.New("DHCPv4 options missing end")
}
func join4(options []Option) map[uint16][]byte {
	out := map[uint16][]byte{}
	for _, o := range options {
		out[o.Code] = append(out[o.Code], o.Data...)
	}
	return out
}
func v4addr(b []byte) string {
	a := netip.AddrFrom4([4]byte(b))
	if a.IsUnspecified() {
		return ""
	}
	return a.String()
}
func safeText(b []byte) (string, bool) {
	if len(b) == 0 || !utf8.Valid(b) {
		return "", false
	}
	for _, c := range string(b) {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			return "", false
		}
	}
	return string(b), true
}
func hints4(h *Hints, o map[uint16][]byte) {
	if b, ok := o[12]; ok {
		if s, good := safeText(b); good {
			h.Hostname = s
		}
	}
	if b, ok := o[60]; ok {
		// Option 60 is opaque bytes. A non-text value remains in Options but
		// cannot safely populate this string display hint.
		if s, good := safeText(b); good {
			h.VendorClass = s
		}
	}
	if b, ok := o[55]; ok {
		h.RequestedOptions = make([]uint16, len(b))
		for i, v := range b {
			h.RequestedOptions[i] = uint16(v)
		}
	}
	if b, ok := o[61]; ok {
		if len(b) > 0 {
			h.ClientID = append([]byte(nil), b...)
		}
	}
}

func Parse6(b []byte) (Message, error) {
	if len(b) < 4 || len(b) > maxPayload {
		return Message{}, errors.New("invalid DHCPv6 message size")
	}
	count := 0
	m, err := parse6(b, &count, 0)
	if err != nil {
		return Message{}, err
	}
	return m, nil
}
func parse6(b []byte, count *int, depth int) (Message, error) {
	if len(b) < 4 {
		return Message{}, errors.New("truncated DHCPv6 message")
	}
	typ := b[0]
	if typ == 12 || typ == 13 {
		if depth >= maxRelayDepth || len(b) < 34 {
			return Message{}, errors.New("invalid DHCPv6 relay")
		}
		opts, err := parse6Options(b[34:], count)
		if err != nil {
			return Message{}, err
		}
		relay := Relay{Type: typ, HopCount: b[1], LinkAddress: v6addr(b[2:18]), PeerAddress: v6addr(b[18:34]), Options: opts}
		var inner []byte
		found := 0
		for _, o := range opts {
			if o.Code == 9 {
				found++
				inner = append([]byte(nil), o.Data...)
			}
		}
		if found != 1 || len(inner) == 0 {
			return Message{}, errors.New("DHCPv6 relay requires one relay-message")
		}
		m, err := parse6(inner, count, depth+1)
		if err != nil {
			return Message{}, err
		}
		m.Relays = append([]Relay{relay}, m.Relays...)
		return m, nil
	}
	opts, err := parse6Options(b[4:], count)
	if err != nil {
		return Message{}, err
	}
	m := Message{Version: 6, Type: typ, TransactionID: hex.EncodeToString(b[1:4]), Options: opts}
	if typ == 0 {
		return Message{}, errors.New("invalid DHCPv6 message type")
	}
	if err := hints6(&m.Hints, opts); err != nil {
		return Message{}, err
	}
	return m, nil
}
func parse6Options(b []byte, count *int) ([]Option, error) {
	var out []Option
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, errors.New("truncated DHCPv6 option")
		}
		code := binary.BigEndian.Uint16(b)
		n := int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if n > len(b) {
			return nil, errors.New("truncated DHCPv6 option data")
		}
		*count = *count + 1
		if *count > maxOptions {
			return nil, errors.New("too many DHCP options")
		}
		out = append(out, Option{Code: code, Data: append([]byte(nil), b[:n]...), Area: "options"})
		b = b[n:]
	}
	return out, nil
}
func v6addr(b []byte) string {
	var raw [16]byte
	copy(raw[:], b)
	a := netip.AddrFrom16(raw)
	if a.IsUnspecified() {
		return ""
	}
	return a.String()
}
func hints6(h *Hints, opts []Option) error {
	values := func(code uint16) [][]byte {
		var out [][]byte
		for _, o := range opts {
			if o.Code == code {
				out = append(out, o.Data)
			}
		}
		return out
	}
	if v := values(1); len(v) == 1 && len(v[0]) > 0 {
		h.ClientID = append([]byte(nil), v[0]...)
	}
	if v := values(6); len(v) > 0 {
		for _, b := range v {
			if len(b)%2 != 0 {
				return errors.New("invalid DHCPv6 ORO")
			}
		}
		if len(v) == 1 {
			h.RequestedOptions = make([]uint16, len(v[0])/2)
			for i := range h.RequestedOptions {
				h.RequestedOptions[i] = binary.BigEndian.Uint16(v[0][i*2:])
			}
		}
	}
	if v := values(39); len(v) > 0 {
		names, usable := make([]string, len(v)), make([]bool, len(v))
		for i, b := range v {
			var err error
			names[i], usable[i], err = fqdn(b)
			if err != nil {
				return err
			}
		}
		if len(names) == 1 && usable[0] {
			h.Hostname = names[0]
		}
	}
	if v := values(16); len(v) > 0 {
		ids := make([]uint32, len(v))
		for i, b := range v {
			if len(b) < 4 {
				return errors.New("invalid DHCPv6 vendor class")
			}
			ids[i] = binary.BigEndian.Uint32(b)
			rest := b[4:]
			for len(rest) > 0 {
				if len(rest) < 2 {
					return errors.New("truncated DHCPv6 vendor class")
				}
				n := int(binary.BigEndian.Uint16(rest))
				rest = rest[2:]
				if n > len(rest) {
					return errors.New("truncated DHCPv6 vendor class data")
				}
				rest = rest[n:]
			}
		}
		if len(ids) == 1 {
			h.EnterpriseID = &ids[0]
		}
	}
	return nil
}
func fqdn(b []byte) (string, bool, error) {
	// RFC 4704 permits an option containing only Flags: the client is asking
	// the server to provide a name. DNS wire names are limited to 255 octets.
	// https://www.rfc-editor.org/rfc/rfc4704.html#section-4.2
	if len(b) < 1 || len(b)-1 > 255 {
		return "", false, errors.New("invalid DHCPv6 FQDN")
	}
	b = b[1:]
	if len(b) == 0 {
		return "", true, nil
	}
	var labels []string
	for {
		if len(b) == 0 {
			break
		} // RFC 4704 permits a partial name without root.
		n := int(b[0])
		b = b[1:]
		if n == 0 {
			break
		}
		if n > 63 || n > len(b) {
			if n > 63 {
				return "", false, nil
			} // compressed or unsupported label form
			return "", false, errors.New("invalid DHCPv6 FQDN label")
		}
		label := b[:n]
		b = b[n:]
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return "", false, nil
			}
		}
		labels = append(labels, string(label))
	}
	if len(b) != 0 || len(labels) == 0 {
		return "", false, errors.New("invalid DHCPv6 FQDN")
	}
	return strings.Join(labels, "."), true, nil
}
