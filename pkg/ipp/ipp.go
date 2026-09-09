// Package ipp implements the bounded IPP subset used for read-only printer identity.
package ipp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxMessage    = 256 << 10
	maxAttributes = 1024
	maxField      = 2048
)

var selected = map[string]bool{"printer-make-and-model": true, "printer-name": true, "printer-device-id": true}

// Request encodes a bounded IPP/1.1 Get-Printer-Attributes request for uri.
func Request(uri string, requestID int32) ([]byte, error) {
	if requestID <= 0 || !safe(uri) || len(uri) > maxField || strings.TrimSpace(uri) != uri {
		return nil, errors.New("invalid IPP request")
	}
	u, err := url.Parse(uri)
	if err != nil || (u.Scheme != "ipp" && u.Scheme != "ipps") || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid printer URI")
	}
	b := []byte{1, 1, 0, 0x0b, 0, 0, 0, 0, 1}
	binary.BigEndian.PutUint32(b[4:8], uint32(requestID))
	b = attr(b, 0x47, "attributes-charset", "utf-8")
	b = attr(b, 0x48, "attributes-natural-language", "en")
	b = attr(b, 0x45, "printer-uri", uri)
	for i, v := range []string{"printer-make-and-model", "printer-name", "printer-device-id"} {
		n := "requested-attributes"
		if i > 0 {
			n = ""
		}
		b = attr(b, 0x44, n, v)
	}
	return append(b, 3), nil
}
func attr(b []byte, t byte, n, v string) []byte {
	b = append(b, t, byte(len(n)>>8), byte(len(n)))
	b = append(b, n...)
	b = append(b, byte(len(v)>>8), byte(len(v)))
	return append(b, v...)
}

// ParseResponse validates a Get-Printer-Attributes response and returns only
// the requested, safe printer identity strings.
func ParseResponse(b []byte, requestID int32) (map[string]string, error) {
	if requestID <= 0 || len(b) < 9 || len(b) > maxMessage {
		return nil, errors.New("invalid or oversized IPP response")
	}
	if !((b[0] == 1 && b[1] <= 1) || (b[0] == 2 && b[1] <= 2)) {
		return nil, errors.New("unsupported IPP version")
	}
	if s := binary.BigEndian.Uint16(b[2:4]); s > 0xff {
		return nil, fmt.Errorf("IPP request failed with status 0x%04x", s)
	}
	if int32(binary.BigEndian.Uint32(b[4:8])) != requestID {
		return nil, errors.New("IPP response request ID mismatch")
	}
	p := parser{b: b[8:], fields: map[string]string{}, seen: map[string]bool{}}
	if err := p.parse(); err != nil {
		return nil, err
	}
	return p.fields, nil
}

type parser struct {
	b                        []byte
	group                    byte
	last                     string
	count, printers, opattrs int
	opseen, charset, ascii   bool
	fields                   map[string]string
	seen                     map[string]bool
}

func (p *parser) parse() error {
	for {
		if len(p.b) == 0 {
			return errors.New("missing end-of-attributes")
		}
		t := p.b[0]
		if t <= 0x0f {
			p.b = p.b[1:]
			if p.group == 1 && p.opattrs < 2 {
				return errors.New("incomplete operation attributes")
			}
			if t == 3 {
				if len(p.b) != 0 {
					return errors.New("trailing IPP data")
				}
				if !p.opseen || !p.charset {
					return errors.New("missing operation attributes")
				}
				return nil
			}
			if t == 0 {
				return errors.New("reserved delimiter")
			}
			if !p.opseen && t != 1 {
				return errors.New("operation group must be first")
			}
			if t == 1 {
				if p.opseen {
					return errors.New("multiple operation groups")
				}
				p.opseen = true
			}
			p.group, p.last = t, ""
			if t == 4 {
				p.printers++
				if p.printers > 1 {
					return errors.New("multiple printer groups")
				}
			}
			continue
		}
		if p.group == 0 {
			return errors.New("IPP attribute before operation group")
		}
		tag, name, value, err := p.record(false)
		if err != nil {
			return err
		}
		if p.group == 1 {
			p.opattrs++
			if p.opattrs > 2 && (name == "attributes-charset" || name == "attributes-natural-language") {
				return errors.New("duplicate required operation attribute")
			}
			if p.opattrs == 1 {
				if tag != 0x47 || name != "attributes-charset" {
					return errors.New("charset must be first")
				}
				c := strings.ToLower(string(value))
				if c != "utf-8" && c != "us-ascii" {
					return errors.New("unsupported charset")
				}
				p.charset = true
				p.ascii = c == "us-ascii"
			}
			if p.opattrs == 2 && (tag != 0x48 || name != "attributes-natural-language") {
				return errors.New("natural language must be second")
			}
			if p.opattrs == 2 && !safe(string(value)) {
				return errors.New("invalid natural language")
			}
		}
		sel := p.group == 4 && selected[name]
		if sel {
			if p.seen[name] {
				return fmt.Errorf("duplicate selected attribute %s", name)
			}
			p.seen[name] = true
		}
		if tag == 0x34 {
			if len(value) != 0 {
				return errors.New("invalid beginCollection")
			}
			if err := p.collection(1); err != nil {
				return err
			}
			continue
		}
		if tag == 0x37 || tag == 0x4a {
			return errors.New("collection tag outside collection")
		}
		if sel {
			if tag == 0x10 || tag == 0x12 || tag == 0x13 {
				if len(value) != 0 {
					return fmt.Errorf("invalid out-of-band attribute %s", name)
				}
				continue
			}
			text, ok := stringValue(name, tag, value)
			if !ok {
				return fmt.Errorf("invalid selected attribute %s", name)
			}
			if p.ascii {
				for _, c := range []byte(text) {
					if c >= 0x80 {
						return fmt.Errorf("non-ASCII selected attribute %s", name)
					}
				}
			}
			p.fields[name] = text
		}
	}
}
func (p *parser) record(collection bool) (byte, string, []byte, error) {
	if p.count >= maxAttributes {
		return 0, "", nil, errors.New("attribute limit exceeded")
	}
	p.count++
	if len(p.b) < 5 {
		return 0, "", nil, errors.New("truncated attribute")
	}
	tag := p.b[0]
	p.b = p.b[1:]
	if collection && tag <= 0x0f {
		return 0, "", nil, errors.New("delimiter inside collection")
	}
	if tag == 0x7f {
		if len(p.b) < 4 {
			return 0, "", nil, errors.New("truncated extension tag")
		}
		p.b = p.b[4:]
	}
	if len(p.b) < 4 {
		return 0, "", nil, errors.New("truncated attribute")
	}
	nl := int(binary.BigEndian.Uint16(p.b[:2]))
	p.b = p.b[2:]
	if nl > maxField || len(p.b) < nl+2 {
		return 0, "", nil, errors.New("invalid attribute name")
	}
	nb := p.b[:nl]
	p.b = p.b[nl:]
	vl := int(binary.BigEndian.Uint16(p.b[:2]))
	p.b = p.b[2:]
	if vl > maxField || len(p.b) < vl {
		return 0, "", nil, errors.New("invalid attribute value")
	}
	v := p.b[:vl]
	p.b = p.b[vl:]
	if collection {
		if nl != 0 {
			return 0, "", nil, errors.New("named collection value")
		}
		return tag, "", v, nil
	}
	if nl == 0 {
		if p.last == "" {
			return 0, "", nil, errors.New("continuation without name")
		}
		return tag, p.last, v, nil
	}
	if !safe(string(nb)) {
		return 0, "", nil, errors.New("invalid attribute name")
	}
	p.last = string(nb)
	return tag, p.last, v, nil
}
func (p *parser) collection(depth int) error {
	if depth > 8 {
		return errors.New("collection depth exceeded")
	}
	member, needsValue := false, false
	for {
		tag, _, v, err := p.record(true)
		if err != nil {
			return err
		}
		switch tag {
		case 0x4a:
			if needsValue || len(v) == 0 || !safe(string(v)) {
				return errors.New("invalid member name")
			}
			member = true
			needsValue = true
		case 0x34:
			if !member || len(v) != 0 {
				return errors.New("invalid nested collection")
			}
			if err := p.collection(depth + 1); err != nil {
				return err
			}
			needsValue = false
		case 0x37:
			if needsValue || len(v) != 0 {
				return errors.New("invalid endCollection")
			}
			return nil
		default:
			if !member {
				return errors.New("collection value without member")
			}
			needsValue = false
		}
	}
}
func stringValue(name string, tag byte, v []byte) (string, bool) {
	text := v
	expectedText := name != "printer-name"
	if tag == 0x35 || tag == 0x36 {
		if (expectedText && tag != 0x35) || (!expectedText && tag != 0x36) || len(v) < 4 {
			return "", false
		}
		n := int(binary.BigEndian.Uint16(v[:2]))
		if n == 0 || len(v) < n+4 || !safe(string(v[2:2+n])) {
			return "", false
		}
		m := int(binary.BigEndian.Uint16(v[2+n : 2+n+2]))
		if n+4+m != len(v) {
			return "", false
		}
		text = v[n+4:]
	} else if (expectedText && tag != 0x41) || (!expectedText && tag != 0x42) {
		return "", false
	}
	if len(text) == 0 || len(text) > maxField || !safe(string(text)) {
		return "", false
	}
	return string(text), true
}
func safe(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
