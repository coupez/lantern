// Package ubiquiti implements the bounded, read-only Ubiquiti discovery wire format.
package ubiquiti

import (
	"encoding/binary"
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ProtocolReference pins the maintained parser used to document the protocol facts.
const ProtocolReference = "https://sources.debian.org/src/nmap/7.95%2Bdfsg-3/scripts/ubiquiti-discovery.nse/"

// Field is one retained, non-empty textual discovery field.
type Field struct {
	Tag   uint8  `json:"tag"`
	Value string `json:"value"`
}

// Observation is one validated Ubiquiti discovery response.
type Observation struct {
	Version uint8   `json:"version"`
	Command uint8   `json:"command"`
	Fields  []Field `json:"fields"`
}

// Query returns the exact version-specific, read-only discovery probe.
func Query(version uint8) ([]byte, error) {
	switch version {
	case 1:
		return []byte{1, 0, 0, 0}, nil
	case 2:
		return []byte{2, 8, 0, 0}, nil
	default:
		return nil, errors.New("unsupported Ubiquiti discovery version")
	}
}

// Parse validates a discovery response. Retained text has outer ASCII space,
// tab, CR and LF removed; controls or format characters inside remain invalid.
func Parse(b []byte) (Observation, error) {
	if len(b) < 4 || len(b) > 8192 {
		return Observation{}, errors.New("invalid Ubiquiti discovery datagram size")
	}
	version, command := b[0], b[1]
	if !((version == 1 && command == 0) || (version == 2 && (command == 6 || command == 9 || command == 11))) {
		return Observation{}, errors.New("invalid Ubiquiti discovery header")
	}
	if int(binary.BigEndian.Uint16(b[2:4])) != len(b)-4 {
		return Observation{}, errors.New("Ubiquiti discovery body length mismatch")
	}
	retained := map[byte]bool{0x03: true, 0x0b: true, 0x0c: true, 0x14: true, 0x15: true, 0x16: true}
	seen := map[byte]bool{}
	fields := []Field{}
	for body, count := b[4:], 0; len(body) > 0; count++ {
		if count >= 128 {
			return Observation{}, errors.New("too many Ubiquiti discovery fields")
		}
		if len(body) < 3 {
			return Observation{}, errors.New("truncated Ubiquiti discovery field")
		}
		tag := body[0]
		n := int(binary.BigEndian.Uint16(body[1:3]))
		body = body[3:]
		if n > len(body) {
			return Observation{}, errors.New("truncated Ubiquiti discovery value")
		}
		value := body[:n]
		body = body[n:]
		if !retained[tag] {
			continue
		}
		if seen[tag] {
			return Observation{}, errors.New("duplicate retained Ubiquiti discovery field")
		}
		seen[tag] = true
		s := strings.Trim(string(value), " \t\r\n")
		if s == "" {
			continue
		}
		if len(s) > 1024 || !utf8.ValidString(s) {
			return Observation{}, errors.New("invalid Ubiquiti discovery text")
		}
		for _, r := range s {
			if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return Observation{}, errors.New("unsafe Ubiquiti discovery text")
			}
		}
		fields = append(fields, Field{Tag: tag, Value: s})
	}
	if len(fields) == 0 {
		return Observation{}, errors.New("Ubiquiti discovery response has no useful fields")
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Tag < fields[j].Tag })
	return Observation{Version: version, Command: command, Fields: fields}, nil
}
