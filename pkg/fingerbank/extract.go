// Package fingerbank converts one observed DHCP exchange into the small,
// privacy-preserving attribute set accepted by Fingerbank's interrogator.
package fingerbank

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/coupez/lantern/pkg/dhcp"
	"github.com/coupez/lantern/pkg/observe"
)

type Attributes struct {
	DHCPFingerprint  string `json:"dhcp_fingerprint,omitempty"`
	DHCP6Fingerprint string `json:"dhcp6_fingerprint,omitempty"`
	DHCPVendor       string `json:"dhcp_vendor,omitempty"`
	DHCP6Enterprise  string `json:"dhcp6_enterprise,omitempty"`
}

const (
	maxFingerprintOptions = 256
	maxOptionBytes        = 65535
	maxVendorBytes        = 1024
)

// Extract accepts only exchanges matching supported client directions and
// message types. BOOTP op is not retained by observe. It intentionally ignores
// Message.Hints, which are derived display conveniences and can be inconsistent
// with the wire options.
func Extract(o observe.Observation) (Attributes, error) {
	if o.Packet <= 0 || o.CapturedTruncated || o.SourcePort == 0 || o.DestinationPort == 0 {
		return Attributes{}, errors.New("truncated or invalid DHCP observation")
	}
	if o.Message.Version == 4 {
		return extract4(o)
	}
	if o.Message.Version == 6 {
		return extract6(o)
	}
	return Attributes{}, errors.New("unsupported DHCP version")
}

func extract4(o observe.Observation) (Attributes, error) {
	if len(o.Message.Relays) != 0 || o.SourcePort != 68 || o.DestinationPort != 67 || (o.Message.Type != 1 && o.Message.Type != 3) {
		return Attributes{}, errors.New("DHCPv4 observation is not a client discover/request")
	}
	if err := validate4Options(o.Message.Options, o.Message.Type); err != nil {
		return Attributes{}, err
	}
	var prl []byte
	var vendors [][]byte
	for _, option := range o.Message.Options {
		switch option.Code {
		case 55:
			prl = append(prl, option.Data...)
		case 60:
			vendors = append(vendors, option.Data)
		}
	}
	a := Attributes{}
	if len(prl) > 0 {
		if len(prl) > maxFingerprintOptions {
			return Attributes{}, errors.New("DHCPv4 PRL exceeds 256 options")
		}
		a.DHCPFingerprint = byteList(prl)
	}
	if len(vendors) > 0 {
		joined := []byte{}
		for _, fragment := range vendors {
			joined = append(joined, fragment...)
		}
		vendor, err := safeVendor(joined)
		if err != nil {
			return Attributes{}, err
		}
		a.DHCPVendor = vendor
	}
	return a, a.Validate()
}

func extract6(o observe.Observation) (Attributes, error) {
	relay := len(o.Message.Relays) > 0
	validType := map[uint8]bool{1: true, 3: true, 5: true, 6: true, 11: true}
	if relay {
		if o.SourcePort != 547 || o.DestinationPort != 547 || len(o.Message.Relays) > 4 {
			return Attributes{}, errors.New("invalid DHCPv6 relay direction or depth")
		}
		for _, r := range o.Message.Relays {
			if r.Type != 12 {
				return Attributes{}, errors.New("unexpected DHCPv6 relay type")
			}
		}
	} else if o.SourcePort != 546 || o.DestinationPort != 547 {
		return Attributes{}, errors.New("DHCPv6 observation is not a client message")
	}
	if !validType[o.Message.Type] {
		return Attributes{}, errors.New("unsupported DHCPv6 client message type")
	}
	if err := validate6Options(o.Message.Options); err != nil {
		return Attributes{}, err
	}
	var oro []byte
	var enterprise [][]byte
	for _, option := range o.Message.Options {
		switch option.Code {
		case 6:
			oro = append(oro, option.Data...)
		case 16:
			enterprise = append(enterprise, option.Data)
		}
	}
	a := Attributes{}
	if len(oro) > 0 {
		if len(oro)%2 != 0 || len(oro)/2 > maxFingerprintOptions {
			return Attributes{}, errors.New("DHCPv6 ORO is invalid or too large")
		}
		values := make([]string, len(oro)/2)
		for i := range values {
			values[i] = strconv.Itoa(int(binary.BigEndian.Uint16(oro[i*2:])))
		}
		a.DHCP6Fingerprint = strings.Join(values, ",")
	}
	if len(enterprise) > 1 {
		return Attributes{}, errors.New("duplicate DHCPv6 vendor class")
	}
	if len(enterprise) == 1 {
		if len(enterprise[0]) < 4 {
			return Attributes{}, errors.New("DHCPv6 vendor class is truncated")
		}
		for rest := enterprise[0][4:]; len(rest) > 0; {
			if len(rest) < 2 {
				return Attributes{}, errors.New("DHCPv6 vendor class tuple is truncated")
			}
			n := int(binary.BigEndian.Uint16(rest))
			rest = rest[2:]
			if n > len(rest) {
				return Attributes{}, errors.New("DHCPv6 vendor class tuple exceeds option")
			}
			rest = rest[n:]
		}
		a.DHCP6Enterprise = strconv.FormatUint(uint64(binary.BigEndian.Uint32(enterprise[0])), 10)
	}
	return a, a.Validate()
}

func validate4Options(options []dhcp.Option, typ uint8) error {
	if len(options) > 1024 {
		return errors.New("too many DHCPv4 options")
	}
	bytes := 0
	types := 0
	for _, o := range options {
		if o.Code == 0 || o.Code == 255 || o.Code > 255 || len(o.Data) > 255 || (o.Area != "options" && o.Area != "file" && o.Area != "sname") {
			return errors.New("invalid DHCPv4 option")
		}
		bytes += len(o.Data)
		if bytes > maxOptionBytes {
			return errors.New("DHCPv4 options exceed 65535 bytes")
		}
		if o.Code == 53 {
			types++
			if len(o.Data) != 1 || o.Data[0] != typ {
				return errors.New("DHCPv4 message type option disagrees with message")
			}
		}
	}
	if types != 1 {
		return errors.New("DHCPv4 message type option must occur exactly once")
	}
	return nil
}

func validate6Options(options []dhcp.Option) error {
	if len(options) > 1024 {
		return errors.New("too many DHCPv6 options")
	}
	bytes, oro, enterprise := 0, 0, 0
	for _, o := range options {
		if o.Area != "options" {
			return errors.New("invalid DHCPv6 option area")
		}
		bytes += len(o.Data)
		if bytes > maxOptionBytes {
			return errors.New("DHCPv6 options exceed 65535 bytes")
		}
		if o.Code == 6 {
			oro++
			if len(o.Data) == 0 || len(o.Data)%2 != 0 {
				return errors.New("invalid DHCPv6 ORO")
			}
		}
		if o.Code == 16 {
			enterprise++
			if len(o.Data) < 4 {
				return errors.New("invalid DHCPv6 vendor class")
			}
		}
	}
	if oro > 1 || enterprise > 1 {
		return errors.New("duplicate DHCPv6 identifying option")
	}
	return nil
}

func safeVendor(b []byte) (string, error) {
	if len(b) == 0 || len(b) > maxVendorBytes || !utf8.Valid(b) {
		return "", errors.New("invalid DHCP vendor class")
	}
	for _, r := range string(b) {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", errors.New("invalid DHCP vendor class")
		}
	}
	return string(b), nil
}

func byteList(b []byte) string {
	out := make([]string, len(b))
	for i, n := range b {
		out[i] = strconv.Itoa(int(n))
	}
	return strings.Join(out, ",")
}

func (a Attributes) Validate() error {
	if a.DHCPFingerprint != "" && a.DHCP6Fingerprint != "" {
		return errors.New("DHCPv4 and DHCPv6 fingerprints are mutually exclusive")
	}
	if a.DHCPFingerprint != "" && a.DHCP6Enterprise != "" || a.DHCP6Fingerprint != "" && a.DHCPVendor != "" || a.DHCPVendor != "" && a.DHCP6Enterprise != "" {
		return errors.New("cross-version Fingerbank attributes are incompatible")
	}
	if a.DHCPFingerprint == "" && a.DHCP6Fingerprint == "" {
		return errors.New("Fingerbank request requires a DHCP fingerprint")
	}
	if err := validateList(a.DHCPFingerprint, 255, maxFingerprintOptions); err != nil {
		return fmt.Errorf("DHCP fingerprint: %w", err)
	}
	if err := validateList(a.DHCP6Fingerprint, 65535, maxFingerprintOptions); err != nil {
		return fmt.Errorf("DHCPv6 fingerprint: %w", err)
	}
	if a.DHCPVendor != "" {
		if _, err := safeVendor([]byte(a.DHCPVendor)); err != nil {
			return err
		}
	}
	if a.DHCP6Enterprise != "" {
		n, err := strconv.ParseUint(a.DHCP6Enterprise, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != a.DHCP6Enterprise {
			return errors.New("invalid DHCPv6 enterprise")
		}
	}
	return nil
}

func validateList(s string, max, count int) error {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	if len(parts) > count {
		return errors.New("too many options")
	}
	for _, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return errors.New("non-canonical option list")
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > max || strconv.Itoa(n) != p {
			return errors.New("option number out of range")
		}
	}
	return nil
}
