package scanner

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode/utf8"
)

const rokuInfoReference = "https://developer.roku.com/dev/docs/external-control-api"
const maxRokuBytes = 32 * 1024

var rokuFields = map[string]bool{
	"vendor-name":          true,
	"model-name":           true,
	"model-number":         true,
	"user-device-name":     true,
	"friendly-device-name": true,
	"software-version":     true,
	"software-build":       true,
	"is-tv":                true,
}

// rokuDescriptionURL only permits the documented device-info endpoint on an
// exact Roku ECP SSDP advertisement. The advertised location supplies the
// responder's literal address and port, never the request path or query.
func rokuDescriptionURL(peer netip.Addr, ad Advertisement) string {
	if ad.Protocol != "ssdp" || !strings.EqualFold(ad.Service, "roku:ecp") {
		return ""
	}
	u, err := descriptionURL(ad.Properties["location"], peer)
	if err != nil {
		return ""
	}
	u.Path = "/query/device-info"
	u.RawPath = ""
	u.RawQuery = ""
	u.ForceQuery = false
	return u.String()
}

func fetchRokuDescription(ctx context.Context, peer netip.Addr, raw string) (map[string]string, error) {
	b, err := fetchDeviceDocument(ctx, peer, raw, "text/xml, application/xml", maxRokuBytes)
	if err != nil {
		return nil, err
	}
	return parseRokuDescription(b)
}

// parseRokuDescription accepts a single unnamespaced device-info response and
// retains only the non-sensitive fields needed for device identification.
func parseRokuDescription(b []byte) (map[string]string, error) {
	if len(b) > maxRokuBytes || !utf8.Valid(b) {
		return nil, errors.New("invalid or oversized Roku device document")
	}
	decoder := xml.NewDecoder(bytes.NewReader(b))
	fields := map[string]string{}
	depth := 0
	rootSeen, rootClosed := false, false
	field := ""
	fieldDepth := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := token.(type) {
		case xml.Directive:
			return nil, errors.New("Roku device document directives are not allowed")
		case xml.StartElement:
			if rootClosed {
				return nil, errors.New("trailing Roku device document data")
			}
			if field != "" {
				return nil, fmt.Errorf("Roku field %s contains nested markup", field)
			}
			depth++
			if depth > 16 {
				return nil, errors.New("Roku device document is too deeply nested")
			}
			if depth == 1 {
				if rootSeen || t.Name.Space != "" || t.Name.Local != "device-info" {
					return nil, errors.New("expected an unnamespaced Roku device-info root")
				}
				rootSeen = true
				continue
			}
			if depth == 2 && t.Name.Space == "" && rokuFields[t.Name.Local] {
				if _, exists := fields[t.Name.Local]; exists {
					return nil, fmt.Errorf("duplicate Roku field %s", t.Name.Local)
				}
				fields[t.Name.Local] = ""
				field, fieldDepth = t.Name.Local, depth
			}
		case xml.CharData:
			if depth == 0 {
				if strings.TrimSpace(string(t)) != "" {
					return nil, errors.New("trailing Roku device document text")
				}
				continue
			}
			if field != "" && depth == fieldDepth {
				if len(fields[field])+len(t) > 2048 {
					return nil, fmt.Errorf("Roku field %s is too long", field)
				}
				fields[field] += string(t)
			}
		case xml.EndElement:
			if depth < 1 {
				return nil, errors.New("invalid Roku device document structure")
			}
			if field != "" && depth == fieldDepth {
				field = ""
			}
			depth--
			if depth == 0 {
				rootClosed = true
			}
		}
	}
	if !rootSeen || !rootClosed || depth != 0 {
		return nil, errors.New("incomplete Roku device document")
	}
	for key, value := range fields {
		value = strings.TrimSpace(value)
		if value == "" {
			delete(fields, key)
			continue
		}
		if key == "is-tv" && value != "true" && value != "false" {
			return nil, errors.New("invalid Roku is-tv field")
		}
		fields[key] = value
	}
	if fields["model-name"] == "" && fields["model-number"] == "" {
		return nil, errors.New("incomplete Roku device identity")
	}
	return fields, nil
}
