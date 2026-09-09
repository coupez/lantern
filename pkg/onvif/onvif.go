// Package onvif implements the small SOAP subset needed for ONVIF device information.
package onvif

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const Action = "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"

const (
	soapNS = "http://www.w3.org/2003/05/soap-envelope"
	tdsNS  = "http://www.onvif.org/ver10/device/wsdl"
	maxXML = 32 << 10
)

var requestXML = []byte(`<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><s:Body><tds:GetDeviceInformation/></s:Body></s:Envelope>`)

// Request returns a fresh SOAP 1.2 GetDeviceInformation request.
func Request() []byte { return append([]byte(nil), requestXML...) }

type parser struct {
	d               *xml.Decoder
	depth, elements int
}

func (p *parser) token() (xml.Token, error) {
	t, err := p.d.Token()
	if err != nil {
		return nil, err
	}
	switch t.(type) {
	case xml.Directive:
		return nil, errors.New("XML directives are not allowed")
	case xml.StartElement:
		p.depth++
		p.elements++
		if p.depth > 16 || p.elements > 1024 {
			return nil, errors.New("XML complexity limit exceeded")
		}
	case xml.EndElement:
		p.depth--
	}
	return t, nil
}

func whitespace(t xml.Token) bool {
	c, ok := t.(xml.CharData)
	return ok && strings.TrimSpace(string(c)) == ""
}

func nextContent(p *parser) (xml.Token, error) {
	for {
		t, err := p.token()
		if err != nil {
			return nil, err
		}
		if _, ok := t.(xml.Comment); ok || whitespace(t) {
			continue
		}
		if x, ok := t.(xml.ProcInst); ok && x.Target == "xml" && p.elements == 0 {
			continue
		}
		return t, nil
	}
}

// ParseResponse validates an ONVIF GetDeviceInformation SOAP response and returns
// its non-unique identity hints. SerialNumber and HardwareId are never returned.
func ParseResponse(b []byte) (map[string]string, error) {
	if len(b) == 0 || len(b) > maxXML || !utf8.Valid(b) {
		return nil, errors.New("invalid ONVIF response size or UTF-8")
	}
	p := &parser{d: xml.NewDecoder(bytes.NewReader(b))}
	t, err := nextContent(p)
	if err != nil {
		return nil, err
	}
	env, ok := t.(xml.StartElement)
	if !ok || env.Name.Space != soapNS || env.Name.Local != "Envelope" {
		return nil, errors.New("expected SOAP 1.2 Envelope")
	}
	seenHeader, seenBody := false, false
	var out map[string]string
	for {
		t, err = nextContent(p)
		if err != nil {
			return nil, err
		}
		switch x := t.(type) {
		case xml.EndElement:
			if x.Name != env.Name || !seenBody {
				return nil, errors.New("malformed SOAP Envelope")
			}
			goto trailing
		case xml.StartElement:
			if x.Name.Space == soapNS && x.Name.Local == "Header" && !seenHeader && !seenBody {
				seenHeader = true
				if err := skip(p, x); err != nil {
					return nil, err
				}
			} else if x.Name.Space == soapNS && x.Name.Local == "Body" && !seenBody {
				seenBody = true
				out, err = body(p, x)
				if err != nil {
					return nil, err
				}
			} else {
				return nil, errors.New("unexpected or duplicate Envelope child")
			}
		default:
			return nil, errors.New("unexpected Envelope content")
		}
	}
trailing:
	for {
		t, err = p.token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if _, ok := t.(xml.Comment); ok || whitespace(t) {
			continue
		}
		return nil, errors.New("trailing XML content")
	}
}

func body(p *parser, start xml.StartElement) (map[string]string, error) {
	t, err := nextContent(p)
	if err != nil {
		return nil, err
	}
	r, ok := t.(xml.StartElement)
	if !ok || r.Name.Space != tdsNS || r.Name.Local != "GetDeviceInformationResponse" {
		return nil, errors.New("unexpected SOAP Body response or Fault")
	}
	out, err := parseResponseFields(p, r)
	if err != nil {
		return nil, err
	}
	t, err = nextContent(p)
	if err != nil {
		return nil, err
	}
	e, ok := t.(xml.EndElement)
	if !ok || e.Name != start.Name {
		return nil, errors.New("SOAP Body must contain exactly one response")
	}
	return out, nil
}

func parseResponseFields(p *parser, start xml.StartElement) (map[string]string, error) {
	want := map[string]bool{"Manufacturer": true, "Model": true, "FirmwareVersion": true, "SerialNumber": true, "HardwareId": true}
	seen := map[string]bool{}
	out := map[string]string{}
	for {
		t, err := nextContent(p)
		if err != nil {
			return nil, err
		}
		switch x := t.(type) {
		case xml.EndElement:
			if x.Name != start.Name {
				return nil, errors.New("malformed response")
			}
			for k := range want {
				if !seen[k] {
					return nil, fmt.Errorf("missing %s", k)
				}
			}
			return out, nil
		case xml.StartElement:
			if want[x.Name.Local] && x.Name.Space != tdsNS {
				return nil, fmt.Errorf("wrong namespace for %s", x.Name.Local)
			}
			if x.Name.Space == tdsNS && want[x.Name.Local] {
				if seen[x.Name.Local] {
					return nil, fmt.Errorf("duplicate %s", x.Name.Local)
				}
				seen[x.Name.Local] = true
				v, err := field(p, x)
				if err != nil {
					return nil, err
				}
				if x.Name.Local == "Manufacturer" || x.Name.Local == "Model" || x.Name.Local == "FirmwareVersion" {
					if !safeHint(v) {
						return nil, fmt.Errorf("invalid %s", x.Name.Local)
					}
					out[x.Name.Local] = v
				}
			} else if err := skip(p, x); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("unexpected response content")
		}
	}
}

func field(p *parser, start xml.StartElement) (string, error) {
	var b strings.Builder
	for {
		t, err := p.token()
		if err != nil {
			return "", err
		}
		switch x := t.(type) {
		case xml.CharData:
			if b.Len()+len(x) > 2048 {
				return "", errors.New("ONVIF field too large")
			}
			b.Write(x)
		case xml.Comment:
		case xml.EndElement:
			if x.Name != start.Name {
				return "", errors.New("malformed field")
			}
			return b.String(), nil
		case xml.StartElement:
			return "", errors.New("nested markup in ONVIF field")
		default:
			return "", errors.New("unexpected field content")
		}
	}
}

func safeHint(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range strings.TrimSpace(s) {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func skip(p *parser, start xml.StartElement) error {
	level := 1
	for level > 0 {
		t, err := p.token()
		if err != nil {
			return err
		}
		switch t.(type) {
		case xml.StartElement:
			level++
		case xml.EndElement:
			level--
		}
	}
	return nil
}
