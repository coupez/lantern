package onvif

import (
	"strings"
	"testing"
)

func response(fields string) []byte {
	return []byte(`<s:Envelope xmlns:s="` + soapNS + `"><s:Header/><s:Body><d:GetDeviceInformationResponse xmlns:d="` + tdsNS + `">` + fields + `</d:GetDeviceInformationResponse></s:Body></s:Envelope>`)
}
func fields() string {
	return `<d:Manufacturer xmlns:d="` + tdsNS + `"> Acme </d:Manufacturer><d:Model xmlns:d="` + tdsNS + `"><![CDATA[Cam X]]></d:Model><d:FirmwareVersion xmlns:d="` + tdsNS + `"></d:FirmwareVersion><d:SerialNumber xmlns:d="` + tdsNS + `">SECRET-SERIAL</d:SerialNumber><d:HardwareId xmlns:d="` + tdsNS + `">SECRET-HW</d:HardwareId>`
}

func TestRequestOwnedAndNamespaced(t *testing.T) {
	a, b := Request(), Request()
	a[0] = 'x'
	if b[0] == 'x' || !strings.Contains(string(b), tdsNS) || !strings.Contains(string(b), "GetDeviceInformation") || strings.Contains(string(b), "Security") {
		t.Fatal(string(b))
	}
}

func TestParseResponseAndPrivacy(t *testing.T) {
	got, err := ParseResponse(response(fields()))
	if err != nil || got["Manufacturer"] != " Acme " || got["Model"] != "Cam X" || got["FirmwareVersion"] != "" || len(got) != 3 {
		t.Fatal(got, err)
	}
	if strings.Contains(strings.Join([]string{got["Manufacturer"], got["Model"], got["FirmwareVersion"]}, ""), "SECRET") {
		t.Fatal("unique identifier escaped")
	}
}

func TestRejectMalformedResponses(t *testing.T) {
	tests := map[string][]byte{
		"duplicate field":       response(fields() + `<d:Model xmlns:d="` + tdsNS + `">x</d:Model>`),
		"missing field":         response(strings.Replace(fields(), `<d:HardwareId xmlns:d="`+tdsNS+`">SECRET-HW</d:HardwareId>`, "", 1)),
		"nested field":          response(strings.Replace(fields(), `<d:Model xmlns:d="`+tdsNS+`"><![CDATA[Cam X]]></d:Model>`, `<d:Model xmlns:d="`+tdsNS+`"><x>Cam X</x></d:Model>`, 1)),
		"wrong field namespace": response(strings.Replace(fields(), `<d:Model xmlns:d="`+tdsNS+`">`, `<d:Model xmlns:d="urn:wrong">`, 1)),
		"fault":                 []byte(`<s:Envelope xmlns:s="` + soapNS + `"><s:Body><s:Fault/></s:Body></s:Envelope>`),
		"duplicate body":        []byte(`<s:Envelope xmlns:s="` + soapNS + `"><s:Body><d:GetDeviceInformationResponse xmlns:d="` + tdsNS + `">` + fields() + `</d:GetDeviceInformationResponse></s:Body><s:Body/></s:Envelope>`),
		"trailing root":         append(response(fields()), []byte(`<x/>`)...),
		"directive":             append([]byte(`<!DOCTYPE x>`), response(fields())...),
		"tainted hint":          response(strings.Replace(fields(), " Acme ", "Acme&#x9;X", 1)),
		"oversized":             []byte(strings.Repeat("x", maxXML+1)),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := ParseResponse(in); err == nil {
				t.Fatalf("accepted: %#v", got)
			}
		})
	}
}

func TestExtensionsAndComments(t *testing.T) {
	in := response(`<x:Extension xmlns:x="urn:x"><x:nested/></x:Extension>` + fields())
	if _, err := ParseResponse(append([]byte("<?xml version=\"1.0\"?>\n<!--a-->"), in...)); err != nil {
		t.Fatal(err)
	}
}

func FuzzParseResponse(f *testing.F) {
	f.Add(response(fields()))
	f.Add(Request())
	f.Add([]byte("x"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseResponse(b) })
}
