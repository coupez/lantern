package scanner

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestONVIFDescriptionURLs(t *testing.T) {
	peer := netip.MustParseAddr("192.0.2.40")
	ad := Advertisement{
		Protocol: "ws-discovery", Service: "probe-match",
		Properties: map[string]string{
			"types":  "{urn:other}Device {http://www.onvif.org/ver10/device/wsdl}Device",
			"xaddrs": "http://example.invalid/device http://192.0.2.40:8899/onvif/device_service http://192.0.2.40:8899/onvif/device_service https://192.0.2.40/secure%20service",
		},
	}
	want := []string{"http://192.0.2.40:8899/onvif/device_service", "https://192.0.2.40/secure%20service"}
	if got := onvifDescriptionURLs(peer, ad); !reflect.DeepEqual(got, want) {
		t.Fatalf("onvifDescriptionURLs() = %#v, want %#v", got, want)
	}

	v6 := netip.MustParseAddr("fe80::40%en0")
	ad.Properties["types"] = "{http://www.onvif.org/ver10/network/wsdl}NetworkVideoTransmitter"
	ad.Properties["xaddrs"] = "http://[fe80::40%25en0]:8080/onvif/device_service"
	if got, want := onvifDescriptionURLs(v6, ad), []string{"http://[fe80::40%25en0]:8080/onvif/device_service"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scoped endpoint = %#v, want %#v", got, want)
	}
}

func TestONVIFDescriptionURLsRejectsIneligibleAndUntrustedInputs(t *testing.T) {
	peer := netip.MustParseAddr("192.0.2.40")
	base := Advertisement{Protocol: "ws-discovery", Service: "probe-match", Properties: map[string]string{
		"types": "{http://www.onvif.org/ver10/device/wsdl}Device", "xaddrs": "http://192.0.2.40/onvif/device_service",
	}}
	for name, mutate := range map[string]func(*Advertisement){
		"protocol": func(a *Advertisement) { a.Protocol = "mdns" },
		"service":  func(a *Advertisement) { a.Service = "hello" },
		"scope only": func(a *Advertisement) {
			a.Properties["types"] = ""
			a.Properties["scopes"] = "onvif://www.onvif.org/type/Device"
		},
		"prefix lookalike": func(a *Advertisement) { a.Properties["types"] = "{http://www.onvif.org/ver10/device/wsdl}DeviceExtra" },
		"other namespace":  func(a *Advertisement) { a.Properties["types"] = "{urn:evil}Device" },
		"too many": func(a *Advertisement) {
			a.Properties["xaddrs"] = strings.TrimSpace(strings.Repeat("http://192.0.2.40/onvif/device_service ", 33))
		},
	} {
		t.Run(name, func(t *testing.T) {
			ad := base
			ad.Properties = map[string]string{"types": base.Properties["types"], "xaddrs": base.Properties["xaddrs"]}
			mutate(&ad)
			if got := onvifDescriptionURLs(peer, ad); len(got) != 0 {
				t.Fatalf("onvifDescriptionURLs() = %#v, want no endpoint", got)
			}
		})
	}

	for _, raw := range []string{
		"http://192.0.2.41/onvif/device_service",
		"http://example.invalid/onvif/device_service",
		"ftp://192.0.2.40/onvif/device_service",
		"http://u:p@192.0.2.40/onvif/device_service",
		"http://192.0.2.40/onvif/device_service?",
		"http://192.0.2.40/onvif/device_service#",
		"http://192.0.2.40/onvif/../admin",
		"http://192.0.2.40/onvif/%252e%252e/admin",
		"http://192.0.2.40/onvif/%5cadmin",
		"http://192.0.2.40",
		"http://192.0.2.40:0/onvif/device_service",
	} {
		if _, err := onvifURL(raw, peer); err == nil {
			t.Fatalf("onvifURL(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestONVIFDescriptionURLLimitPreservesOrder(t *testing.T) {
	peer := netip.MustParseAddr("192.0.2.40")
	ad := Advertisement{Protocol: "ws-discovery", Service: "probe-match", Properties: map[string]string{
		"types":  "{http://www.onvif.org/ver10/device/wsdl}Device",
		"xaddrs": "http://192.0.2.40/a http://192.0.2.40/b http://192.0.2.40/c http://192.0.2.40/d http://192.0.2.40/e",
	}}
	want := []string{"http://192.0.2.40/a", "http://192.0.2.40/b", "http://192.0.2.40/c", "http://192.0.2.40/d"}
	if got := onvifDescriptionURLs(peer, ad); !reflect.DeepEqual(got, want) {
		t.Fatalf("onvif endpoint limit = %#v, want %#v", got, want)
	}
}

func TestONVIFSOAPContentType(t *testing.T) {
	for _, raw := range []string{"application/soap+xml", "application/soap+xml; charset=utf-8", "application/soap+xml; charset=UTF-8; action=\"urn:action\""} {
		if !validONVIFContentType(raw) {
			t.Fatalf("validONVIFContentType(%q) = false", raw)
		}
	}
	for _, raw := range []string{"text/xml", "application/soap+xml; charset=iso-8859-1", "application/soap+xml; charset=us-ascii", "application/soap+xml; charset"} {
		if validONVIFContentType(raw) {
			t.Fatalf("validONVIFContentType(%q) = true", raw)
		}
	}
}
