package scanner

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
)

const rokuFixture = `<device-info><vendor-name>Roku</vendor-name><model-number>4200X</model-number><model-name>Roku 3</model-name><user-device-name>Living room</user-device-name><software-version>14.0.0</software-version><software-build>1234</software-build><is-tv>false</is-tv><serial-number>do-not-retain</serial-number><wifi-mac>00:11:22:33:44:55</wifi-mac></device-info>`

func TestParseRokuDescription(t *testing.T) {
	fields, err := parseRokuDescription([]byte(rokuFixture))
	if err != nil || fields["vendor-name"] != "Roku" || fields["model-name"] != "Roku 3" || fields["is-tv"] != "false" || len(fields) != 7 {
		t.Fatal(fields, err)
	}
	for _, key := range []string{"serial-number", "wifi-mac", "ethernet-mac", "keyed-developer-id"} {
		if fields[key] != "" {
			t.Fatal("retained sensitive field", key, fields)
		}
	}
	for _, raw := range []string{
		`<device-info><model-number>X</model-number><unknown><value>ok</value></unknown></device-info>`,
		`<?xml version="1.0"?><device-info><model-name>Model</model-name></device-info>`,
		`<device-info><model-name>Model</model-name><is-tv>true</is-tv></device-info>`,
	} {
		if _, err := parseRokuDescription([]byte(raw)); err != nil {
			t.Fatal(raw, err)
		}
	}
}

func TestParseRokuDescriptionRejectsInvalidInput(t *testing.T) {
	for _, raw := range []string{
		`<other><model-name>Model</model-name></other>`,
		`<x:device-info xmlns:x="urn:x"><model-name>Model</model-name></x:device-info>`,
		`<device-info><model-name>One</model-name><model-name>Two</model-name></device-info>`,
		`<device-info><model-name>One<x>Two</x></model-name></device-info>`,
		`<!DOCTYPE device-info><device-info><model-name>Model</model-name></device-info>`,
		`<device-info><model-name>Model</model-name></device-info><extra/>`,
		`<device-info><model-name>Model</model-name></device-info> trailing`,
		`<device-info><model-name>Model</model-name><is-tv>yes</is-tv></device-info>`,
		`<device-info><vendor-name>Roku</vendor-name></device-info>`,
		"<device-info><model-name>Model</model-name><is-tv>tru\u202ee</is-tv></device-info>",
		`<device-info>` + strings.Repeat("<x>", 16) + `<model-name>Model</model-name>` + strings.Repeat("</x>", 16) + `</device-info>`,
		`<device-info><model-name>` + strings.Repeat("x", 2049) + `</model-name></device-info>`,
	} {
		if _, err := parseRokuDescription([]byte(raw)); err == nil {
			t.Fatalf("accepted malformed document %.200q", raw)
		}
	}
	if _, err := parseRokuDescription([]byte("<device-info><model-name>\xff</model-name></device-info>")); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
	if _, err := parseRokuDescription([]byte(strings.Repeat(" ", maxRokuBytes) + rokuFixture)); err == nil {
		t.Fatal("accepted oversized document")
	}
}

func TestRokuDescriptionURL(t *testing.T) {
	for _, peer := range []string{"192.0.2.1", "2001:db8::1", "fe80::1%test0"} {
		ip := netip.MustParseAddr(peer)
		host := peer
		if ip.Is6() {
			host = "[" + strings.Replace(peer, "%", "%25", 1) + "]"
		}
		ad := Advertisement{Protocol: "ssdp", Service: "ROKU:ECP", Properties: map[string]string{"location": "http://" + host + ":8060/base?untrusted=yes"}}
		if ip.Is4() {
			ad.Properties["location"] = "http://" + peer + ":8060/base?untrusted=yes"
		}
		u := rokuDescriptionURL(ip, ad)
		if u == "" || !strings.Contains(u, "/query/device-info") || strings.Contains(u, "?") || strings.Contains(u, "/base") {
			t.Fatal(peer, u)
		}
	}
	peer := netip.MustParseAddr("192.0.2.1")
	valid := Advertisement{Protocol: "ssdp", Service: "roku:ecp", Properties: map[string]string{"location": "http://192.0.2.1:8060/"}}
	for _, mutate := range []func(*Advertisement){
		func(a *Advertisement) { a.Protocol = "mdns" },
		func(a *Advertisement) { a.Service = "roku:ecp:other" },
		func(a *Advertisement) { a.Properties["location"] = "http://192.0.2.2:8060/" },
		func(a *Advertisement) { a.Properties["location"] = "https://192.0.2.1:8060/" },
		func(a *Advertisement) { a.Properties["location"] = "http://user:pass@192.0.2.1:8060/" },
		func(a *Advertisement) { a.Properties["location"] = "" },
	} {
		ad := valid
		ad.Properties = map[string]string{"location": valid.Properties["location"]}
		mutate(&ad)
		if rokuDescriptionURL(peer, ad) != "" {
			t.Fatal("accepted invalid endpoint", ad)
		}
	}
}

func TestRokuSSDPSelectorsAreNotRepaired(t *testing.T) {
	for _, field := range []string{"ST: ro\u202eku:ecp", "LOCATION: http://192.0.2.1/\u202epath"} {
		raw := "HTTP/1.1 200 OK\r\nST: roku:ecp\r\nLOCATION: http://192.0.2.1:8060/\r\n" + field + "\r\n\r\n"
		if _, ok := parseSSDP([]byte(raw)); ok {
			t.Fatal("cleaning repaired an identity-read selector", field)
		}
	}
	c := multicastErrorFixture(t, "SSDP", 0)
	c.failWrite = 2
	c.writeErr = io.ErrClosedPipe
	if _, err := collectFixture(context.Background(), "SSDP", c); !errors.Is(err, io.ErrClosedPipe) || c.reads != 0 || c.writes != 2 {
		t.Fatal("second search failure was hidden", err, c.reads, c.writes)
	}
}

func FuzzRokuDescription(f *testing.F) {
	f.Add([]byte(rokuFixture))
	f.Add([]byte(`<device-info><model-number>X</model-number></device-info>`))
	f.Add([]byte(`<device-info><model-name></model-name><model-name>X</model-name></device-info>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		fields, err := parseRokuDescription(b)
		if err != nil {
			return
		}
		if fields["model-name"] == "" && fields["model-number"] == "" {
			t.Fatal("accepted missing identity")
		}
		for k, v := range fields {
			if !rokuFields[k] || len(v) > 2048 {
				t.Fatal("unbounded/unselected field", k)
			}
		}
		if tv, ok := fields["is-tv"]; ok && tv != "true" && tv != "false" {
			t.Fatal("invalid classification", tv)
		}
	})
}
