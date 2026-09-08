package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func descriptionWithFields(fields string) string {
	return `<root xmlns="urn:schemas-upnp-org:device-1-0"><device>` + fields + `</device></root>`
}

func TestDescriptionAmbiguousIdentityNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			listener, err := net.Listen("tcp", net.JoinHostPort(address, "0"))
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fields := `<modelName>First</modelName><modelName>Second</modelName>`
				if r.URL.Path == "/nested" {
					fields = `<modelName>First<part>Middle</part>Last</modelName>`
				}
				fmt.Fprint(w, descriptionWithFields(`<UDN>uuid:device</UDN>`+fields))
			}))
			server.Listener.Close()
			server.Listener = listener
			server.Start()
			defer server.Close()
			for _, path := range []string{"/duplicate", "/nested"} {
				d := Device{IP: netip.MustParseAddr(address), Advertisements: []Advertisement{{Protocol: "ssdp", Properties: map[string]string{
					"location": server.URL + path, "usn": "uuid:device::upnp:rootdevice",
				}}}}
				before := d.Clone()
				enrichDescriptions(context.Background(), &d, time.Second)
				if !reflect.DeepEqual(d, before) || identify(d.Advertisements) != nil {
					t.Fatalf("ambiguous HTTP description added identity: %+v", d)
				}
			}
		})
	}
}

func TestDescriptionRejectsAmbiguousIdentityFields(t *testing.T) {
	for _, field := range []string{"friendlyName", "manufacturer", "modelName", "modelNumber", "deviceType", "UDN"} {
		t.Run(field, func(t *testing.T) {
			for _, fields := range []string{
				"<" + field + ">First</" + field + "><" + field + ">Second</" + field + ">",
				"<" + field + "/><" + field + ">Second</" + field + ">",
				"<" + field + ">First</" + field + "><u:" + field + ` xmlns:u="urn:schemas-upnp-org:device-1-0">Second</u:` + field + ">",
				"<" + field + ">First<part>Middle</part>Last</" + field + ">",
				"<" + field + `>First<x:part xmlns:x="urn:extension"/>Last</` + field + ">",
			} {
				if devices, err := parseDescription(descriptionWithFields(fields)); err == nil || devices != nil {
					t.Fatalf("accepted ambiguous %s: devices=%v err=%v", fields, devices, err)
				}
			}
		})
	}
}

func TestDescriptionPreservesSplitTextAndExtensionIsolation(t *testing.T) {
	fields := `<modelName>Router <![CDATA[42 &]]><!-- split --> Office</modelName>` +
		`<x:modelName xmlns:x="urn:extension">Unrelated</x:modelName>` +
		`<extension><modelName>Nested extension value</modelName></extension>` +
		`<UDN>uuid:root</UDN><deviceList><device><modelName>Child</modelName><UDN>uuid:child</UDN></device></deviceList>`
	devices, err := parseDescription(descriptionWithFields(fields))
	if err != nil || len(devices) != 2 || devices[0]["modelName"] != "Router 42 & Office" || devices[1]["modelName"] != "Child" {
		t.Fatal(devices, err)
	}
	// Field limits apply to the accumulated text, including separate CDATA tokens.
	if _, err := parseDescription(descriptionWithFields("<modelName>" + strings.Repeat("x", 2048) + "<![CDATA[x]]></modelName>")); err == nil {
		t.Fatal("split text bypassed field size limit")
	}
}
