package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func wsdFixture(probe wsdProbe) string {
	v := probe.version
	return fmt.Sprintf(`<s:Envelope xmlns:s="%s" xmlns:a="%s" xmlns:d="%s" xmlns:t="http://www.onvif.org/ver10/device/wsdl"><s:Header><a:Action>%s/ProbeMatches</a:Action><a:MessageID>urn:uuid:response</a:MessageID><a:RelatesTo>%s</a:RelatesTo></s:Header><s:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:device</a:Address></a:EndpointReference><d:Types>t:Device</d:Types><d:Scopes>onvif://www.onvif.org/name/Front%%20Door onvif://www.onvif.org/hardware/Board%%2F42</d:Scopes><d:XAddrs>http://192.0.2.99/control http://example.invalid/device</d:XAddrs><d:MetadataVersion>1</d:MetadataVersion></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>`, wsdSOAP, v.addressing, v.discovery, v.discovery, probe.id)
}
func testWSDProbes(t *testing.T) []wsdProbe {
	t.Helper()
	probes, err := newWSDProbes()
	if err != nil {
		t.Fatal(err)
	}
	return probes
}
func TestWSDVersionsAndIdentity(t *testing.T) {
	probes := testWSDProbes(t)
	if len(probes) != 2 || probes[0].id == probes[1].id {
		t.Fatal(probes)
	}
	for _, p := range probes {
		root, err := readWSDXML(p.packet)
		if err != nil {
			t.Fatal(err)
		}
		header, _ := root.child(wsdSOAP, "Header", true)
		action, _ := header.value(p.version.addressing, "Action", true)
		if action != p.version.discovery+"/Probe" {
			t.Fatal(action)
		}
		ads, err := parseWSD([]byte(wsdFixture(p)), probes)
		if err != nil || len(ads) != 1 {
			t.Fatal(ads, err)
		}
		ad := ads[0]
		if ad.Protocol != "ws-discovery" || ad.Port != 0 || ad.Instance != "urn:uuid:device" || ad.Properties["types"] != "{http://www.onvif.org/ver10/device/wsdl}Device" {
			t.Fatal(ad)
		}
		id := identify(ads)
		if id == nil || id.Name != "Front Door" || id.Model != "" || id.Manufacturer != "" || len(id.Claims) != 2 {
			t.Fatal(id)
		}
		for _, c := range id.Claims {
			if c.Basis != "advertised" || c.Reference != onvifDiscoveryReference || c.Source != "ws-discovery:urn:uuid:device" {
				t.Fatal(c)
			}
			if c.Field == "hardware" && c.Value != "Board/42" {
				t.Fatal(c)
			}
		}
		if !(Device{Evidence: []string{"ws-discovery"}}).Responsive() {
			t.Fatal("lost live discovery evidence")
		}
		ad.Service = "hello"
		if identify([]Advertisement{ad}) != nil {
			t.Fatal("unsupported message became identity")
		}
	}
}
func TestWSDRejectsInvalidAndUncorrelatedReplies(t *testing.T) {
	probes := testWSDProbes(t)
	p := probes[0]
	fixture := wsdFixture(p)
	for name, bad := range map[string]string{
		"wrong nonce":            strings.ReplaceAll(fixture, p.id, "urn:uuid:other"),
		"wrong version nonce":    strings.ReplaceAll(fixture, p.id, probes[1].id),
		"hello":                  strings.ReplaceAll(fixture, "/ProbeMatches", "/Hello"),
		"namespace lookalike":    strings.ReplaceAll(fixture, p.version.discovery, p.version.discovery+"/fake"),
		"duplicate correlation":  strings.ReplaceAll(fixture, "</a:RelatesTo>", "</a:RelatesTo><a:RelatesTo>other</a:RelatesTo>"),
		"duplicate model scopes": strings.ReplaceAll(fixture, "</d:Scopes>", "</d:Scopes><d:Scopes/>"),
		"nested field":           strings.ReplaceAll(fixture, "<d:Scopes>", "<d:Scopes><nested/>"),
		"missing endpoint":       strings.ReplaceAll(fixture, "<a:Address>urn:uuid:device</a:Address>", ""),
		"duplicate body":         strings.ReplaceAll(fixture, "</s:Body>", "</s:Body><s:Body/>"),
		"relative endpoint":      strings.ReplaceAll(fixture, "urn:uuid:device", "relative"),
		"invalid local QName":    strings.ReplaceAll(fixture, "t:Device", "t:1Device"),
		"mixed structure":        strings.ReplaceAll(fixture, "<s:Body>", "<s:Body>garbage"),
		"bad QName":              strings.ReplaceAll(fixture, "t:Device", "unknown:Device"),
		"negative version":       strings.ReplaceAll(fixture, ">1</d:MetadataVersion>", ">-1</d:MetadataVersion>"),
		"overflow version":       strings.ReplaceAll(fixture, ">1</d:MetadataVersion>", ">4294967296</d:MetadataVersion>"),
		"multiple roots":         fixture + fixture,
		"outside text":           fixture + "ignored",
		"DTD":                    "<!DOCTYPE s:Envelope>" + fixture,
		"too large":              strings.Repeat("x", maxWSDBytes+1),
		"field cap":              strings.ReplaceAll(fixture, "urn:uuid:device", strings.Repeat("x", 8193)),
		"depth cap":              strings.ReplaceAll(fixture, "<d:Scopes>", "<d:Scopes>"+strings.Repeat("<n>", 17)),
	} {
		t.Run(name, func(t *testing.T) {
			if ads, err := parseWSD([]byte(bad), probes); err == nil || ads != nil {
				t.Fatal(ads, err)
			}
		})
	}
	// Namespace prefix spelling may change; expanded types cannot.
	renamed := strings.ReplaceAll(strings.ReplaceAll(fixture, "xmlns:t=", "xmlns:camera="), "t:Device", "camera:Device")
	if ads, err := parseWSD([]byte(renamed), probes); err != nil || len(ads) != 1 {
		t.Fatal(ads, err)
	}
	proxy := strings.ReplaceAll(fixture, "t:Device", "d:DiscoveryProxy")
	if ads, err := parseWSD([]byte(proxy), probes); err != nil || len(ads) != 0 {
		t.Fatal("proxy became device", ads, err)
	}
}
func TestONVIFScopesAreNamespacedClaims(t *testing.T) {
	for _, raw := range []string{
		"http://www.onvif.org/name/Fake", "onvif://www.onvif.org.evil/name/Fake", "onvif://u@www.onvif.org/name/Fake", "onvif://www.onvif.org/name/Fake?q=1", "onvif://www.onvif.org/name/Fake#part", "onvif://www.onvif.org/name/%00Fake", "onvif://www.onvif.org/name/", "onvif://www.onvif.org/other/Fake", "onvif://www.onvif.org/%6eame/Fake",
	} {
		if field, _ := onvifScope(raw); field != "" {
			t.Fatal("accepted scope", raw)
		}
	}
	if field, value := onvifScope("onvif://www.onvif.org/name/A+B%20C"); field != "name" || value != "A+B C" {
		t.Fatal(field, value)
	}
}

type scriptedWSD struct{ scriptedDiscoveryUDP }

func (c *scriptedWSD) SetWriteDeadline(time.Time) error { return nil }
func TestWSDCollectorBoundsAndFailures(t *testing.T) {
	probes := testWSDProbes(t)
	fixture := wsdFixture(probes[0])
	target := netip.MustParsePrefix("192.0.2.0/24")
	peer := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 3702}
	for _, failure := range []error{os.ErrDeadlineExceeded, io.ErrUnexpectedEOF, net.ErrClosed} {
		c := &scriptedWSD{scriptedDiscoveryUDP{packet: []byte(fixture), peer: peer, packetCount: 2, readErr: failure}}
		hits, err := collectWSD(context.Background(), c, peer, target, "", probes)
		if len(hits) != 1 || hits[0].IP.String() != "192.0.2.1" || len(hits[0].Names) != 1 || hits[0].Names[0] != "Front Door" {
			t.Fatal(hits, err)
		}
		if failure == os.ErrDeadlineExceeded {
			if err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, failure) {
			t.Fatal(err)
		}
	}
	c := &scriptedWSD{scriptedDiscoveryUDP{packet: []byte("junk"), peer: peer, packetCount: maxDiscoveryPackets}}
	hits, err := collectWSD(context.Background(), c, peer, target, "", probes)
	if len(hits) != 0 || err == nil || !strings.Contains(err.Error(), "packet limit") || c.reads != maxDiscoveryPackets {
		t.Fatal(hits, err, c.reads)
	}
	for _, invalid := range []*net.UDPAddr{{IP: net.ParseIP("198.51.100.1")}, {IP: net.ParseIP("224.0.0.1")}, {IP: peer.IP, Zone: "other"}} {
		c := &scriptedWSD{scriptedDiscoveryUDP{packet: []byte(fixture), peer: invalid, packetCount: 1, readErr: os.ErrDeadlineExceeded}}
		if hits, err := collectWSD(context.Background(), c, peer, target, "", probes); len(hits) != 0 || err != nil {
			t.Fatal(hits, err)
		}
	}
	for _, short := range []bool{true, false} {
		c := &scriptedWSD{scriptedDiscoveryUDP{peer: peer, readErr: os.ErrDeadlineExceeded}}
		if short {
			c.shortWrite = 1
		} else {
			c.failWrite = 1
			c.writeErr = net.ErrClosed
		}
		if _, err := collectWSD(context.Background(), c, peer, target, "", probes); err == nil || c.reads != 0 {
			t.Fatal(err, c.reads)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c = &scriptedWSD{}
	if hits, err := collectWSD(ctx, c, peer, target, "", probes); len(hits) != 0 || err != nil || c.writes != 0 {
		t.Fatal(hits, err, c.writes)
	}
}
func FuzzWSD(f *testing.F) {
	// Fixed correlation IDs keep the valid seed valid in fuzz worker processes.
	probes := []wsdProbe{{id: "urn:uuid:fuzz-2005", version: wsdVersions[0]}, {id: "urn:uuid:fuzz-2009", version: wsdVersions[1]}}
	f.Add([]byte(wsdFixture(probes[0])))
	f.Add([]byte("<root/>"))
	f.Fuzz(func(t *testing.T, b []byte) { parseWSD(b, probes) })
}

func TestWSDMatchAndNamespaceBudgets(t *testing.T) {
	probes := testWSDProbes(t)
	fixture := wsdFixture(probes[0])
	start, end := strings.Index(fixture, "<d:ProbeMatch>"), strings.Index(fixture, "</d:ProbeMatch>")+len("</d:ProbeMatch>")
	for _, n := range []int{32, 33} {
		b := fixture[:start] + strings.Repeat(fixture[start:end], n) + fixture[end:]
		ads, err := parseWSD([]byte(b), probes)
		if n == 32 && (err != nil || len(ads) != n) {
			t.Fatal(len(ads), err)
		}
		if n == 33 && (err == nil || ads != nil) {
			t.Fatal(len(ads), err)
		}
	}

	proxyFlood := strings.ReplaceAll(fixture[:start]+strings.Repeat(fixture[start:end], 33)+fixture[end:], "t:Device", "d:DiscoveryProxy")
	if ads, err := parseWSD([]byte(proxyFlood), probes); err == nil || ads != nil {
		t.Fatal("proxy matches bypassed match limit", ads, err)
	}
	for _, local := range []string{"Printer", "印刷機", "Device.Type", "_Device"} {
		if !wsdLocalName(local) {
			t.Fatal("valid XML name rejected", local)
		}
	}
	for _, local := range []string{"1Device", "a:b", "x/>", "a b", "a{b}", "", "<x"} {
		if wsdLocalName(local) {
			t.Fatal("invalid XML name accepted", local)
		}
	}
	// QName namespace rebinding is interpreted at the Types element itself.
	b := strings.Replace(fixture, "<d:Types>", `<d:Types xmlns:t="urn:other">`, 1)
	ads, err := parseWSD([]byte(b), probes)
	if err != nil || ads[0].Properties["types"] != "{urn:other}Device" {
		t.Fatal(ads, err)
	}
}
