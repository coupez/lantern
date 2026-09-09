package fingerbank

import (
	"net/netip"
	"testing"

	"github.com/coupez/lantern/pkg/dhcp"
	"github.com/coupez/lantern/pkg/observe"
)

func obs4(src, dst uint16, typ uint8, opts ...dhcp.Option) observe.Observation {
	return observe.Observation{Packet: 1, SourcePort: src, DestinationPort: dst, Message: dhcp.Message{Version: 4, Type: typ, Options: opts}}
}
func obs6(src, dst uint16, typ uint8, opts ...dhcp.Option) observe.Observation {
	return observe.Observation{Packet: 1, SourcePort: src, DestinationPort: dst, Message: dhcp.Message{Version: 6, Type: typ, Options: opts}}
}

func TestExtractDHCPv4PreservesOrderedRawOptionsAndIgnoresHints(t *testing.T) {
	o := obs4(68, 67, 1,
		dhcp.Option{Code: 53, Data: []byte{1}, Area: "options"},
		dhcp.Option{Code: 55, Data: []byte{1, 3}, Area: "options"},
		dhcp.Option{Code: 55, Data: []byte{6}, Area: "file"},
		dhcp.Option{Code: 60, Data: []byte("MSFT 5.0"), Area: "options"})
	o.Message.Hints.RequestedOptions = []uint16{99}
	a, err := Extract(o)
	if err != nil || a.DHCPFingerprint != "1,3,6" || a.DHCPVendor != "MSFT 5.0" {
		t.Fatalf("%#v %v", a, err)
	}
}

func TestExtractRejectsServerDirectionTypeAndRawHintForgery(t *testing.T) {
	cases := []observe.Observation{
		obs4(67, 68, 2, dhcp.Option{Code: 53, Data: []byte{2}, Area: "options"}, dhcp.Option{Code: 55, Data: []byte{1}, Area: "options"}),
		obs4(68, 67, 1, dhcp.Option{Code: 53, Data: []byte{3}, Area: "options"}, dhcp.Option{Code: 55, Data: []byte{1}, Area: "options"}),
		{Packet: 1, CapturedTruncated: true, SourcePort: 68, DestinationPort: 67, Message: dhcp.Message{Version: 4, Type: 1, Hints: dhcp.Hints{RequestedOptions: []uint16{1}}}},
	}
	for i, o := range cases {
		if _, err := Extract(o); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

func TestExtractDHCPv6OROEnterpriseAndRelay(t *testing.T) {
	o := obs6(546, 547, 1,
		dhcp.Option{Code: 6, Data: []byte{0, 1, 0, 3, 0, 6}, Area: "options"},
		dhcp.Option{Code: 16, Data: []byte{0, 0, 0, 42, 0, 3, 'a', 'b', 'c'}, Area: "options"})
	a, err := Extract(o)
	if err != nil || a.DHCP6Fingerprint != "1,3,6" || a.DHCP6Enterprise != "42" {
		t.Fatalf("%#v %v", a, err)
	}
	o.Message.Relays = []dhcp.Relay{{Type: 12}, {Type: 12}}
	o.SourcePort, o.DestinationPort, o.Message.Type = 547, 547, 3
	if _, err = Extract(o); err != nil {
		t.Fatal(err)
	}
	o.Message.Type = 7
	if _, err = Extract(o); err == nil {
		t.Fatal("accepted unsupported relayed client type")
	}
}

func TestAttributesValidation(t *testing.T) {
	for _, a := range []Attributes{{DHCPFingerprint: "01,2"}, {DHCPFingerprint: "1", DHCP6Fingerprint: "2"}, {DHCPFingerprint: "1", DHCP6Enterprise: "42"}, {DHCP6Fingerprint: "2", DHCPVendor: "vendor"}, {DHCPVendor: "vendor", DHCP6Enterprise: "42"}, {DHCPVendor: "bad\x00"}, {DHCP6Enterprise: "042"}, {DHCPVendor: "vendor"}, {}} {
		if err := a.Validate(); err == nil {
			t.Fatalf("accepted %#v", a)
		}
	}
	if err := (Attributes{DHCP6Fingerprint: "1,65535", DHCP6Enterprise: "42"}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractRejectsInvalidVendorAndAmbiguousORO(t *testing.T) {
	base := obs4(68, 67, 3, dhcp.Option{Code: 53, Data: []byte{3}, Area: "options"}, dhcp.Option{Code: 55, Data: []byte{1}, Area: "options"})
	base.Message.Options = append(base.Message.Options, dhcp.Option{Code: 60, Data: []byte{0xff}, Area: "options"})
	if _, err := Extract(base); err == nil {
		t.Fatal("accepted invalid vendor")
	}
	v6 := obs6(546, 547, 1, dhcp.Option{Code: 6, Data: []byte{0, 1}, Area: "options"}, dhcp.Option{Code: 6, Data: []byte{0, 3}, Area: "options"})
	if _, err := Extract(v6); err == nil {
		t.Fatal("accepted duplicate ORO")
	}
}

func TestExtractConcatenatesRFC3396VendorFragments(t *testing.T) {
	o := obs4(68, 67, 3,
		dhcp.Option{Code: 53, Data: []byte{3}, Area: "options"},
		dhcp.Option{Code: 55, Data: []byte{1}, Area: "options"},
		dhcp.Option{Code: 60, Data: []byte("MSFT "), Area: "options"},
		dhcp.Option{Code: 60, Data: []byte("5.0"), Area: "options"})
	a, err := Extract(o)
	if err != nil || a.DHCPVendor != "MSFT 5.0" {
		t.Fatalf("%#v %v", a, err)
	}
}

func TestExtractDoesNotUseAddressFields(t *testing.T) {
	o := obs4(68, 67, 3, dhcp.Option{Code: 53, Data: []byte{3}, Area: "options"}, dhcp.Option{Code: 55, Data: []byte{1}, Area: "options"})
	o.SourceIP, o.DestinationIP = netip.MustParseAddr("192.0.2.1").String(), netip.MustParseAddr("192.0.2.2").String()
	if a, err := Extract(o); err != nil || a.DHCPFingerprint != "1" {
		t.Fatalf("%#v %v", a, err)
	}
}
