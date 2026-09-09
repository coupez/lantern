package ui

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coupez/lantern/pkg/scanner"
	"github.com/coupez/lantern/pkg/vendors"
	"github.com/rivo/uniseg"
)

func TestAddressRoleDisplayAndSearch(t *testing.T) {
	v, _ := vendors.Lookup("00:00:5e:00:01:2a")
	d := scanner.Device{IP: netip.MustParseAddr("192.0.2.1"), MAC: "00:00:5e:00:01:2a", Vendor: v, Evidence: []string{"neighbor-cache"}}
	r := scanner.Report{Devices: []scanner.Device{d}}
	for _, width := range []int{60, 100} {
		var out bytes.Buffer
		(&UI{Out: &out, Width: width}).Report(r)
		if !strings.Contains(out.String(), "VRRP/CARP virtual MAC range") || !strings.Contains(out.String(), "ID 42") || !strings.Contains(out.String(), "0 responsive") {
			t.Fatal(out.String())
		}
		for _, line := range strings.Split(out.String(), "\n") {
			if uniseg.StringWidth(line) > width {
				t.Fatal("role label overflow", line)
			}
		}
	}
	var out bytes.Buffer
	(&UI{Out: &out, Width: 100}).Details(r)
	for _, value := range append([]string{v.Name, "Range ID", "42", v.AddressRole.Prefix}, v.AddressRole.References...) {
		if !strings.Contains(out.String(), value) {
			t.Fatal("inspector lost range metadata", value, out.String())
		}
	}
	m := watchModel{}
	m.accept(r)
	for _, query := range []string{"carp", "vrrp", "id 42", v.AddressRole.Prefix} {
		m.query = query
		if len(m.devices()) != 1 {
			t.Fatal("address metadata not searchable", query)
		}
	}
	m.query = ""
	if frame := m.frame(&UI{}, 120, 24, time.Now()); !strings.Contains(frame, "VRRP/CARP") {
		t.Fatal("unnamed virtual range was hidden", frame)
	}
	next := d.Clone()
	next.MAC = "02:11:22:33:44:55"
	next.Vendor, _ = vendors.Lookup(next.MAC)
	m.accept(scanner.Report{Devices: []scanner.Device{next}})
	m.query = "carp"
	if len(m.devices()) != 0 {
		t.Fatal("old range survived refresh")
	}
	d.Names = []string{"named-gateway"}
	if deviceName(d) != "named-gateway" {
		t.Fatal("range label replaced a name")
	}
}
