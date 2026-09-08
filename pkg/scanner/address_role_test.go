package scanner

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/coupez/lantern/pkg/vendors"
)

func TestMACRoleRemainsAddressMetadata(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	o := Defaults()
	o.Target = netip.PrefixFrom(ip, 32)
	o.Ports = nil
	o.ICMP, o.Multicast, o.Descriptions, o.Resolve = false, false, false, false
	e := Engine{NeighborSource: func(context.Context) (map[netip.Addr]string, error) {
		return map[netip.Addr]string{ip: "00:00:5e:00:01:2a"}, nil
	}}
	updates := 0
	r, err := e.Scan(context.Background(), o, func(event Event) {
		if event.Type == "device_update" {
			updates++
			role := event.Device.Vendor.AddressRole
			if role == nil || role.Identifier != 42 {
				t.Fatal("missing enriched role", event.Device)
			}
			role.Name = "changed by event consumer"
			role.References[0] = "changed by event consumer"
		}
	})
	if err != nil || updates != 1 || len(r.Devices) != 1 || r.Probed != 0 {
		t.Fatal(r, err)
	}
	d := r.Devices[0]
	if d.Responsive() || d.Kind != "device" || d.Identity != nil || len(d.Ports) > 0 || len(d.Advertisements) > 0 || d.Vendor.AddressRole.Identifier != 42 || !strings.Contains(d.Vendor.AddressRole.References[0], "rfc9568") {
		t.Fatal("range label invented physical identity/response or was aliased", d)
	}
	copy := d.Clone()
	copy.Vendor.AddressRole.References[0] = "copy mutation"
	copy.Vendor.AddressRole.Identifier = 7
	if d.Vendor.AddressRole.Identifier != 42 || strings.Contains(d.Vendor.AddressRole.References[0], "mutation") {
		t.Fatal("clone shared address-role metadata")
	}
	path := t.TempDir() + "/report.json"
	if err := Save(path, r); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.Devices[0].Vendor.AddressRole.Identifier != 42 || len(Diff(r, loaded)) > 0 {
		t.Fatal("snapshot lost role", loaded, err)
	}
	legacy := d.Clone()
	legacy.Vendor.AddressRole = nil
	if changes := Diff(Report{Devices: []Device{legacy}}, r); len(changes) != 1 || changes[0].Field != "coverage" {
		t.Fatal("derived role manufactured device change", changes)
	}
	next := d.Clone()
	next.MAC = "00:00:5e:00:01:2b"
	next.Vendor, _ = vendors.Lookup(next.MAC)
	changes := Diff(Report{Devices: []Device{d}}, Report{Devices: []Device{next}})
	if len(changes) != 1 || changes[0].Field != "mac" {
		t.Fatal("changed virtual identifier did not retain MAC observation semantics", changes)
	}
}
