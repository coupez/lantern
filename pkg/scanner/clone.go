package scanner

import (
	"maps"
	"slices"
)

// Clone returns an independently mutable device, including advertisements and
// identity claims. Immutable strings and value types are copied by value.
func (d Device) Clone() Device {
	if d.Vendor.AddressRole != nil {
		role := *d.Vendor.AddressRole
		role.References = slices.Clone(role.References)
		d.Vendor.AddressRole = &role
	}
	d.Names = slices.Clone(d.Names)
	d.Ports = slices.Clone(d.Ports)
	for i := range d.Ports {
		d.Ports[i].Fingerprint = d.Ports[i].Fingerprint.Clone()
	}
	d.Evidence = slices.Clone(d.Evidence)
	d.Advertisements = slices.Clone(d.Advertisements)
	for i := range d.Advertisements {
		d.Advertisements[i].Properties = maps.Clone(d.Advertisements[i].Properties)
	}
	if d.Identity != nil {
		identity := *d.Identity
		identity.ModelNames = slices.Clone(identity.ModelNames)
		identity.Claims = slices.Clone(identity.Claims)
		d.Identity = &identity
	}
	return d
}
