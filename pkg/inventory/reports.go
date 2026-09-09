// Package inventory converts saved protocol reports into unbound scanner evidence.
package inventory

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/coupez/lantern/pkg/android"
	"github.com/coupez/lantern/pkg/scanner"
	"github.com/coupez/lantern/pkg/snmp"
)

const (
	androidRef = "https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/core/java/android/os/Build.java"
	rfc1213Ref = "https://www.rfc-editor.org/rfc/rfc1213.html"
	rfc4133Ref = "https://www.rfc-editor.org/rfc/rfc4133.html"
	sysDescr   = "1.3.6.1.2.1.1.1.0"
	sysObject  = "1.3.6.1.2.1.1.2.0"
	sysName    = "1.3.6.1.2.1.1.5.0"
	parentOID  = "1.3.6.1.2.1.47.1.1.1.1.4"
	mfgOID     = "1.3.6.1.2.1.47.1.1.1.1.12"
	modelOID   = "1.3.6.1.2.1.47.1.1.1.1.13"
)

// Meta is provenance supplied by the saved-report importer.
type Meta struct{ ID, SourceSHA256, BindingSHA256, ObservedAt string }

func validText(s string, n int) bool {
	if s == "" || len(s) > n || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func metaBase(m Meta) (scanner.InventoryObservation, error) {
	if !validText(m.ID, 128) || !validHash(m.SourceSHA256) || !validHash(m.BindingSHA256) {
		return scanner.InventoryObservation{}, errors.New("invalid inventory report metadata")
	}
	return scanner.InventoryObservation{ID: m.ID, SourceSHA256: m.SourceSHA256, BindingSHA256: m.BindingSHA256}, nil
}
func stamp(s string) bool {
	t, e := time.Parse(time.RFC3339Nano, s)
	return e == nil && !t.IsZero() && validText(s, 64)
}
func claim(field, value, key, ref string) scanner.InventoryClaim {
	return scanner.InventoryClaim{Field: field, Value: value, Key: key, Reference: ref}
}
func useful(s string) bool { return s != "" && !strings.EqualFold(s, "unknown") }

// FromAndroid converts a collector-produced Android report without trusting its derived claims.
func FromAndroid(m Meta, r android.Report) (scanner.InventoryObservation, error) {
	o, e := metaBase(m)
	if e != nil {
		return o, e
	}
	server, e := netip.ParseAddrPort(r.Server)
	if e != nil || server.String() != r.Server || server.Port() == 0 || !server.Addr().IsLoopback() || server.Addr().Is4In6() || server.Addr().Zone() != "" || r.Schema != 1 || r.Source != "adb" || r.TransportID == 0 || !stamp(r.CollectedAt) {
		return o, errors.New("invalid Android report provenance")
	}
	if m.ObservedAt != "" && m.ObservedAt != r.CollectedAt {
		return o, errors.New("Android observation timestamp mismatch")
	}
	o.Kind = "android"
	o.Source = "adb://" + r.Server + "/transport/" + strconv.FormatUint(r.TransportID, 10)
	o.ObservedAt = r.CollectedAt
	o.TimeBasis = "collector"
	if !r.Complete {
		if r.Properties != (android.Properties{}) {
			return o, errors.New("failed Android report contains properties")
		}
		o.Status = "failed"
		return o, nil
	}
	raw := []byte(r.Properties.Manufacturer + "\n" + r.Properties.Model + "\n" + r.Properties.Device + "\n" + r.Properties.BuildFingerprint + "\n")
	p, e := android.ParseProperties(raw)
	if e != nil || p != r.Properties {
		return o, errors.New("invalid Android property fields")
	}
	o.Status = "complete"
	for _, x := range []struct{ f, k, v string }{{"manufacturer", "ro.product.manufacturer", p.Manufacturer}, {"model", "ro.product.model", p.Model}, {"device", "ro.product.device", p.Device}, {"build_fingerprint", "ro.build.fingerprint", p.BuildFingerprint}} {
		if useful(x.v) {
			o.Claims = append(o.Claims, claim(x.f, x.v, x.k, androidRef))
		}
	}
	return o, nil
}

// FromSNMP converts a bounded SNMP report and independently recomputes its selected chassis.
func FromSNMP(m Meta, r snmp.Report) (scanner.InventoryObservation, error) {
	o, e := metaBase(m)
	if e != nil {
		return o, e
	}
	if !stamp(m.ObservedAt) {
		return o, errors.New("SNMP inventory requires an owner-supplied observation time")
	}
	target, e := netip.ParseAddrPort(r.Target)
	if e != nil || target.String() != r.Target || !validTarget(target) {
		return o, errors.New("invalid SNMP target")
	}
	if !map[string]bool{"complete": true, "truncated": true, "unsupported": true, "failed": true}[r.EntityStatus] || len(r.Entities) > 32 {
		return o, errors.New("invalid SNMP entity status or count")
	}
	for _, s := range []string{r.System.Description, r.System.ObjectID, r.System.Name, r.Manufacturer, r.Model, r.ManufacturerOID, r.ModelOID} {
		if s != "" && !validText(s, 2048) {
			return o, errors.New("invalid SNMP text")
		}
	}
	o.Kind = "snmp"
	o.Source = "snmpv2c://" + r.Target
	o.ObservedAt = m.ObservedAt
	o.TimeBasis = "owner-supplied"
	o.Status = r.EntityStatus
	if useful(r.System.Description) {
		o.Claims = append(o.Claims, claim("system_description", r.System.Description, sysDescr, rfc1213Ref))
	}
	if useful(r.System.Name) {
		o.Claims = append(o.Claims, claim("name", r.System.Name, sysName, rfc1213Ref))
	}
	if useful(r.System.ObjectID) {
		if !validOID(r.System.ObjectID) {
			return o, errors.New("invalid SNMP agent object ID")
		}
		o.Claims = append(o.Claims, claim("agent_object_id", r.System.ObjectID, sysObject, rfc1213Ref))
	}
	seen := map[int64]bool{}
	allParents := true
	var roots []snmp.Entity
	for _, x := range r.Entities {
		if x.Index < 1 || x.Index > 1<<31-1 || x.Class < 1 || x.Class > 255 || seen[x.Index] {
			return o, errors.New("invalid or duplicate SNMP entity")
		}
		seen[x.Index] = true
		if x.Parent != nil && (*x.Parent < 0 || *x.Parent > 1<<31-1) {
			return o, errors.New("invalid SNMP entity parent")
		}
		for _, s := range []string{x.Manufacturer, x.Model} {
			if s != "" && !validText(s, 2048) {
				return o, errors.New("invalid SNMP entity text")
			}
		}
		if x.Class == 3 {
			idx := strconv.FormatInt(x.Index, 10)
			if useful(x.Manufacturer) {
				o.Claims = append(o.Claims, claim("component_manufacturer", x.Manufacturer, mfgOID+"."+idx, rfc4133Ref))
			}
			if useful(x.Model) {
				o.Claims = append(o.Claims, claim("component_model", x.Model, modelOID+"."+idx, rfc4133Ref))
			}
			if x.Parent == nil {
				allParents = false
			} else if *x.Parent == 0 {
				roots = append(roots, x)
			}
		}
	}
	var em, ef, emo, efo string
	if r.EntityStatus == "complete" && allParents && len(roots) == 1 && roots[0].Model != "" {
		root := roots[0]
		em, ef = root.Model, root.Manufacturer
		idx := strconv.FormatInt(root.Index, 10)
		emo = modelOID + "." + idx
		if ef != "" {
			efo = mfgOID + "." + idx
		}
	}
	if r.Model != em || r.Manufacturer != ef || r.ModelOID != emo || r.ManufacturerOID != efo {
		return o, errors.New("inconsistent derived SNMP chassis identity")
	}
	if useful(em) {
		o.Claims = append(o.Claims, claim("model", em, emo, rfc4133Ref))
		if useful(ef) {
			o.Claims = append(o.Claims, claim("manufacturer", ef, efo, rfc4133Ref))
		}
	}
	return o, nil
}

func validTarget(a netip.AddrPort) bool {
	if !a.IsValid() || a.Port() == 0 || a.Addr().Is4In6() {
		return false
	}
	ip := a.Addr()
	base := ip.WithZone("")
	if base.IsUnspecified() || base.IsMulticast() || base == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || !(base.IsGlobalUnicast() || base.IsLinkLocalUnicast() || base.IsLoopback()) {
		return false
	}
	if base.Is6() && base.IsLinkLocalUnicast() {
		return validText(ip.Zone(), 255) && !strings.ContainsFunc(ip.Zone(), unicode.IsSpace)
	}
	return ip.Zone() == "" || validText(ip.Zone(), 255) && !strings.ContainsFunc(ip.Zone(), unicode.IsSpace)
}
func validOID(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 128 {
		return false
	}
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return false
		}
		for j := range p {
			if p[j] < '0' || p[j] > '9' {
				return false
			}
		}
		n, e := strconv.ParseUint(p, 10, 32)
		if e != nil {
			return false
		}
		if i == 0 && n > 2 {
			return false
		}
		if i == 1 && parts[0] != "2" && n > 39 {
			return false
		}
	}
	return true
}
