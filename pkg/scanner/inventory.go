package scanner

import (
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// InventoryClaim is a device-reported field from an explicitly attached saved
// inventory. It does not contribute to network identity or responsiveness.
type InventoryClaim struct {
	Field     string `json:"field"`
	Value     string `json:"value"`
	Key       string `json:"key"`
	Reference string `json:"reference"`
}

// InventoryObservation preserves collection and owner-declared binding
// provenance. Content digests identify inputs; they do not authenticate them.
type InventoryObservation struct {
	ID             string           `json:"id"`
	Kind           string           `json:"kind"`
	Source         string           `json:"source"`
	SourceSHA256   string           `json:"source_sha256"`
	BindingSHA256  string           `json:"binding_sha256"`
	BindingAddress string           `json:"binding_address"`
	ObservedAt     string           `json:"observed_at"`
	TimeBasis      string           `json:"time_basis"`
	Status         string           `json:"status"`
	Claims         []InventoryClaim `json:"claims,omitempty"`
}

// InventoryModels returns all distinct attached reported model claims. It does
// not choose one, infer a retail model, or include component models.
func (d Device) InventoryModels() []string {
	seen := map[string]bool{}
	var models []string
	for _, observation := range d.Inventory {
		for _, claim := range observation.Claims {
			if claim.Field == "model" && claim.Value != "" && !seen[claim.Value] {
				seen[claim.Value] = true
				models = append(models, claim.Value)
			}
		}
	}
	sort.Strings(models)
	return models
}

// ValidateInventoryObservation validates one already-bound observation before
// storage or attachment. A snapshot additionally checks the parent device IP.
func ValidateInventoryObservation(o InventoryObservation) error {
	text := func(s string, limit int) bool {
		if s == "" || len(s) > limit || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
			return false
		}
		for _, r := range s {
			if r == utf8.RuneError || unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
				return false
			}
		}
		return true
	}
	hash := func(s string) bool {
		if len(s) != 64 {
			return false
		}
		for _, r := range s {
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
				return false
			}
		}
		return true
	}
	ip, err := netip.ParseAddr(o.BindingAddress)
	if err != nil || ip.String() != o.BindingAddress || ip.Is4In6() || !(ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || ip.IsLoopback()) || (ip.Is6() && ip.IsLinkLocalUnicast() && ip.Zone() == "") {
		return errors.New("invalid inventory binding address")
	}
	if ip.Zone() != "" && (!text(ip.Zone(), 255) || strings.ContainsFunc(ip.Zone(), unicode.IsSpace)) {
		return errors.New("invalid inventory address zone")
	}
	if !text(o.ID, 128) || !text(o.Source, 512) || !hash(o.SourceSHA256) || !hash(o.BindingSHA256) {
		return errors.New("invalid inventory provenance")
	}
	if o.Kind != "android" && o.Kind != "snmp" {
		return errors.New("unsupported inventory kind")
	}
	stamp, err := time.Parse(time.RFC3339Nano, o.ObservedAt)
	if err != nil || stamp.IsZero() || !text(o.ObservedAt, 64) {
		return errors.New("invalid inventory observation time")
	}
	if o.TimeBasis != "collector" && o.TimeBasis != "owner-supplied" {
		return errors.New("invalid inventory time basis")
	}
	if o.Kind == "android" {
		if o.TimeBasis != "collector" || !validAndroidInventorySource(o.Source) {
			return errors.New("Android inventory provenance is inconsistent")
		}
		if o.Status != "complete" && o.Status != "failed" {
			return errors.New("invalid Android inventory status")
		}
	} else if o.TimeBasis != "owner-supplied" || !validSNMPInventorySource(o.Source) {
		return errors.New("SNMP inventory provenance is inconsistent")
	}
	if o.Status != "complete" && o.Status != "truncated" && o.Status != "unsupported" && o.Status != "failed" {
		return errors.New("invalid inventory status")
	}
	if len(o.Claims) > 72 {
		return errors.New("too many inventory claims")
	}
	allowed := map[string]bool{"model": true, "manufacturer": true, "device": true, "build_fingerprint": true, "name": true, "system_description": true, "agent_object_id": true, "component_model": true, "component_manufacturer": true}
	seen := map[InventoryClaim]bool{}
	for _, c := range o.Claims {
		if !allowed[c.Field] || !text(c.Value, 2048) || !text(c.Key, 256) || !text(c.Reference, 512) || !strings.HasPrefix(c.Reference, "https://") || seen[c] {
			return errors.New("invalid or repeated inventory claim")
		}
		if strings.EqualFold(c.Value, "unknown") || (c.Field == "model" || c.Field == "manufacturer") && o.Status != "complete" {
			return errors.New("incomplete inventory cannot supply a selected model")
		}
		if !validInventoryClaimNamespace(o.Kind, c) {
			return errors.New("inventory claim contradicts its source kind")
		}
		seen[c] = true
	}
	if o.Kind == "android" && o.Status == "failed" && len(o.Claims) != 0 {
		return errors.New("failed Android inventory cannot supply claims")
	}
	return nil
}

func validAndroidInventorySource(source string) bool {
	rest, ok := strings.CutPrefix(source, "adb://")
	if !ok {
		return false
	}
	serverText, idText, ok := strings.Cut(rest, "/transport/")
	if !ok || strings.Contains(idText, "/") || idText == "" || idText[0] == '0' {
		return false
	}
	server, err := netip.ParseAddrPort(serverText)
	if err != nil || server.String() != serverText || server.Port() == 0 || !server.Addr().IsLoopback() || server.Addr().Is4In6() || server.Addr().Zone() != "" {
		return false
	}
	_, err = strconv.ParseUint(idText, 10, 64)
	return err == nil
}

func validSNMPInventorySource(source string) bool {
	rest, ok := strings.CutPrefix(source, "snmpv2c://")
	if !ok {
		return false
	}
	target, err := netip.ParseAddrPort(rest)
	if err != nil || target.String() != rest || target.Port() == 0 || target.Addr().Is4In6() {
		return false
	}
	ip := target.Addr()
	base := ip.WithZone("")
	if base.IsUnspecified() || base.IsMulticast() || base == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || !(base.IsGlobalUnicast() || base.IsLinkLocalUnicast() || base.IsLoopback()) {
		return false
	}
	if base.Is6() && base.IsLinkLocalUnicast() {
		return validInventoryZone(ip.Zone())
	}
	return ip.Zone() == "" || validInventoryZone(ip.Zone())
}

func validInventoryZone(zone string) bool {
	if zone == "" || len(zone) > 255 || !utf8.ValidString(zone) || strings.TrimSpace(zone) != zone || strings.ContainsFunc(zone, unicode.IsSpace) {
		return false
	}
	for _, r := range zone {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}

func validInventoryClaimNamespace(kind string, c InventoryClaim) bool {
	if kind == "android" {
		return map[string]string{"manufacturer": "ro.product.manufacturer", "model": "ro.product.model", "device": "ro.product.device", "build_fingerprint": "ro.build.fingerprint"}[c.Field] == c.Key
	}
	exact := map[string]string{"system_description": "1.3.6.1.2.1.1.1.0", "agent_object_id": "1.3.6.1.2.1.1.2.0", "name": "1.3.6.1.2.1.1.5.0"}
	if key, ok := exact[c.Field]; ok {
		return c.Key == key
	}
	prefix := map[string]string{"component_manufacturer": "1.3.6.1.2.1.47.1.1.1.1.12.", "manufacturer": "1.3.6.1.2.1.47.1.1.1.1.12.", "component_model": "1.3.6.1.2.1.47.1.1.1.1.13.", "model": "1.3.6.1.2.1.47.1.1.1.1.13."}[c.Field]
	if prefix == "" || !strings.HasPrefix(c.Key, prefix) {
		return false
	}
	index := strings.TrimPrefix(c.Key, prefix)
	if index == "" || index[0] == '0' {
		return false
	}
	for _, r := range index {
		if r < '0' || r > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(index, 10, 31)
	return err == nil && n > 0
}
