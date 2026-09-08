package scanner

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

const matterTXTReference = "https://github.com/project-chip/connectedhomeip/blob/43aa98c2d30ee547c6b587b9de7bbb794f175ece/src/lib/dnssd/TxtFields.h"
const matterServiceReference = "https://github.com/project-chip/connectedhomeip/blob/43aa98c2d30ee547c6b587b9de7bbb794f175ece/src/lib/dnssd/ServiceNaming.h"
const matterTypeReference = "https://github.com/project-chip/connectedhomeip/blob/43aa98c2d30ee547c6b587b9de7bbb794f175ece/src/app/zap-templates/zcl/data-model/chip/matter-devices.xml"

//go:embed data/matter-types.json
var matterTypeData []byte
var matterTypeOnce sync.Once
var matterTypes struct {
	Types map[string]struct {
		Name        string `json:"name"`
		Application bool   `json:"application"`
	} `json:"types"`
}

func matterRole(service string) string {
	switch strings.ToLower(service) {
	case "_matterc._udp":
		return "commissionable"
	case "_matterd._udp":
		return "commissioner"
	case "_matter._tcp":
		return "operational"
	}
	return ""
}

// Matter TXT numbers are unsigned decimal without leading zeros. Keep unknown
// valid identifiers as claims, without guessing a brand or retail model.
func matterNumber(raw string, bits int) bool {
	if raw == "" || len(raw) > 10 || (len(raw) > 1 && raw[0] == '0') {
		return false
	}
	for i := range len(raw) {
		if raw[i] < '0' || raw[i] > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(raw, 10, bits)
	return err == nil
}

func matterDeviceType(raw string) (name, kind string) {
	if !matterNumber(raw, 32) {
		return "", ""
	}
	matterTypeOnce.Do(func() {
		if err := json.Unmarshal(matterTypeData, &matterTypes); err != nil {
			panic(err)
		}
	})
	t := matterTypes.Types[raw]
	if t.Application {
		kind = strings.ToLower(t.Name)
	}
	return t.Name, kind
}

func matterClaims(a Advertisement) []IdentityClaim {
	role := matterRole(a.Service)
	if a.Protocol != "mdns" || role == "" {
		return nil
	}
	claims := []IdentityClaim{}
	add := func(field, key, value, basis, reference string) {
		claims = append(claims, IdentityClaim{Field: field, Key: key, Value: value, Basis: basis, Source: "mdns:" + a.Instance, Reference: reference})
	}
	add("protocol", "service", "Matter", "protocol", matterServiceReference)
	add("discovery_role", "service", role, "protocol", matterServiceReference)
	// Operational advertisements do not define DN/DT/VP. Their instance is a
	// fabric/node identifier, not a friendly name or a physical device key.
	if role == "operational" {
		return claims
	}
	if name := a.Properties["dn"]; len(name) <= 32 && utf8.ValidString(name) {
		if name = strings.TrimSpace(CleanText(name)); name != "" {
			add("name", "dn", name, "advertised", matterTXTReference)
		}
	}
	vendor, product, hasProduct := strings.Cut(a.Properties["vp"], "+")
	if matterNumber(vendor, 16) && (!hasProduct || matterNumber(product, 16)) {
		add("matter_vendor_id", "vp", vendor, "advertised", matterTXTReference)
		if hasProduct {
			add("matter_product_id", "vp", product, "advertised", matterTXTReference)
		}
	}
	if raw := a.Properties["dt"]; matterNumber(raw, 32) {
		add("matter_device_type", "dt", raw, "advertised", matterTXTReference)
		if name, kind := matterDeviceType(raw); name != "" {
			add("device_type_name", "dt", name, "protocol", matterTypeReference)
			claims[len(claims)-1].Identifier = raw
			if kind != "" {
				add("kind", "dt", kind, "protocol", matterTypeReference)
				claims[len(claims)-1].Identifier = raw
			}
		}
	}
	return claims
}
