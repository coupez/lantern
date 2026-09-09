package scanner

import (
	"net/netip"

	"github.com/coupez/lantern/pkg/models"
)

const localModelSource = "local:sysctl"
const localModelReference = "https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/sysctlbyname.3.html"

// localTargetModels binds the kernel fact only to selected addresses enumerated
// by the local OS. A remote advertisement or address/MAC resemblance cannot
// create this binding. The map is complete before enrichment workers start.
func localTargetModels(networks []Network, targets map[netip.Addr]bool, iface string, read func() string) map[netip.Addr]string {
	result := map[netip.Addr]string{}
	readOnce := false
	model := ""
	for _, n := range networks {
		ip, err := netip.ParseAddr(n.Address)
		if err != nil || !targets[ip] || (iface != "" && n.Interface != iface) {
			continue
		}
		if !readOnce {
			model = identityText(read())
			readOnce = true
		}
		if model != "" {
			result[ip] = model
		}
	}
	return result
}

func localModelClaims(raw string) []IdentityClaim {
	model := identityText(raw)
	if model == "" {
		return nil
	}
	claims := []IdentityClaim{{Field: "model", Value: model, Source: localModelSource, Key: "hw.model", Basis: "local-system", Reference: localModelReference}}
	matches := models.LookupApple(model)
	for _, match := range matches {
		for _, field := range []struct{ name, value string }{{"model_name", match.Name}, {"manufacturer", match.Manufacturer}} {
			claims = append(claims, IdentityClaim{Field: field.name, Value: field.value, Source: localModelSource, Key: "hw.model", Basis: "catalog", Catalog: match.Source, Identifier: match.Identifier})
		}
	}
	// All AppleDB matches must identify a Mac before assigning a generic computer
	// category. Unknown/virtual hardware identifiers remain raw local evidence.
	if len(matches) > 0 {
		computer := true
		for _, match := range matches {
			switch match.Type {
			case "Mac Pro", "Mac Studio", "Mac mini", "MacBook", "MacBook Air", "MacBook Neo", "MacBook Pro", "PowerBook", "PowerMac", "Xserve", "eMac", "iBook", "iMac":
			default:
				computer = false
			}
		}
		if computer {
			claims = append(claims, IdentityClaim{Field: "kind", Value: "computer", Source: localModelSource, Key: "hw.model", Basis: "catalog", Catalog: matches[0].Source, Identifier: model})
		}
	}
	return claims
}
