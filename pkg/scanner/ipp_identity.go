package scanner

import "strings"

const ippIdentityReference = "https://www.rfc-editor.org/rfc/rfc8011.html#section-5.4.9"

// retainIPPDeviceID retains only manufacturer/model from the IEEE 1284 string.
// In particular serials, UUIDs and arbitrary vendor extensions are not persisted.
// Aliases share one duplicate check; competing values do not become an identity.
func retainIPPDeviceID(fields map[string]string) {
	raw := fields["printer-device-id"]
	delete(fields, "printer-device-id")
	if len(raw) > 2048 {
		return
	}
	values := map[string]string{}
	seen := map[string]bool{}
	ambiguous := map[string]bool{}
	var retained []string
	for _, entry := range strings.Split(raw, ";") {
		key, value, ok := strings.Cut(entry, ":")
		if !ok {
			continue
		}
		var field string
		switch strings.ToUpper(strings.TrimSpace(key)) {
		case "MFG", "MANUFACTURER":
			field = "device-id-manufacturer"
		case "MDL", "MODEL":
			field = "device-id-model"
		default:
			continue
		}
		retained = append(retained, entry)
		value = identityText(value)
		if seen[field] {
			ambiguous[field] = true
		}
		seen[field] = true
		values[field] = value
	}
	if len(retained) > 0 {
		fields["device-id-identity"] = strings.Join(retained, ";") + ";"
	}
	for key, value := range values {
		if !ambiguous[key] && value != "" {
			fields[key] = value
		}
	}
}
