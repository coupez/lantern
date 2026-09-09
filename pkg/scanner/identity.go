package scanner

import (
	"github.com/coupez/lantern/pkg/models"
	"github.com/coupez/lantern/pkg/ubiquiti"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const companionReference = "https://github.com/postlund/pyatv/blob/b277a4c8222ecdcbaab8a24e3e713ca44765adb4/pyatv/protocols/companion/__init__.py"

// identityText rejects values whose display normalization would manufacture a
// different identity. Raw observations remain available in advertisements.
func identityText(raw string) string {
	value := strings.TrimSpace(raw)
	if !utf8.ValidString(value) || CleanText(value) != value || len([]rune(value)) > 256 {
		return ""
	}
	return value
}

// IdentityClaim records a reported/local field, protocol interpretation, or catalog match.
// It is not an independently verified hardware identity.
type IdentityClaim struct {
	Field      string `json:"field"`
	Value      string `json:"value"`
	Source     string `json:"source"`
	Key        string `json:"key"`
	Basis      string `json:"basis"`
	Catalog    string `json:"catalog,omitempty"`
	Reference  string `json:"reference,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

// Identity retains competing claims while offering deterministic display fields.
type Identity struct {
	Name            string `json:"name,omitempty"`
	Manufacturer    string `json:"manufacturer,omitempty"`
	Model           string `json:"model,omitempty"`
	Firmware        string `json:"firmware,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	// ModelNames contains catalog candidates for the selected advertised/local model,
	// or a Matter vendor/product pair when no explicit model was advertised.
	ModelNames []string        `json:"model_names,omitempty"`
	Claims     []IdentityClaim `json:"claims,omitempty"`
}

func identify(ads []Advertisement) *Identity {
	return identifyWithLocalModel(ads, "")
}

func identifyWithLocalModel(ads []Advertisement, localModel string) *Identity {
	claims := localModelClaims(localModel)
	addValue := func(field, key, value string, a Advertisement) {
		if a.Protocol == "roku" || a.Protocol == "ipp" || a.Protocol == "onvif" || (a.Protocol == "mdns" && strings.EqualFold(a.Service, "_companion-link._tcp")) {
			value = identityText(value)
		}
		value = strings.TrimSpace(CleanText(value))
		if value == "" {
			return
		}
		if len([]rune(value)) > 256 {
			value = string([]rune(value)[:256])
		}
		source := a.Protocol + ":" + a.Instance
		if a.Protocol == "upnp" || a.Protocol == "shelly" || a.Protocol == "roku" || a.Protocol == "ipp" || a.Protocol == "onvif" {
			source = a.Protocol + ":" + a.Properties["location"] + "#" + a.Instance
		}
		reference := ""
		if a.Protocol == "mdns" && strings.EqualFold(a.Service, "_esphomelib._tcp") {
			reference = espHomeReference
		}
		if a.Protocol == "mdns" && strings.EqualFold(a.Service, "_shelly._tcp") {
			reference = shellyMDNSReference
		}
		if a.Protocol == "mdns" && strings.EqualFold(a.Service, "_companion-link._tcp") {
			reference = companionReference
		}
		if a.Protocol == "roku" {
			reference = rokuInfoReference
		}
		if a.Protocol == "onvif" {
			reference = onvifInfoReference
		}
		if a.Protocol == "ipp" {
			reference = ippIdentityReference
		}
		if a.Protocol == "shelly" {
			reference = shellyInfoReference
		}
		if a.Protocol == "ws-discovery" {
			reference = onvifDiscoveryReference
		}
		claims = append(claims, IdentityClaim{Field: field, Value: value, Source: source, Key: key, Basis: "advertised", Reference: reference})
	}
	add := func(field, key string, a Advertisement) { addValue(field, key, a.Properties[key], a) }
	catalogModel := func(key string, a Advertisement) {
		for _, match := range models.LookupApple(a.Properties[key]) {
			claims = append(claims,
				IdentityClaim{Field: "model_name", Value: match.Name, Source: "mdns:" + a.Instance, Key: key, Basis: "catalog", Catalog: match.Source, Identifier: match.Identifier},
				IdentityClaim{Field: "manufacturer", Value: match.Manufacturer, Source: "mdns:" + a.Instance, Key: key, Basis: "catalog", Catalog: match.Source, Identifier: match.Identifier})
		}
	}
	for _, a := range ads {
		switch a.Protocol {
		case "ubiquiti":
			if a.Service != ubiquitiDiscoveryService {
				continue
			}
			source := "ubiquiti:" + a.Properties["location"] + "#" + a.Instance
			addUbiquiti := func(field, key string) {
				value := identityText(a.Properties[key])
				if field == "model" && strings.EqualFold(value, "unknown") {
					return
				}
				if value != "" {
					claims = append(claims, IdentityClaim{Field: field, Value: value, Source: source, Key: key, Basis: "advertised", Reference: ubiquiti.ProtocolReference})
				}
			}
			// These are protocol-tagged observations. Platform is intentionally
			// retained separately and cannot stand in for a model identifier.
			addUbiquiti("name", "0x0b")
			addUbiquiti("firmware_build", "0x03")
			addUbiquiti("platform", "0x0c")
			addUbiquiti("model", "0x14")
			addUbiquiti("model", "0x15")
			addUbiquiti("firmware_version", "0x16")
			if a.Properties["protocol_version"] != "" {
				claims = append(claims, IdentityClaim{Field: "manufacturer", Value: "Ubiquiti", Source: source, Key: "protocol_version", Basis: "protocol", Reference: ubiquiti.ProtocolReference, Identifier: a.Properties["protocol_version"]})
			}
		case "onvif":
			if a.Service != "device-information" {
				continue
			}
			add("model", "Model", a)
			add("manufacturer", "Manufacturer", a)
			add("firmware_version", "FirmwareVersion", a)
			source := "onvif:" + a.Properties["location"] + "#" + a.Instance
			if a.Properties["transport"] == "tls-unverified" {
				claims = append(claims, IdentityClaim{Field: "transport", Value: "TLS certificate not verified", Source: source, Key: "transport", Basis: "transport", Reference: onvifInfoReference})
			}
			if a.Properties["authentication"] == "none" {
				claims = append(claims, IdentityClaim{Field: "authentication", Value: "No credentials supplied", Source: source, Key: "authentication", Basis: "transport", Reference: onvifInfoReference})
			}
		case "ipp":
			if a.Service != "printer-attributes" {
				continue
			}
			if identityText(a.Properties["device-id-model"]) != "" {
				add("model", "device-id-model", a)
			} else {
				add("model", "printer-make-and-model", a)
			}
			add("manufacturer", "device-id-manufacturer", a)
			add("printer_name", "printer-name", a)
			add("printer_make_and_model", "printer-make-and-model", a)
			add("printer_device_identity", "device-id-identity", a)
			if a.Properties["transport"] == "tls-unverified" {
				claims = append(claims, IdentityClaim{Field: "transport", Value: "TLS certificate not verified", Source: "ipp:" + a.Properties["location"] + "#" + a.Instance, Key: "transport", Basis: "transport", Reference: "https://www.rfc-editor.org/rfc/rfc7472.html#section-3"})
			}
		case "ws-discovery":
			if a.Service != "probe-match" {
				continue
			}
			for _, scope := range strings.Fields(a.Properties["scopes"]) {
				if field, value := onvifScope(scope); field != "" {
					addValue(field, scope, value, a)
				}
			}
		case "roku":
			if a.Service != "device-info" {
				continue
			}
			add("name", "user-device-name", a)
			add("name", "friendly-device-name", a)
			add("manufacturer", "vendor-name", a)
			if identityText(a.Properties["model-name"]) != "" {
				add("model", "model-name", a)
			} else {
				add("model", "model-number", a)
			}
			add("model_number", "model-number", a)
			add("firmware_version", "software-version", a)
			add("firmware_build", "software-build", a)
			claims = append(claims, IdentityClaim{Field: "firmware", Value: "Roku OS", Source: "roku:" + a.Properties["location"] + "#" + a.Instance, Key: "service", Basis: "protocol", Reference: rokuInfoReference, Identifier: "device-info"})
		case "shelly":
			if a.Service != "device-info" {
				continue
			}
			for _, field := range []struct{ field, key string }{
				{"name", "name"}, {"name", "id"}, {"model", "model"}, {"firmware_version", "ver"},
				{"firmware_build", "fw_id"}, {"generation", "gen"}, {"application", "app"}, {"profile", "profile"}, {"reported_mac", "mac"},
			} {
				add(field.field, field.key, a)
			}
			claims = append(claims, IdentityClaim{Field: "firmware", Value: "Shelly", Source: "shelly:" + a.Properties["location"] + "#" + a.Instance, Key: "service", Basis: "protocol", Reference: shellyInfoReference, Identifier: "device-info"})
			if generation, err := strconv.Atoi(a.Properties["gen"]); err == nil && generation >= 2 {
				for _, match := range models.LookupShelly(a.Properties["model"], generation) {
					source := "shelly:" + a.Properties["location"] + "#" + a.Instance
					claims = append(claims,
						IdentityClaim{Field: "model_name", Value: match.Name, Source: source, Key: "model", Basis: "catalog", Catalog: match.Source, Identifier: match.Identifier},
						IdentityClaim{Field: "manufacturer", Value: match.Manufacturer, Source: source, Key: "model", Basis: "catalog", Catalog: match.Source, Identifier: match.Identifier})
				}
			}
		case "netbios":
			if a.Service == "workstation" || a.Service == "file-server" {
				add("name", "name", a)
			}
		case "upnp":
			add("name", "friendlyName", a)
			add("manufacturer", "manufacturer", a)
			add("model", "modelName", a)
		case "mdns":
			switch strings.ToLower(a.Service) {
			case "_matterc._udp", "_matterd._udp", "_matter._tcp":
				claims = append(claims, matterClaims(a)...)
			case "_shelly._tcp":
				addValue("name", "instance", mdnsInstanceName(a.Instance, "_shelly._tcp"), a)
				if shellyGeneration(a.Properties["gen"]) {
					add("generation", "gen", a)
				}
				claims = append(claims, IdentityClaim{Field: "kind", Value: "smart home device", Source: "mdns:" + a.Instance, Key: "service", Basis: "protocol", Reference: shellyMDNSReference, Identifier: "_shelly._tcp"})
			case "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp":
				add("manufacturer", "usb_mfg", a)
				add("model", "usb_mdl", a)
				add("model", "ty", a)
				add("model", "product", a)
			case "_esphomelib._tcp":
				add("name", "friendly_name", a)
				addValue("name", "instance", mdnsInstanceName(a.Instance, "_esphomelib._tcp"), a)
				claims = append(claims,
					IdentityClaim{Field: "firmware", Value: "ESPHome", Source: "mdns:" + a.Instance, Key: "service", Basis: "protocol", Reference: espHomeReference, Identifier: "_esphomelib._tcp"},
					IdentityClaim{Field: "kind", Value: "smart home device", Source: "mdns:" + a.Instance, Key: "service", Basis: "protocol", Reference: espHomeReference, Identifier: "_esphomelib._tcp"})
				for _, field := range []struct{ field, key string }{
					{"firmware_version", "version"}, {"build_board", "board"}, {"platform", "platform"},
					{"firmware_project", "project_name"}, {"firmware_project_version", "project_version"},
				} {
					add(field.field, field.key, a)
				}
			case "_hap._tcp":
				add("model", "md", a)
				addValue("name", "instance", homeKitName(a.Instance), a)
				if kind := homeKitCategory(a.Properties["ci"]); kind != "" {
					claims = append(claims, IdentityClaim{Field: "kind", Value: kind, Source: "mdns:" + a.Instance, Key: "ci", Basis: "protocol", Reference: homeKitCategoryReference, Identifier: a.Properties["ci"]})
				}
			case "_googlecast._tcp":
				add("model", "md", a)
				add("name", "fn", a)
				if maker, catalog := castManufacturer(a.Properties["md"]); maker != "" {
					claims = append(claims, IdentityClaim{Field: "manufacturer", Value: maker, Source: "mdns:" + a.Instance, Key: "md", Basis: "catalog", Catalog: catalog, Identifier: strings.TrimSpace(a.Properties["md"])})
				}
			case "_companion-link._tcp":
				add("model", "rpmd", a)
				catalogModel("rpmd", a)
			case "_device-info._tcp", "_airplay._tcp":
				add("model", "model", a)
				catalogModel("model", a)
			case "_raop._tcp":
				add("model", "am", a)
				catalogModel("am", a)
			}
		}
	}
	if len(claims) == 0 {
		return nil
	}
	// Standardized, explicit fields precede human-readable printer descriptions.
	rank := func(c IdentityClaim) int {
		if c.Basis == "local-system" {
			return -1
		}
		if strings.HasPrefix(c.Source, "netbios:") {
			if strings.HasSuffix(c.Source, "<00>") {
				return 4
			}
			return 5
		}
		if c.Basis == "catalog" {
			return 4
		}
		switch c.Key {
		case "Model", "Manufacturer", "device-id-model", "device-id-manufacturer", "printer-make-and-model", "0x14", "0x15":
			return 0
		case "manufacturer", "friendlyName", "friendly_name", "name", "modelName", "usb_mfg", "usb_mdl", "vendor-name", "model-name", "user-device-name":
			return 0
		case "model", "md", "am", "model-number", "friendly-device-name":
			return 1
		case "ty", "rpmd":
			return 2
		default:
			return 3
		}
	}
	sort.Slice(claims, func(i, j int) bool {
		a, b := claims[i], claims[j]
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		if a.Value != b.Value {
			return a.Value < b.Value
		}
		if a.Catalog != b.Catalog {
			return a.Catalog < b.Catalog
		}
		if a.Reference != b.Reference {
			return a.Reference < b.Reference
		}
		return a.Identifier < b.Identifier
	})
	result := &Identity{}
	var selectedModel, selectedFirmware IdentityClaim
	for _, c := range claims {
		if len(result.Claims) > 0 && result.Claims[len(result.Claims)-1] == c {
			continue
		}
		result.Claims = append(result.Claims, c)
		switch c.Field {
		case "firmware":
			if result.Firmware == "" {
				result.Firmware, selectedFirmware = c.Value, c
			}
		case "model":
			if result.Model == "" {
				result.Model = c.Value
				selectedModel = c
			}
		}
	}
	modelIdentifier := result.Model
	if modelIdentifier == "" {
		for _, c := range result.Claims {
			if c.Field == "matter_product_id" && c.Identifier != "" {
				selectedModel, modelIdentifier = c, c.Identifier
				break
			}
		}
	}
	for _, c := range result.Claims {
		// A competing Roku endpoint cannot contribute a display name/vendor to
		// another model. Keep its original claim available for inspection.
		rokuLinked := !strings.HasPrefix(c.Source, "roku:") || c.Source == selectedModel.Source
		// Ubiquiti's protocol manufacturer is meaningful only for a model from
		// the same discovery endpoint. Conversely, a selected Ubiquiti model
		// must not inherit an unrelated advertised manufacturer.
		ubiquitiLinked := (!strings.HasPrefix(c.Source, "ubiquiti:") && !strings.HasPrefix(selectedModel.Source, "ubiquiti:")) || c.Source == selectedModel.Source
		if c.Field == "name" && result.Name == "" && rokuLinked {
			result.Name = c.Value
		}
		onvifVersion := result.Firmware == "" && strings.HasPrefix(selectedModel.Source, "onvif:") && c.Source == selectedModel.Source
		ubiquitiVersion := result.Firmware == "" && strings.HasPrefix(selectedModel.Source, "ubiquiti:") && c.Source == selectedModel.Source
		if c.Field == "firmware_version" && (c.Source == selectedFirmware.Source || onvifVersion || ubiquitiVersion) && result.FirmwareVersion == "" {
			result.FirmwareVersion = c.Value
		}
		linked := c.Source == selectedModel.Source && c.Key == selectedModel.Key && strings.EqualFold(c.Identifier, result.Model)
		localLinked := selectedModel.Basis != "local-system" || c.Source == selectedModel.Source
		ippLinked := (!strings.HasPrefix(c.Source, "ipp:") && !strings.HasPrefix(selectedModel.Source, "ipp:")) || c.Source == selectedModel.Source
		onvifLinked := (!strings.HasPrefix(c.Source, "onvif:") && !strings.HasPrefix(selectedModel.Source, "onvif:")) || c.Source == selectedModel.Source
		if c.Field == "manufacturer" && result.Manufacturer == "" && onvifLinked && ippLinked && localLinked && rokuLinked && ubiquitiLinked && (c.Basis != "catalog" || linked) {
			result.Manufacturer = c.Value
		}
		if c.Field == "model_name" && c.Basis == "catalog" && c.Source == selectedModel.Source && c.Key == selectedModel.Key && strings.EqualFold(c.Identifier, modelIdentifier) && !contains(result.ModelNames, c.Value) {
			result.ModelNames = append(result.ModelNames, c.Value)
		}
	}
	sort.Strings(result.ModelNames)
	return result
}
