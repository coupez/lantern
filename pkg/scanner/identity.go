package scanner

import (
	"lantern/pkg/models"
	"sort"
	"strings"
)

// IdentityClaim records a reported or catalog-derived field with its provenance.
// It is not an independently verified hardware identity.
type IdentityClaim struct {
	Field      string `json:"field"`
	Value      string `json:"value"`
	Source     string `json:"source"`
	Key        string `json:"key"`
	Basis      string `json:"basis"`
	Catalog    string `json:"catalog,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

// Identity retains competing claims while offering deterministic display fields.
type Identity struct {
	Name         string `json:"name,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	// ModelNames contains catalog candidates for the selected advertised model.
	ModelNames []string        `json:"model_names,omitempty"`
	Claims     []IdentityClaim `json:"claims,omitempty"`
}

func identify(ads []Advertisement) *Identity {
	claims := []IdentityClaim{}
	add := func(field, key string, a Advertisement) {
		value := strings.TrimSpace(CleanText(a.Properties[key]))
		if value == "" {
			return
		}
		if len([]rune(value)) > 256 {
			value = string([]rune(value)[:256])
		}
		source := a.Protocol + ":" + a.Instance
		if a.Protocol == "upnp" {
			source = "upnp:" + a.Properties["location"] + "#" + a.Instance
		}
		claims = append(claims, IdentityClaim{Field: field, Value: value, Source: source, Key: key, Basis: "advertised"})
	}
	catalogModel := func(key string, a Advertisement) {
		for _, match := range models.Lookup(a.Properties[key]) {
			claims = append(claims,
				IdentityClaim{Field: "model_name", Value: match.Name, Source: "mdns:" + a.Instance, Key: key, Basis: "catalog", Catalog: match.Source, Identifier: match.Identifier},
				IdentityClaim{Field: "manufacturer", Value: match.Manufacturer, Source: "mdns:" + a.Instance, Key: key, Basis: "catalog", Catalog: match.Source, Identifier: match.Identifier})
		}
	}
	for _, a := range ads {
		switch a.Protocol {
		case "upnp":
			add("name", "friendlyName", a)
			add("manufacturer", "manufacturer", a)
			add("model", "modelName", a)
		case "mdns":
			switch a.Service {
			case "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp":
				add("manufacturer", "usb_mfg", a)
				add("model", "usb_mdl", a)
				add("model", "ty", a)
				add("model", "product", a)
			case "_googlecast._tcp":
				add("model", "md", a)
				add("name", "fn", a)
				if maker, catalog := castManufacturer(a.Properties["md"]); maker != "" {
					claims = append(claims, IdentityClaim{Field: "manufacturer", Value: maker, Source: "mdns:" + a.Instance, Key: "md", Basis: "catalog", Catalog: catalog, Identifier: strings.TrimSpace(a.Properties["md"])})
				}
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
		if c.Basis == "catalog" {
			return 4
		}
		switch c.Key {
		case "manufacturer", "friendlyName", "modelName", "usb_mfg", "usb_mdl":
			return 0
		case "model", "md", "am":
			return 1
		case "ty":
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
		return a.Identifier < b.Identifier
	})
	result := &Identity{}
	var selectedModel IdentityClaim
	for _, c := range claims {
		if len(result.Claims) > 0 && result.Claims[len(result.Claims)-1] == c {
			continue
		}
		result.Claims = append(result.Claims, c)
		switch c.Field {
		case "name":
			if result.Name == "" {
				result.Name = c.Value
			}
		case "model":
			if result.Model == "" {
				result.Model = c.Value
				selectedModel = c
			}
		}
	}
	for _, c := range result.Claims {
		linked := c.Source == selectedModel.Source && c.Key == selectedModel.Key && strings.EqualFold(c.Identifier, result.Model)
		if c.Field == "manufacturer" && result.Manufacturer == "" && (c.Basis != "catalog" || linked) {
			result.Manufacturer = c.Value
		}
		if c.Field == "model_name" && c.Basis == "catalog" && c.Source == selectedModel.Source && c.Key == selectedModel.Key && strings.EqualFold(c.Identifier, result.Model) && !contains(result.ModelNames, c.Value) {
			result.ModelNames = append(result.ModelNames, c.Value)
		}
	}
	sort.Strings(result.ModelNames)
	return result
}
