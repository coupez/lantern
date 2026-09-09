package scanner

import (
	"strconv"
	"strings"
)

const espHomeReference = "https://github.com/esphome/esphome/blob/1ce0bed3f672d3a4699dad0cbfd8617c3b8950e5/esphome/components/mdns/mdns_component.cpp"

const homeKitCategoryReference = "https://github.com/homebridge/HAP-NodeJS/blob/25e8bea26a64309a47184dec478479483fbdd50c/src/lib/Accessory.ts"

// Protocol category numbers, not a manufacturer or model catalog. Some Apple
// product categories map to generic types: the number alone cannot verify brand.
func homeKitCategory(raw string) string {
	if len(raw) == 0 || len(raw) > 5 {
		return ""
	}
	for i := range len(raw) {
		if raw[i] < '0' || raw[i] > '9' {
			return ""
		}
	}
	n, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return ""
	}
	categories := [...]string{
		1: "smart home device", 2: "smart home hub", 3: "fan", 4: "garage door opener",
		5: "light", 6: "door lock", 7: "outlet", 8: "switch", 9: "thermostat",
		10: "sensor", 11: "security system", 12: "door", 13: "window", 14: "window covering",
		15: "programmable switch", 16: "range extender", 17: "camera", 18: "video doorbell",
		19: "air purifier", 20: "heater", 21: "air conditioner", 22: "humidifier",
		23: "dehumidifier", 24: "media player", 25: "speaker", 26: "speaker", 27: "router",
		28: "sprinkler", 29: "faucet", 30: "shower system", 31: "television",
		32: "remote control", 33: "router", 34: "audio receiver", 35: "media player", 36: "media player",
	}
	if n >= uint64(len(categories)) {
		return ""
	}
	return categories[n]
}

func homeKitName(instance string) string { return mdnsInstanceName(instance, "_hap._tcp") }

func mdnsInstanceName(instance, service string) string {
	instance = strings.TrimSuffix(instance, ".")
	suffix := "." + service + ".local"
	if !strings.HasSuffix(strings.ToLower(instance), suffix) {
		return ""
	}
	return instance[:len(instance)-len(suffix)]
}

// inferKind returns a deterministic hint, retaining category conflicts in the
// identity claims. Exact protocol/service matching prevents lookalike names from
// accidentally acquiring another service's type.
func inferKind(d Device) string {
	// A local machine can advertise a shared printer or media receiver; those
	// services must not override its directly observed hardware category.
	if d.Identity != nil {
		for _, c := range d.Identity.Claims {
			if c.Field == "kind" && c.Source == localModelSource && c.Basis == "catalog" && c.Identifier == d.Identity.Model {
				return c.Value
			}
		}
	}
	kinds := map[string]bool{}
	netbiosComputer, homeKit := false, false
	homeKitKinds := map[string]bool{}
	matter, matterKinds := false, map[string]bool{}
	for _, a := range d.Advertisements {
		switch a.Protocol {
		case "roku":
			if a.Service == "device-info" {
				if a.Properties["is-tv"] == "true" {
					kinds["television"] = true
				} else {
					kinds["media"] = true
				}
			}
		case "netbios":
			netbiosComputer = netbiosComputer || a.Service == "workstation" || a.Service == "file-server"
		case "mdns":
			switch strings.ToLower(a.Service) {
			case "_matterc._udp", "_matterd._udp", "_matter._tcp":
				matter = true
				if matterRole(a.Service) != "operational" {
					if _, kind := matterDeviceType(a.Properties["dt"]); kind != "" {
						matterKinds[kind] = true
					}
				}
			case "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp":
				kinds["printer"] = true
			case "_home-assistant._tcp":
				kinds["smart home hub"] = true
			case "_esphomelib._tcp", "_shelly._tcp":
				kinds["smart home device"] = true
			case "_hap._tcp":
				homeKit = true
				if kind := homeKitCategory(a.Properties["ci"]); kind != "" && kind != "smart home device" {
					homeKitKinds[kind] = true
				}
			case "_googlecast._tcp", "_airplay._tcp", "_raop._tcp":
				kinds["media"] = true
			}
		case "ssdp", "upnp":
			parts := strings.Split(strings.ToLower(a.Service), ":")
			if len(parts) != 5 || parts[0] != "urn" || parts[1] != "schemas-upnp-org" || parts[2] != "device" {
				continue
			}
			version, err := strconv.ParseUint(parts[4], 10, 32)
			if err != nil || version == 0 {
				continue
			}
			switch parts[3] {
			case "internetgatewaydevice":
				kinds["router"] = true
			case "mediarenderer":
				kinds["media"] = true
			}
		}
	}
	for _, kind := range []string{"printer", "router", "smart home hub"} {
		if kinds[kind] {
			return kind
		}
	}
	if homeKit {
		if len(homeKitKinds) == 1 {
			for kind := range homeKitKinds {
				return kind
			}
		}
		return "smart home device"
	}
	if kinds["television"] {
		return "television"
	}
	if kinds["media"] {
		return "media"
	}
	if matter {
		if len(matterKinds) == 1 {
			for kind := range matterKinds {
				return kind
			}
		}
		return "smart home device"
	}
	if kinds["smart home device"] {
		return "smart home device"
	}
	has := func(port uint16) bool {
		for _, p := range d.Ports {
			if p.Number == port {
				return true
			}
		}
		return false
	}
	if has(631) || has(9100) {
		return "printer"
	}
	if has(8008) || has(8009) || has(7000) {
		return "media"
	}
	if has(554) {
		return "camera / media"
	}
	if has(445) || has(3389) || netbiosComputer {
		return "computer / NAS"
	}
	return "device"
}
