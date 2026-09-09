package scanner

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/coupez/lantern/pkg/ubiquiti"
)

const ubiquitiDiscoveryService = "discovery"

// ubiquitiHit turns an already parsed response into discovery evidence. The
// UDP socket peer remains authoritative for the address; no response field can
// create or move a device record.
func ubiquitiHit(ip netip.Addr, observation ubiquiti.Observation) discoveryHit {
	if !ip.IsValid() || ip.Is4In6() || ip.WithZone("").IsUnspecified() || ip.IsMulticast() {
		return discoveryHit{}
	}
	properties := map[string]string{
		"location":         "udp://" + ip.String() + ":10001",
		"protocol_version": strconv.Itoa(int(observation.Version)),
		"protocol_command": strconv.Itoa(int(observation.Command)),
	}
	for _, field := range observation.Fields {
		switch field.Tag {
		case 0x03, 0x0b, 0x0c, 0x14, 0x15, 0x16:
			// The hexadecimal field tag is the protocol key. Do not reinterpret
			// unrecognized fields as identity data.
			properties[fmt.Sprintf("0x%02x", field.Tag)] = field.Value
		}
	}
	return discoveryHit{
		IP:       ip,
		Evidence: "ubiquiti",
		Ads: []Advertisement{{
			Protocol:   "ubiquiti",
			Service:    ubiquitiDiscoveryService,
			Instance:   ip.String() + "#v" + strconv.Itoa(int(observation.Version)),
			Port:       10001,
			Properties: properties,
		}},
	}
}
