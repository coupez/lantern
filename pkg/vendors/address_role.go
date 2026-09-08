package vendors

// AddressRole interprets an address range, not observed protocol traffic or
// physical hardware identity. References and the returned value are caller-owned.
type AddressRole struct {
	Name       string   `json:"name"`
	Prefix     string   `json:"prefix"`
	Identifier uint16   `json:"identifier"`
	References []string `json:"references"`
}

const vrrpReference = "https://www.rfc-editor.org/rfc/rfc9568.html#section-7.3"
const carpReference = "https://github.com/openbsd/src/blob/d11ef3f2eb061fd729dc1885eaf71ab411202b53/sys/netinet/ip_carp.c"
const hsrpReference = "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ntw-servs/b-network-services/m_fhp-hsrp-0.html"
const hsrpIPv6Reference = "https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/unicast-routing-configuration/cisco-nexus-9000-series-nx-os-unicast-routing-configuration-guide/m_configuring_hsrp.pdf#page=3"

// hw has already been validated as a global-unicast 48-bit address by Lookup.
func addressRole(hw []byte) *AddressRole {
	switch string(hw[:3]) {
	case "\x00\x00\x5e":
		if hw[3] != 0 || hw[5] == 0 {
			return nil // VRID/VHID zero is not a configured virtual router.
		}
		switch hw[4] {
		case 1:
			// CARP shares this range; the MAC alone cannot distinguish it
			// from IPv4 VRRP, nor establish the peer's IP address family.
			return &AddressRole{"VRRP/CARP virtual MAC range", "00:00:5e:00:01:00/40", uint16(hw[5]), []string{vrrpReference, carpReference}}
		case 2:
			return &AddressRole{"VRRP IPv6 virtual MAC range", "00:00:5e:00:02:00/40", uint16(hw[5]), []string{vrrpReference}}
		}
	case "\x00\x00\x0c":
		if hw[3] == 7 && hw[4] == 0xac {
			return &AddressRole{"HSRP v1 virtual MAC range", "00:00:0c:07:ac:00/40", uint16(hw[5]), []string{hsrpReference}}
		}
		if hw[3] == 0x9f && hw[4]&0xf0 == 0xf0 {
			return &AddressRole{"HSRP v2 IPv4 virtual MAC range", "00:00:0c:9f:f0:00/36", uint16(hw[4]&15)<<8 | uint16(hw[5]), []string{hsrpReference}}
		}
	case "\x00\x05\x73":
		if hw[3] == 0xa0 && hw[4]&0xf0 == 0 {
			return &AddressRole{"HSRP v2 IPv6 virtual MAC range", "00:05:73:a0:00:00/36", uint16(hw[4]&15)<<8 | uint16(hw[5]), []string{hsrpIPv6Reference}}
		}
	}
	return nil
}
