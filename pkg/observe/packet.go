package observe

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/coupez/lantern/pkg/capture"
	"github.com/coupez/lantern/pkg/dhcp"
)

// Decode accepts Ethernet (up to two VLAN tags), raw IP, BSD null/loopback and
// Linux cooked frames. Fragmented IP traffic is not reassembled. Transport/IP
// checksums are not authentication and may be absent due to capture offload.
func Decode(p capture.Packet) (Observation, error) {
	o := Observation{Timestamp: p.Timestamp, Section: p.Section, Interface: p.Interface, LinkType: p.LinkType, CapturedTruncated: p.Truncated}
	b := p.Data
	var ether uint16
	switch p.LinkType {
	case 1:
		if len(b) < 14 {
			return o, ErrMalformed
		}
		o.EthernetSource = net.HardwareAddr(b[6:12]).String()
		ether = binary.BigEndian.Uint16(b[12:14])
		b = b[14:]
	case 101:
		if len(b) == 0 {
			return o, ErrMalformed
		}
		switch b[0] >> 4 {
		case 4:
			ether = 0x0800
		case 6:
			ether = 0x86dd
		default:
			return o, ErrMalformed
		}
	case 228:
		ether = 0x0800
	case 229:
		ether = 0x86dd
	case 0, 108:
		if len(b) < 4 {
			return o, ErrMalformed
		}
		family := binary.BigEndian.Uint32(b[:4])
		// LINKTYPE_NULL uses the capture host's byte order; family constants identify
		// the supported IPv4/IPv6 variants without assuming the reader's host OS.
		if p.LinkType == 0 && !ipFamily(family) {
			family = binary.LittleEndian.Uint32(b[:4])
		}
		switch family {
		case 2:
			ether = 0x0800
		case 10, 24, 28, 30:
			ether = 0x86dd
		default:
			return o, ErrUnsupported
		}
		b = b[4:]
	case 113:
		if len(b) < 16 {
			return o, ErrMalformed
		}
		ether = binary.BigEndian.Uint16(b[14:16])
		b = b[16:]
	case 276:
		if len(b) < 20 {
			return o, ErrMalformed
		}
		ether = binary.BigEndian.Uint16(b[:2])
		b = b[20:]
	default:
		return o, ErrUnsupported
	}
	for ether == 0x8100 || ether == 0x88a8 || ether == 0x9100 {
		if len(o.VLANs) >= 2 {
			return o, ErrUnsupported
		}
		if len(b) < 4 {
			return o, ErrMalformed
		}
		o.VLANs = append(o.VLANs, binary.BigEndian.Uint16(b[:2])&0x0fff)
		ether = binary.BigEndian.Uint16(b[2:4])
		b = b[4:]
	}
	var version int
	switch ether {
	case 0x0800:
		version = 4
		if len(b) < 20 || b[0]>>4 != 4 {
			return o, ErrMalformed
		}
		header := int(b[0]&15) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if header < 20 || header > len(b) || total < header || total > len(b) {
			return o, ErrMalformed
		}
		if b[9] != 17 {
			return o, ErrNotDHCP
		}
		o.IPHopLimit = b[8]
		if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return o, fmt.Errorf("%w: fragmented IPv4", ErrUnsupported)
		}
		o.SourceIP = netip.AddrFrom4([4]byte(b[12:16])).String()
		o.DestinationIP = netip.AddrFrom4([4]byte(b[16:20])).String()
		b = b[header:total]
	case 0x86dd:
		version = 6
		if len(b) < 40 || b[0]>>4 != 6 {
			return o, ErrMalformed
		}
		size := int(binary.BigEndian.Uint16(b[4:6]))
		if size == 0 {
			return o, fmt.Errorf("%w: IPv6 jumbogram", ErrUnsupported)
		}
		if size > len(b)-40 {
			return o, ErrMalformed
		}
		o.IPHopLimit = b[7]
		o.SourceIP = netip.AddrFrom16([16]byte(b[8:24])).String()
		o.DestinationIP = netip.AddrFrom16([16]byte(b[24:40])).String()
		next := b[6]
		b = b[40 : 40+size]
		extensions := 0
		for next != 17 {
			if extensions >= 8 {
				return o, fmt.Errorf("%w: too many IPv6 extension headers", ErrUnsupported)
			}
			extensions++
			var n int
			switch next {
			case 0, 43, 60:
				if len(b) < 2 {
					return o, ErrMalformed
				}
				n = (int(b[1]) + 1) * 8
			case 51:
				if len(b) < 2 {
					return o, ErrMalformed
				}
				n = (int(b[1]) + 2) * 4
			case 44:
				n = 8
				if len(b) < n {
					return o, ErrMalformed
				}
				if binary.BigEndian.Uint16(b[2:4])&0xfff9 != 0 {
					return o, fmt.Errorf("%w: fragmented IPv6", ErrUnsupported)
				}
			case 50:
				return o, ErrUnsupported
			default:
				return o, ErrNotDHCP
			}
			if n > len(b) {
				return o, ErrMalformed
			}
			next = b[0]
			b = b[n:]
		}
	default:
		return o, ErrNotDHCP
	}
	if len(b) < 8 {
		return o, ErrMalformed
	}
	o.SourcePort = binary.BigEndian.Uint16(b[:2])
	o.DestinationPort = binary.BigEndian.Uint16(b[2:4])
	if !dhcpPorts(version, o.SourcePort, o.DestinationPort) {
		return o, ErrNotDHCP
	}
	size := int(binary.BigEndian.Uint16(b[4:6]))
	if size < 8 || size > len(b) {
		return o, ErrMalformed
	}
	var message dhcp.Message
	var err error
	if version == 4 {
		message, err = dhcp.Parse4(b[8:size])
	} else {
		message, err = dhcp.Parse6(b[8:size])
	}
	if err != nil {
		return o, fmt.Errorf("%w: DHCPv%d: %v", ErrMalformed, version, err)
	}
	o.Message = message
	return o, nil
}
func ipFamily(n uint32) bool { return n == 2 || n == 10 || n == 24 || n == 28 || n == 30 }
func dhcpPorts(v int, src, dst uint16) bool {
	if v == 4 {
		return (src == 68 && dst == 67) || (src == 67 && (dst == 68 || dst == 67))
	}
	return (src == 546 && dst == 547) || (src == 547 && (dst == 546 || dst == 547))
}
