package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// NetBIOSName retains the 16 name bytes (including the suffix) and RFC 1002
// registration flags. The OEM character encoding is not specified on the wire.
type NetBIOSName struct {
	Name  [16]byte
	Flags uint16
}

// NetBIOSReply is an unauthenticated node-status response. UnitID is reported by
// the remote application; it must not replace an observed link-layer MAC.
type NetBIOSReply struct {
	IP     netip.Addr
	Names  []NetBIOSName
	UnitID string
}

// NetBIOSResult retains responses and attempted addresses, including on cancellation.
type NetBIOSResult struct {
	Replies []NetBIOSReply
	Probed  []netip.Addr
}

// RFC 1002 wildcard: '*' followed by 15 nulls, first-level A–P encoding,
// then an empty scope. This is a status request, never a name registration.
var netbiosWildcard = func() []byte {
	name := make([]byte, 34)
	name[0] = 32
	for i := 1; i <= 32; i++ {
		name[i] = 'A'
	}
	name[1], name[2] = 'C', 'K'
	return name
}()

func netbiosQuery(id uint16) []byte {
	b := make([]byte, 50)
	binary.BigEndian.PutUint16(b, id)
	binary.BigEndian.PutUint16(b[4:], 1)
	copy(b[12:], netbiosWildcard)
	binary.BigEndian.PutUint16(b[46:], 0x21)
	binary.BigEndian.PutUint16(b[48:], 1)
	return b
}

func parseNetBIOSReply(b []byte, id uint16) (NetBIOSReply, bool) {
	// A node-status response has no question and exactly one NBSTAT/IN answer.
	// With no earlier name in the message, RR_NAME is the uncompressed wildcard.
	if len(b) < 57 || binary.BigEndian.Uint16(b) != id || binary.BigEndian.Uint16(b[2:]) != 0x8400 ||
		binary.BigEndian.Uint16(b[4:]) != 0 || binary.BigEndian.Uint16(b[6:]) != 1 ||
		binary.BigEndian.Uint32(b[8:]) != 0 || !bytes.Equal(b[12:46], netbiosWildcard) ||
		binary.BigEndian.Uint16(b[46:]) != 0x21 || binary.BigEndian.Uint16(b[48:]) != 1 ||
		binary.BigEndian.Uint32(b[50:]) != 0 {
		return NetBIOSReply{}, false
	}
	length := int(binary.BigEndian.Uint16(b[54:]))
	count := int(b[56])
	// The status tail is 46 bytes, including its six-byte unit ID. Require the
	// complete table and tail so truncation cannot manufacture partial identities.
	if length != 1+count*18+46 || len(b) != 56+length {
		return NetBIOSReply{}, false
	}
	reply := NetBIOSReply{Names: make([]NetBIOSName, count)}
	for i := range reply.Names {
		offset := 57 + i*18
		copy(reply.Names[i].Name[:], b[offset:offset+16])
		reply.Names[i].Flags = binary.BigEndian.Uint16(b[offset+16:])
	}
	unit := net.HardwareAddr(b[57+count*18 : 63+count*18])
	if validEthernetMAC(unit) {
		reply.UnitID = unit.String()
	}
	return reply, true
}

func netbiosSweep(ctx context.Context, hosts []netip.Addr, timeout time.Duration) (NetBIOSResult, error) {
	if len(hosts) == 0 || ctx.Err() != nil {
		return NetBIOSResult{}, nil
	}
	c, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return NetBIOSResult{}, fmt.Errorf("NetBIOS unavailable: %w", err)
	}
	defer c.Close()
	return exchangeNetBIOS(ctx, c, hosts, timeout, 137)
}

func exchangeNetBIOS(ctx context.Context, c echoConn, hosts []netip.Addr, timeout time.Duration, port uint16) (NetBIOSResult, error) {
	result := NetBIOSResult{}
	if len(hosts) == 0 || ctx.Err() != nil {
		return result, nil
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	type probe struct {
		id             uint16
		sent, answered bool
	}
	probes := make(map[netip.Addr]*probe, len(hosts))
	entropy := make([]byte, len(hosts)*2)
	if _, err := rand.Read(entropy); err != nil {
		return result, err
	}
	for i, ip := range hosts {
		if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip == netip.MustParseAddr("255.255.255.255") {
			return result, fmt.Errorf("NetBIOS requires unicast IPv4 targets")
		}
		probes[ip] = &probe{id: binary.BigEndian.Uint16(entropy[i*2:])}
	}
	var mu sync.Mutex
	done := make(chan struct{})
	var readErr error
	go func() {
		defer close(done)
		b := make([]byte, 8192)
		for {
			n, peer, err := c.ReadFrom(b)
			if err != nil {
				readErr = err
				return
			}
			addr, ok := peer.(*net.UDPAddr)
			if !ok || addr.Port != int(port) || addr.Zone != "" {
				continue
			}
			ip, ok := netip.AddrFromSlice(addr.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			mu.Lock()
			p := probes[ip]
			if p == nil || !p.sent || p.answered {
				mu.Unlock()
				continue
			}
			reply, ok := parseNetBIOSReply(b[:n], p.id)
			if !ok {
				mu.Unlock()
				continue
			}
			p.answered = true
			reply.IP = ip
			result.Replies = append(result.Replies, reply)
			complete := len(result.Replies) == len(probes)
			mu.Unlock()
			if complete {
				return
			}
		}
	}()
	var sendErr error
	attempted := make(map[netip.Addr]bool, len(hosts))
send:
	for _, ip := range hosts {
		select {
		case <-ctx.Done():
			break send
		case <-done:
			break send
		default:
		}
		if attempted[ip] {
			continue
		}
		if len(result.Probed) > 0 && len(result.Probed)%32 == 0 {
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				break send
			case <-done:
				timer.Stop()
				break send
			case <-timer.C:
			}
		}
		if err := c.SetWriteDeadline(time.Now().Add(2 * time.Millisecond)); err != nil {
			sendErr = err
			break
		}
		attempted[ip] = true
		result.Probed = append(result.Probed, ip)
		mu.Lock()
		p := probes[ip]
		packet := netbiosQuery(p.id)
		n, err := c.WriteTo(packet, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, port)))
		p.sent = err == nil && n == len(packet)
		mu.Unlock()
		if err != nil {
			sendErr = err
			break
		}
		if n != len(packet) {
			sendErr = fmt.Errorf("short UDP write")
			break
		}
	}
	// Keep one response window after the final send; fully answered sweeps exit
	// immediately. A send error stops further writes rather than multiplying the
	// per-write deadline by every remaining address.
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		sendErr = errors.Join(sendErr, err)
		c.Close()
	}
	<-done
	if ctx.Err() != nil {
		return result, nil
	}
	var errs []error
	if sendErr != nil {
		errs = append(errs, fmt.Errorf("NetBIOS send stopped after %d/%d targets: %w", len(result.Probed), len(probes), sendErr))
	}
	if readErr != nil && !errors.Is(readErr, os.ErrDeadlineExceeded) {
		errs = append(errs, fmt.Errorf("NetBIOS receive: %w", readErr))
	}
	sort.Slice(result.Replies, func(i, j int) bool { return result.Replies[i].IP.Less(result.Replies[j].IP) })
	return result, errors.Join(errs...)
}

func netbiosText(raw []byte) string {
	raw = bytes.TrimRight(raw, " \x00")
	var out strings.Builder
	for _, b := range raw {
		if b >= 0x20 && b < 0x7f && b != '\\' {
			out.WriteByte(b)
		} else {
			fmt.Fprintf(&out, "\\x%02x", b)
		}
	}
	return out.String()
}

func netbiosHit(reply NetBIOSReply) discoveryHit {
	h := discoveryHit{IP: reply.IP, Evidence: "netbios"}
	status := Advertisement{Protocol: "netbios", Instance: reply.IP.String(), Service: "node-status", Port: 137, Properties: map[string]string{}}
	if mac, err := net.ParseMAC(reply.UnitID); err == nil && validEthernetMAC(mac) {
		status.Properties["reported_unit_id"] = mac.String()
	}
	h.Ads = append(h.Ads, status)
	for _, record := range reply.Names[:min(len(reply.Names), 255)] {
		name := netbiosText(record.Name[:15])
		suffix := record.Name[15]
		active := record.Flags&0x0400 != 0
		usable := active && record.Flags&0x1800 == 0
		group := record.Flags&0x8000 != 0
		service := "name-registration"
		if usable && suffix == 0 {
			if group {
				service = "workgroup"
			} else {
				service = "workstation"
			}
		}
		if usable && !group && suffix == 0x20 {
			service = "file-server"
		}
		props := map[string]string{"name": name, "raw_name_hex": hex.EncodeToString(record.Name[:]), "suffix": fmt.Sprintf("%02x", suffix), "flags": fmt.Sprintf("%04x", record.Flags), "group": fmt.Sprint(group), "active": fmt.Sprint(active), "conflict": fmt.Sprint(record.Flags&0x0800 != 0), "deregistering": fmt.Sprint(record.Flags&0x1000 != 0)}
		if name != "" && (service == "workstation" || service == "file-server") && !contains(h.Names, name) {
			h.Names = append(h.Names, name)
		}
		h.Ads = append(h.Ads, Advertisement{Protocol: "netbios", Instance: name + fmt.Sprintf("<%02x>", suffix), Service: service, Port: 137, Properties: props})
	}
	return h
}
