package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// NDPResult retains solicited IPv6 neighbors and attempted addresses, including
// interface zones on link-local addresses. It may accompany a partial failure.
type NDPResult struct {
	Neighbors []Neighbor
	Probed    []netip.Addr
}

type ndpLink struct {
	iface    net.Interface
	prefixes []netip.Prefix
}

func ndpInterface(target netip.Prefix, preferred string) (ndpLink, error) {
	iface, prefixes, err := ipv6Interface(target, preferred)
	if err != nil {
		return ndpLink{}, err
	}
	if iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || !validEthernetMAC(iface.HardwareAddr) {
		return ndpLink{}, fmt.Errorf("NDP needs an Ethernet interface with an IPv6 address")
	}
	return ndpLink{*iface, prefixes}, nil
}

// Keep solicitations on the selected link and never probe our own addresses.
// Prefer a source in the target's configured prefix, then a link-local source.
func (l ndpLink) source(target netip.Addr) (netip.Addr, bool) {
	if target.IsLoopback() || !onIPv6Link(target, l.iface.Name, l.prefixes) {
		return netip.Addr{}, false
	}
	target = target.WithZone("")
	var best netip.Addr
	score := -1
	for _, p := range l.prefixes {
		a := p.Addr().WithZone("")
		if a == target {
			return netip.Addr{}, false
		}
		if !a.Is6() || a.Is4In6() || a.IsMulticast() || a.IsUnspecified() || a.IsLoopback() {
			continue
		}
		n := 0
		if a.IsLinkLocalUnicast() {
			n = 1
		}
		if p.Contains(target) {
			n = 2 + p.Bits()
		}
		if target.IsLinkLocalUnicast() && !a.IsLinkLocalUnicast() {
			continue
		}
		if n > score || n == score && a.Less(best) {
			best, score = a, n
		}
	}
	return best, best.IsValid()
}

// ICMPv6 includes the IPv6 pseudo-header, unlike the ICMPv4 checksum.
func ndpChecksum(source, destination, message []byte) uint16 {
	sum := uint32(len(message)) + 58
	for _, b := range [][]byte{source, destination, message} {
		for len(b) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(b))
			b = b[2:]
		}
		if len(b) != 0 {
			sum += uint32(b[0]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ndpRequest(local netip.Addr, mac net.HardwareAddr, target netip.Addr) []byte {
	a := target.As16()
	destination := netip.MustParseAddr("ff02::1:ff00:0").As16()
	copy(destination[13:], a[13:])
	b := make([]byte, 14+40+32)
	copy(b[:6], []byte{0x33, 0x33, 0xff, a[13], a[14], a[15]})
	copy(b[6:12], mac)
	binary.BigEndian.PutUint16(b[12:14], 0x86dd)
	ip := b[14:54]
	ip[0], ip[6], ip[7] = 0x60, 58, 255
	binary.BigEndian.PutUint16(ip[4:6], 32)
	copy(ip[8:24], local.AsSlice())
	copy(ip[24:40], destination[:])
	message := b[54:]
	message[0] = 135
	copy(message[8:24], a[:])
	message[24], message[25] = 1, 1 // source link-layer address, eight bytes
	copy(message[26:32], mac)
	binary.BigEndian.PutUint16(message[2:4], ndpChecksum(ip[8:24], ip[24:40], message))
	return b
}

// Accept only solicited unicast advertisements addressed to this interface,
// with an Ethernet target-address option and a valid ICMPv6 checksum. The caller
// also correlates the advertised target and destination with an actual request.
// Raw VLAN trunks, fragments, routing/authentication headers are not decoded.
func parseNDPReply(b []byte, mac net.HardwareAddr) (Neighbor, netip.Addr, bool) {
	bad := func() (Neighbor, netip.Addr, bool) { return Neighbor{}, netip.Addr{}, false }
	if len(b) < 14+40+32 || !bytes.Equal(b[:6], mac) || !validEthernetMAC(b[6:12]) || binary.BigEndian.Uint16(b[12:14]) != 0x86dd {
		return bad()
	}
	ip := b[14:]
	length := int(binary.BigEndian.Uint16(ip[4:6]))
	if ip[0]>>4 != 6 || ip[7] != 255 || length == 0 || length > len(ip)-40 {
		return bad()
	}
	source := netip.AddrFrom16([16]byte(ip[8:24]))
	destination := netip.AddrFrom16([16]byte(ip[24:40]))
	if source.IsUnspecified() || source.IsMulticast() || source.Is4In6() || source.IsLoopback() || destination.IsUnspecified() || destination.IsMulticast() || destination.Is4In6() || destination.IsLoopback() {
		return bad()
	}
	message, next := ip[40:40+length], ip[6]
	for n := 0; next != 58; n++ {
		if n == 8 || (next != 0 && next != 60) || len(message) < 8 {
			return bad()
		}
		size := (int(message[1]) + 1) * 8
		if size > len(message) {
			return bad()
		}
		next, message = message[0], message[size:]
	}
	if len(message) < 32 || message[0] != 136 || message[1] != 0 || message[4]&0x40 == 0 || ndpChecksum(ip[8:24], ip[24:40], message) != 0 {
		return bad()
	}
	target := netip.AddrFrom16([16]byte(message[8:24]))
	if target.IsUnspecified() || target.IsMulticast() || target.Is4In6() || target.IsLoopback() {
		return bad()
	}
	var address net.HardwareAddr
	for options := message[24:]; len(options) > 0; {
		if len(options) < 2 || options[1] == 0 {
			return bad()
		}
		size := int(options[1]) * 8
		if size > len(options) {
			return bad()
		}
		if options[0] == 2 {
			if size != 8 || address != nil || !validEthernetMAC(options[2:8]) {
				return bad()
			}
			address = net.HardwareAddr(options[2:8])
		}
		options = options[size:]
	}
	if address == nil || !bytes.Equal(address, b[6:12]) {
		return bad()
	}
	return Neighbor{IP: target, MAC: address.String()}, destination, true
}

func openNDP(iface *net.Interface) (frameConn, error) { return openEthernet(iface, 0x86dd, 2048) }

func ndpSweep(ctx context.Context, o Options, hosts []netip.Addr) (NDPResult, error) {
	if ctx.Err() != nil {
		return NDPResult{}, nil
	}
	link, err := ndpInterface(o.Target, o.Interface)
	if err != nil {
		return NDPResult{}, err
	}
	c, err := openNDP(&link.iface)
	if err != nil {
		return NDPResult{}, fmt.Errorf("NDP unavailable on %s (macOS needs BPF access; Linux needs CAP_NET_RAW): %w", link.iface.Name, err)
	}
	defer c.Close()
	return exchangeNDP(ctx, c, link, hosts, o.Timeout)
}

func exchangeNDP(ctx context.Context, c frameConn, link ndpLink, hosts []netip.Addr, timeout time.Duration) (NDPResult, error) {
	result := NDPResult{}
	if ctx.Err() != nil {
		return result, nil
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	type pending struct {
		source netip.Addr
		start  time.Time
	}
	starts := map[netip.Addr]pending{}
	seen := map[netip.Addr]bool{}
	var mu sync.Mutex
	sendingDone := false
	readDone := make(chan error, 1)
	go func() {
		for {
			b, err := c.ReadFrame()
			if err != nil {
				readDone <- err
				return
			}
			n, destination, ok := parseNDPReply(b, link.iface.HardwareAddr)
			if !ok {
				continue
			}
			mu.Lock()
			p, solicited := starts[n.IP]
			if solicited && p.source == destination && !seen[n.IP] {
				seen[n.IP] = true
				n.IP = scoped(n.IP, link.iface.Name)
				n.RTT = time.Since(p.start)
				result.Neighbors = append(result.Neighbors, n)
			}
			complete := sendingDone && len(seen) == len(starts)
			mu.Unlock()
			if complete {
				readDone <- nil
				return
			}
		}
	}()
	var sendErr, receiveErr error
	readerFinished := false
	sent := 0
send:
	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		select {
		case receiveErr = <-readDone:
			readerFinished = true
			break send
		default:
		}
		source, ok := link.source(host)
		if !ok {
			continue
		}
		ip := host.WithZone("")
		mu.Lock()
		_, duplicate := starts[ip]
		mu.Unlock()
		if duplicate {
			continue
		}
		if len(result.Probed) > 0 && len(result.Probed)%32 == 0 {
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
			}
			if ctx.Err() != nil {
				break
			}
		}
		mu.Lock()
		starts[ip] = pending{source, time.Now()}
		mu.Unlock()
		result.Probed = append(result.Probed, scoped(ip, link.iface.Name))
		if sendErr = c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond)); sendErr != nil {
			break
		}
		if sendErr = c.WriteFrame(ndpRequest(source, link.iface.HardwareAddr, ip)); sendErr != nil {
			break
		}
		sent++
	}
	mu.Lock()
	sendingDone = true
	complete := sent == 0 || len(starts) == len(seen)
	mu.Unlock()
	if !readerFinished {
		deadline := time.Now().Add(timeout)
		if complete {
			deadline = time.Now()
		}
		if err := c.SetReadDeadline(deadline); err != nil {
			c.Close()
			receiveErr = err
		}
		err := <-readDone
		if receiveErr == nil {
			receiveErr = err
		}
	}
	if ctx.Err() != nil {
		return result, nil
	}
	var errs []error
	if sendErr != nil {
		errs = append(errs, fmt.Errorf("NDP send: %w", sendErr))
	}
	if receiveErr != nil && !errors.Is(receiveErr, os.ErrDeadlineExceeded) {
		errs = append(errs, fmt.Errorf("NDP receive: %w", receiveErr))
	}
	return result, errors.Join(errs...)
}
