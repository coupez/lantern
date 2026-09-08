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

// Neighbor is a solicited link-layer response, independent of TCP reachability.
type Neighbor struct {
	IP  netip.Addr
	MAC string
	RTT time.Duration
}

// ARPResult retains partial observations and attempted addresses on cancellation.
type ARPResult struct {
	Neighbors []Neighbor
	Probed    []netip.Addr
}

type arpLink struct {
	iface   net.Interface
	address netip.Addr
	prefix  netip.Prefix
}

func arpInterface(target netip.Prefix, preferred string) (arpLink, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return arpLink{}, err
	}
	var links []arpLink
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagPointToPoint != 0 || !validEthernetMAC(i.HardwareAddr) || (preferred != "" && i.Name != preferred) {
			continue
		}
		as, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range as {
			p, err := netip.ParsePrefix(a.String())
			if err == nil && p.Addr().Is4() && p.Overlaps(target) {
				links = append(links, arpLink{i, p.Addr(), p.Masked()})
			}
		}
	}
	if len(links) == 0 {
		return arpLink{}, fmt.Errorf("ARP needs an Ethernet interface with an IPv4 network overlapping the target")
	}
	for _, l := range links[1:] {
		if l.iface.Index != links[0].iface.Index {
			return arpLink{}, fmt.Errorf("ARP target spans multiple interfaces; choose --interface")
		}
	}
	// Prefer the most specific matching local prefix, then a stable address.
	best := links[0]
	for _, l := range links[1:] {
		if l.prefix.Bits() > best.prefix.Bits() || (l.prefix.Bits() == best.prefix.Bits() && l.address.Less(best.address)) {
			best = l
		}
	}
	return best, nil
}
func validEthernetMAC(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0]&1 == 0 && !bytes.Equal(mac, make([]byte, 6))
}
func arpRequest(local netip.Addr, mac net.HardwareAddr, target netip.Addr) []byte {
	b := make([]byte, 60) // Ethernet minimum payload, excluding FCS.
	for i := 0; i < 6; i++ {
		b[i] = 0xff
	}
	copy(b[6:12], mac)
	binary.BigEndian.PutUint16(b[12:14], 0x0806)
	binary.BigEndian.PutUint16(b[14:16], 1)
	binary.BigEndian.PutUint16(b[16:18], 0x0800)
	b[18], b[19] = 6, 4
	binary.BigEndian.PutUint16(b[20:22], 1)
	copy(b[22:28], mac)
	copy(b[28:32], local.AsSlice())
	copy(b[38:42], target.AsSlice())
	return b
}

// parseARPReply accepts Ethernet/IPv4 replies addressed to this scanner. VLAN
// interfaces should be selected directly; raw tagged/trunk frames are excluded.
func parseARPReply(b []byte, local netip.Addr, mac net.HardwareAddr) (Neighbor, bool) {
	if len(b) < 42 || len(mac) != 6 || !local.Is4() {
		return Neighbor{}, false
	}
	if binary.BigEndian.Uint16(b[12:14]) != 0x0806 || binary.BigEndian.Uint16(b[14:16]) != 1 || binary.BigEndian.Uint16(b[16:18]) != 0x0800 || b[18] != 6 || b[19] != 4 || binary.BigEndian.Uint16(b[20:22]) != 2 {
		return Neighbor{}, false
	}
	if !bytes.Equal(b[:6], mac) || !bytes.Equal(b[32:38], mac) || !bytes.Equal(b[38:42], local.AsSlice()) || !bytes.Equal(b[6:12], b[22:28]) || !validEthernetMAC(b[22:28]) {
		return Neighbor{}, false
	}
	ip := netip.AddrFrom4([4]byte(b[28:32]))
	if ip.IsUnspecified() || ip.IsMulticast() || ip == local || ip == netip.MustParseAddr("255.255.255.255") {
		return Neighbor{}, false
	}
	return Neighbor{IP: ip, MAC: net.HardwareAddr(b[22:28]).String()}, true
}

type arpConn interface {
	ReadFrame() ([]byte, error)
	WriteFrame([]byte) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
}

func arpSweep(ctx context.Context, o Options, hosts []netip.Addr) (ARPResult, error) {
	if ctx.Err() != nil {
		return ARPResult{}, nil
	}
	link, err := arpInterface(o.Target, o.Interface)
	if err != nil {
		return ARPResult{}, err
	}
	c, err := openARP(&link.iface)
	if err != nil {
		return ARPResult{}, fmt.Errorf("ARP unavailable on %s (macOS needs BPF access; Linux needs CAP_NET_RAW): %w", link.iface.Name, err)
	}
	defer c.Close()
	return exchangeARP(ctx, c, link, hosts, o.Timeout)
}
func exchangeARP(ctx context.Context, c arpConn, link arpLink, hosts []netip.Addr, timeout time.Duration) (ARPResult, error) {
	result := ARPResult{}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	var mu sync.Mutex
	starts := map[netip.Addr]time.Time{}
	seen := map[netip.Addr]bool{}
	readErr := make(chan error, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			b, err := c.ReadFrame()
			if err != nil {
				readErr <- err
				return
			}
			n, ok := parseARPReply(b, link.address, link.iface.HardwareAddr)
			if !ok {
				continue
			}
			mu.Lock()
			start, solicited := starts[n.IP]
			if solicited && !seen[n.IP] {
				seen[n.IP] = true
				n.RTT = time.Since(start)
				result.Neighbors = append(result.Neighbors, n)
			}
			mu.Unlock()
		}
	}()
	// Bursts of 32 at 10 ms intervals cap send rate at about 3,200 requests/s.
	// This avoids relying on sub-millisecond timer resolution across platforms.
	var firstErr error
	sent := 0
send:
	for _, ip := range hosts {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-readerDone:
			break send
		default:
		}
		if !ip.Is4() || ip == link.address || !link.prefix.Contains(ip) {
			continue
		}
		if sent > 0 && sent%32 == 0 {
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
		starts[ip] = time.Now()
		mu.Unlock()
		result.Probed = append(result.Probed, ip)
		if err := c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
			firstErr = err
			break
		}
		if err := c.WriteFrame(arpRequest(link.address, link.iface.HardwareAddr, ip)); err != nil {
			firstErr = err
			break
		}
		sent++
	}
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		c.Close()
		if firstErr == nil {
			firstErr = err
		}
	}
	err := <-readErr
	if ctx.Err() != nil {
		return result, nil
	}
	if firstErr != nil {
		return result, fmt.Errorf("ARP send: %w", firstErr)
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return result, fmt.Errorf("ARP receive: %w", err)
	}
	return result, nil
}
