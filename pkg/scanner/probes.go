package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type tcpDialer struct{}

func (tcpDialer) Probe(ctx context.Context, ip netip.Addr, port uint16, timeout time.Duration) (bool, bool, time.Duration, error) {
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	elapsed := time.Since(start)
	if err == nil {
		c.Close()
		return true, true, elapsed, nil
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true, false, elapsed, nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, syscall.EHOSTDOWN) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) || ctx.Err() != nil {
		return false, false, elapsed, nil
	}
	return false, false, elapsed, err
}

type pingHit struct {
	IP  netip.Addr
	RTT time.Duration
}

func pingSweep(ctx context.Context, hosts []netip.Addr, timeout time.Duration, hit func(pingHit), attempt func(netip.Addr)) error {
	if len(hosts) == 0 || ctx.Err() != nil {
		return nil
	}
	network, bind, proto := "udp4", "0.0.0.0", 1
	var requestType icmp.Type = ipv4.ICMPTypeEcho
	var replyType icmp.Type = ipv4.ICMPTypeEchoReply
	if hosts[0].Is6() {
		network, bind, proto = "udp6", "::", 58
		requestType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
	}
	c, err := icmp.ListenPacket(network, bind)
	if err != nil {
		return fmt.Errorf("ICMP unavailable: %w", err)
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	var startsMu sync.RWMutex
	starts := make(map[netip.Addr]time.Time, len(hosts))
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 1500)
		for {
			n, peer, e := c.ReadFrom(b)
			if e != nil {
				return
			}
			m, e := icmp.ParseMessage(proto, b[:n])
			if e != nil || m.Type != replyType || m.Code != 0 {
				continue
			}
			body, ok := m.Body.(*icmp.Echo)
			if !ok || !bytes.Equal(body.Data, nonce) {
				continue
			}
			a, ok := pingPeer(peer)
			if !ok {
				continue
			}
			startsMu.RLock()
			t, ok := starts[a.Unmap()]
			startsMu.RUnlock()
			if ok {
				hit(pingHit{a.Unmap(), time.Since(t)})
			}
		}
	}()
	var writeErr error
	dropped := 0
	for i, ip := range hosts {
		if ctx.Err() != nil {
			break
		}
		if attempt != nil {
			attempt(ip)
		}
		m := icmp.Message{Type: requestType, Code: 0, Body: &icmp.Echo{ID: 1, Seq: i % 65536, Data: nonce}}
		b, _ := m.Marshal(nil)
		startsMu.Lock()
		starts[ip] = time.Now()
		startsMu.Unlock()
		// A full Darwin ICMP send queue must never block the entire sweep.
		c.SetWriteDeadline(time.Now().Add(2 * time.Millisecond))
		if _, e := c.WriteTo(b, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Zone: ip.Zone()}); e != nil {
			dropped++
			if writeErr == nil {
				writeErr = e
			}
		}
	}
	c.SetReadDeadline(time.Now().Add(timeout))
	<-done
	if writeErr != nil {
		return fmt.Errorf("ICMP could not send %d probes: %w", dropped, writeErr)
	}
	return nil
}

func pingPeer(peer net.Addr) (netip.Addr, bool) {
	var ip net.IP
	var zone string
	switch p := peer.(type) {
	case *net.UDPAddr:
		ip, zone = p.IP, p.Zone
	case *net.IPAddr:
		ip, zone = p.IP, p.Zone
	default:
		a, err := netip.ParseAddr(peer.String())
		return a, err == nil
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	if a.Is6() && a.IsLinkLocalUnicast() {
		a = a.WithZone(zone)
	}
	return a, true
}
func pingAllNodes6(ctx context.Context, iface *net.Interface, target netip.Prefix, timeout time.Duration, limit int, hit func(pingHit)) error {
	if ctx.Err() != nil {
		return nil
	}
	c, err := icmp.ListenPacket("udp6", "::")
	if err != nil {
		return fmt.Errorf("IPv6 multicast echo unavailable: %w", err)
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if err = c.IPv6PacketConn().SetMulticastInterface(iface); err != nil {
		return err
	}
	if err = c.IPv6PacketConn().SetMulticastHopLimit(1); err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	m := icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: 1, Seq: 1, Data: nonce}}
	b, err := m.Marshal(nil)
	if err != nil {
		return err
	}
	start := time.Now()
	c.SetDeadline(start.Add(timeout))
	if _, err = c.WriteTo(b, &net.UDPAddr{IP: net.ParseIP("ff02::1"), Zone: iface.Name}); err != nil {
		return fmt.Errorf("IPv6 all-nodes echo: %w", err)
	}
	buffer := make([]byte, 1500)
	seen := map[netip.Addr]bool{}
	for packets := 0; packets < max(64, limit*4); packets++ {
		n, peer, err := c.ReadFrom(buffer)
		if err != nil {
			var ne net.Error
			if ctx.Err() != nil || errors.As(err, &ne) && ne.Timeout() {
				return nil
			}
			return err
		}
		message, err := icmp.ParseMessage(58, buffer[:n])
		if err != nil || message.Type != ipv6.ICMPTypeEchoReply || message.Code != 0 {
			continue
		}
		body, ok := message.Body.(*icmp.Echo)
		if !ok || !bytes.Equal(body.Data, nonce) {
			continue
		}
		ip, ok := pingPeer(peer)
		if !ok || !ip.Is6() || !inTarget(target, ip) || (ip.Zone() != "" && ip.Zone() != iface.Name) {
			continue
		}
		ip = scoped(ip, iface.Name)
		if seen[ip] {
			continue
		}
		if len(seen) >= limit {
			return fmt.Errorf("IPv6 echo candidate limit reached")
		}
		seen[ip] = true
		hit(pingHit{ip, time.Since(start)})
	}
	return fmt.Errorf("IPv6 echo response budget reached")
}
