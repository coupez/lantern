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
	"os"
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

// ICMPStats distinguishes kernel-accepted sends from actual replies. Counts are
// for unicast echo only; IPv6 multicast candidate discovery is separate.
type ICMPStats struct {
	Attempted            int  `json:"attempted"`
	Sent                 int  `json:"sent"`
	Retries              int  `json:"retries"`
	Recovered            int  `json:"recovered"`
	Failed               int  `json:"failed"`
	Responders           int  `json:"responders"`
	RetryBudgetExhausted bool `json:"retry_budget_exhausted,omitempty"`
}
type echoConn interface {
	ReadFrom([]byte) (int, net.Addr, error)
	WriteTo([]byte, net.Addr) (int, error)
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
}

func pingSweep(ctx context.Context, hosts []netip.Addr, timeout time.Duration, hit func(pingHit), attempt func(netip.Addr)) (ICMPStats, error) {
	if len(hosts) == 0 || ctx.Err() != nil {
		return ICMPStats{}, nil
	}
	network, bind := "udp4", "0.0.0.0"
	if hosts[0].Is6() {
		network, bind = "udp6", "::"
	}
	c, err := icmp.ListenPacket(network, bind)
	if err != nil {
		return ICMPStats{}, fmt.Errorf("ICMP unavailable: %w", err)
	}
	defer c.Close()
	return exchangeEcho(ctx, c, hosts, timeout, hit, attempt)
}
func exchangeEcho(ctx context.Context, c echoConn, hosts []netip.Addr, timeout time.Duration, hit func(pingHit), attempt func(netip.Addr)) (ICMPStats, error) {
	stats := ICMPStats{}
	if len(hosts) == 0 || ctx.Err() != nil {
		return stats, nil
	}
	proto := 1
	var requestType icmp.Type = ipv4.ICMPTypeEcho
	var replyType icmp.Type = ipv4.ICMPTypeEchoReply
	if hosts[0].Is6() {
		proto = 58
		requestType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return stats, err
	}
	type probe struct {
		start    time.Time
		seq      int
		answered bool
		err      error
	}
	var mu sync.Mutex
	probes := make(map[netip.Addr]*probe, len(hosts))
	readDone := make(chan struct{})
	var readErr error
	responders := 0
	go func() {
		defer close(readDone)
		b := make([]byte, 1500)
		for {
			n, peer, err := c.ReadFrom(b)
			if err != nil {
				readErr = err
				return
			}
			message, err := icmp.ParseMessage(proto, b[:n])
			if err != nil || message.Type != replyType || message.Code != 0 {
				continue
			}
			body, ok := message.Body.(*icmp.Echo)
			if !ok || !bytes.Equal(body.Data, nonce) {
				continue
			}
			ip, ok := pingPeer(peer)
			if !ok {
				continue
			}
			mu.Lock()
			p := probes[ip]
			if p == nil || p.answered || body.Seq != p.seq {
				mu.Unlock()
				continue
			}
			p.answered = true
			responders++
			elapsed := time.Since(p.start)
			complete := responders == len(hosts)
			mu.Unlock()
			hit(pingHit{ip, elapsed})
			// Every target has replied; waiting for the timeout cannot add a new host.
			if complete {
				return
			}
		}
	}()
	var retry []int
	send := func(i int, deadline time.Time) error {
		ip := hosts[i]
		m := icmp.Message{Type: requestType, Body: &icmp.Echo{ID: 1, Seq: i % 65536, Data: nonce}}
		packet, err := m.Marshal(nil)
		if err != nil {
			return err
		}
		if err = c.SetWriteDeadline(deadline); err != nil {
			return err
		}
		_, err = c.WriteTo(packet, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Zone: ip.Zone()})
		return err
	}
	setError := func(ip netip.Addr, err error) { mu.Lock(); probes[ip].err = err; mu.Unlock() }
firstPass:
	for i, ip := range hosts {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-readDone:
			break firstPass
		default:
		}
		if attempt != nil {
			attempt(ip)
		}
		stats.Attempted++
		mu.Lock()
		probes[ip] = &probe{start: time.Now(), seq: i % 65536}
		mu.Unlock()
		err := send(i, time.Now().Add(2*time.Millisecond))
		setError(ip, err)
		if err != nil && retryableEchoSend(err) {
			retry = append(retry, i)
		}
	}
	// One retry per pressure-dropped address, sharing at most 100 ms. This retries
	// local queue failures only; unanswered, successfully sent probes are not resent.
	retryUntil := time.Now().Add(min(timeout, 100*time.Millisecond))
retryPass:
	for _, i := range retry {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-readDone:
			break retryPass
		default:
		}
		if time.Until(retryUntil) <= 2*time.Millisecond {
			stats.RetryBudgetExhausted = true
			break
		}
		mu.Lock()
		answered := probes[hosts[i]].answered
		mu.Unlock()
		if answered {
			continue
		}
		timer := time.NewTimer(2 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
		}
		if ctx.Err() != nil {
			break
		}
		stats.Retries++
		err := send(i, minTime(time.Now().Add(2*time.Millisecond), retryUntil))
		if err == nil {
			stats.Recovered++
		}
		setError(hosts[i], err)
	}
	var firstErr error
	mu.Lock()
	for _, ip := range hosts {
		if p := probes[ip]; p != nil {
			if p.err != nil {
				stats.Failed++
				if firstErr == nil {
					firstErr = p.err
				}
			} else {
				stats.Sent++
			}
		}
	}
	mu.Unlock()
	var deadlineErr error
	if stats.Sent == 0 {
		c.Close()
	} else if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		c.Close()
		deadlineErr = err
	}
	<-readDone
	stats.Responders = responders
	if ctx.Err() != nil {
		return stats, nil
	}
	if firstErr != nil {
		return stats, fmt.Errorf("ICMP could not send %d probes after %d retries: %w", stats.Failed, stats.Retries, firstErr)
	}
	if deadlineErr != nil {
		return stats, fmt.Errorf("ICMP response deadline: %w", deadlineErr)
	}
	if readErr != nil && !errors.Is(readErr, os.ErrDeadlineExceeded) {
		return stats, fmt.Errorf("ICMP receive: %w", readErr)
	}
	return stats, nil
}
func retryableEchoSend(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.EAGAIN)
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
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
