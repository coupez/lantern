package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
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
	c, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
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
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
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
			m, e := icmp.ParseMessage(1, b[:n])
			if e != nil || m.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			body, ok := m.Body.(*icmp.Echo)
			if !ok || !bytes.Equal(body.Data, nonce) {
				continue
			}
			peerHost := peer.String()
			if addr, ok := peer.(*net.UDPAddr); ok {
				peerHost = addr.IP.String()
			}
			if addr, ok := peer.(*net.IPAddr); ok {
				peerHost = addr.IP.String()
			}
			a, e := netip.ParseAddr(peerHost)
			if e != nil {
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
		m := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: 1, Seq: i % 65536, Data: nonce}}
		b, _ := m.Marshal(nil)
		startsMu.Lock()
		starts[ip] = time.Now()
		startsMu.Unlock()
		// A full Darwin ICMP send queue must never block the entire sweep.
		c.SetWriteDeadline(time.Now().Add(2 * time.Millisecond))
		if _, e := c.WriteTo(b, &net.UDPAddr{IP: net.IP(ip.AsSlice())}); e != nil {
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
