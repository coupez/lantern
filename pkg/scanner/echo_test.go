package scanner

import (
	"context"
	"errors"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

type echoPacket struct {
	data []byte
	peer net.Addr
	err  error
}
type fakeEcho struct {
	reads           chan echoPacket
	closed          chan struct{}
	once            sync.Once
	mu              sync.Mutex
	timer           *time.Timer
	readDeadlineErr error
	write           func([]byte, net.Addr) (int, error)
}

func newFakeEcho() *fakeEcho {
	return &fakeEcho{reads: make(chan echoPacket, 128), closed: make(chan struct{})}
}
func (f *fakeEcho) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-f.reads:
		return copy(b, p.data), p.peer, p.err
	case <-f.closed:
		return 0, nil, os.ErrClosed
	}
}
func (f *fakeEcho) WriteTo(b []byte, a net.Addr) (int, error) {
	if f.write != nil {
		return f.write(b, a)
	}
	return len(b), nil
}
func (f *fakeEcho) SetWriteDeadline(time.Time) error { return nil }
func (f *fakeEcho) SetReadDeadline(t time.Time) error {
	if f.readDeadlineErr != nil {
		return f.readDeadlineErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.timer != nil {
		f.timer.Stop()
	}
	if !t.IsZero() {
		f.timer = time.AfterFunc(time.Until(t), func() {
			select {
			case f.reads <- echoPacket{err: os.ErrDeadlineExceeded}:
			case <-f.closed:
			}
		})
	}
	return nil
}
func (f *fakeEcho) Close() error {
	f.once.Do(func() { close(f.closed) })
	f.mu.Lock()
	if f.timer != nil {
		f.timer.Stop()
	}
	f.mu.Unlock()
	return nil
}
func echoReply(t *testing.T, request []byte, peer net.Addr) []byte {
	t.Helper()
	ip, _ := pingPeer(peer)
	proto := 1
	var reply icmp.Type = ipv4.ICMPTypeEchoReply
	if ip.Is6() {
		proto = 58
		reply = ipv6.ICMPTypeEchoReply
	}
	m, err := icmp.ParseMessage(proto, request)
	if err != nil {
		t.Fatal(err)
	}
	m.Type = reply
	b, err := m.Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestEchoCompletesWhenAllTargetsReply(t *testing.T) {
	for _, raw := range []string{"192.0.2.1", "fe80::1%test0"} {
		t.Run(raw, func(t *testing.T) {
			f := newFakeEcho()
			defer f.Close()
			ip := netip.MustParseAddr(raw)
			f.write = func(b []byte, a net.Addr) (int, error) {
				reply := echoReply(t, b, a)
				f.reads <- echoPacket{data: reply, peer: a}
				return len(b), nil
			}
			start := time.Now()
			hits, attempts := 0, 0
			stats, err := exchangeEcho(context.Background(), f, []netip.Addr{ip}, time.Second, func(h pingHit) {
				hits++
				if h.IP != ip {
					t.Errorf("lost scope: %s", h.IP)
				}
			}, func(netip.Addr) { attempts++ })
			if err != nil || time.Since(start) > 250*time.Millisecond || stats.Responders != 1 || stats.Sent != 1 || hits != 1 || attempts != 1 {
				t.Fatal(stats, hits, attempts, err)
			}
		})
	}
}
func TestEchoIgnoresDuplicateForeignAndMismatchedReplies(t *testing.T) {
	f := newFakeEcho()
	defer f.Close()
	hosts := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	f.write = func(b []byte, a net.Addr) (int, error) {
		ip, _ := pingPeer(a)
		if ip != hosts[0] {
			return len(b), nil
		}
		reply := echoReply(t, b, a)
		wrong := append([]byte{}, reply...)
		wrong[len(wrong)-1] ^= 1
		f.reads <- echoPacket{data: wrong, peer: a}
		f.reads <- echoPacket{data: reply, peer: &net.UDPAddr{IP: net.ParseIP("192.0.2.88")}}
		// The right nonce from a peer that has not been sent this sequence is invalid.
		f.reads <- echoPacket{data: reply, peer: &net.UDPAddr{IP: net.ParseIP("192.0.2.2")}}
		f.reads <- echoPacket{data: reply, peer: a}
		f.reads <- echoPacket{data: reply, peer: a}
		return len(b), nil
	}
	start := time.Now()
	hits := 0
	stats, err := exchangeEcho(context.Background(), f, hosts, 30*time.Millisecond, func(pingHit) { hits++ }, nil)
	if err != nil || stats.Responders != 1 || hits != 1 || stats.Sent != 2 || time.Since(start) < 25*time.Millisecond {
		t.Fatal(stats, hits, err)
	}
}
func TestEchoRetriesOnlyLocalPressureFailures(t *testing.T) {
	for _, failure := range []error{os.ErrDeadlineExceeded, syscall.ENOBUFS, syscall.EAGAIN, syscall.EPERM} {
		f := newFakeEcho()
		calls := 0
		f.write = func(b []byte, a net.Addr) (int, error) {
			calls++
			if calls == 1 {
				return 0, failure
			}
			f.reads <- echoPacket{data: echoReply(t, b, a), peer: a}
			return len(b), nil
		}
		hits := 0
		stats, err := exchangeEcho(context.Background(), f, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, time.Second, func(pingHit) { hits++ }, nil)
		f.Close()
		if errors.Is(failure, syscall.EPERM) {
			if err == nil || calls != 1 || stats.Failed != 1 || stats.Retries != 0 {
				t.Fatal(stats, calls, err)
			}
		} else if err != nil || calls != 2 || stats.Sent != 1 || stats.Retries != 1 || stats.Recovered != 1 || stats.Failed != 0 || hits != 1 {
			t.Fatal(stats, calls, hits, err)
		}
	}
}
func TestEchoRetryBudgetAndCancellation(t *testing.T) {
	f := newFakeEcho()
	defer f.Close()
	f.write = func([]byte, net.Addr) (int, error) { return 0, syscall.ENOBUFS }
	hosts, _ := Hosts(netip.MustParsePrefix("192.0.2.0/24"), 4096)
	start := time.Now()
	stats, err := exchangeEcho(context.Background(), f, hosts, 10*time.Millisecond, func(pingHit) {}, nil)
	if err == nil || !stats.RetryBudgetExhausted || stats.Retries >= len(hosts) || stats.Failed != len(hosts) || time.Since(start) > 250*time.Millisecond {
		t.Fatal(stats, err)
	}
	f = newFakeEcho()
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	f.write = func([]byte, net.Addr) (int, error) { cancel(); return 0, syscall.ENOBUFS }
	start = time.Now()
	stats, err = exchangeEcho(ctx, f, hosts, time.Second, func(pingHit) {}, nil)
	if err != nil || stats.Attempted != 1 || stats.Retries != 0 || time.Since(start) > 250*time.Millisecond {
		t.Fatal(stats, err)
	}
}
func TestEchoReportsReadFailure(t *testing.T) {
	f := newFakeEcho()
	defer f.Close()
	f.write = func(b []byte, _ net.Addr) (int, error) { f.reads <- echoPacket{err: syscall.EIO}; return len(b), nil }
	stats, err := exchangeEcho(context.Background(), f, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, time.Second, func(pingHit) {}, nil)
	if !errors.Is(err, syscall.EIO) || stats.Responders != 0 {
		t.Fatal(stats, err)
	}
}

func TestEchoDeadlineFailureClosesReader(t *testing.T) {
	f := newFakeEcho()
	defer f.Close()
	f.readDeadlineErr = syscall.EINVAL
	start := time.Now()
	stats, err := exchangeEcho(context.Background(), f, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, time.Second, func(pingHit) {}, nil)
	if !errors.Is(err, syscall.EINVAL) || stats.Sent != 1 || stats.Failed != 0 || time.Since(start) > 250*time.Millisecond {
		t.Fatal(stats, err)
	}
}
