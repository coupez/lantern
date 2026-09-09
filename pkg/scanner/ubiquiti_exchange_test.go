package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

func ubReply(version, command, tag byte, value string) []byte {
	body := append([]byte{tag, 0, byte(len(value))}, []byte(value)...)
	b := []byte{version, command, 0, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(len(body)))
	return append(b, body...)
}

type ubRead struct {
	b []byte
	a net.Addr
	e error
}
type fakeUBConn struct {
	mu            sync.Mutex
	reads         chan ubRead
	writes        int
	writeMode     string
	closed        bool
	finalDeadline bool
	recvErr       error
	onFinal       []ubRead
	failAt        int
	shortAt       int
}

func newFakeUB() *fakeUBConn { return &fakeUBConn{reads: make(chan ubRead, 32)} }
func (c *fakeUBConn) ReadFrom(b []byte) (int, net.Addr, error) {
	x := <-c.reads
	if x.e != nil {
		return 0, nil, x.e
	}
	return copy(b, x.b), x.a, nil
}
func (c *fakeUBConn) WriteTo(b []byte, a net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writeMode == "error" || c.writes == c.failAt {
		return 0, errors.New("write failed")
	}
	if c.writeMode == "short" || c.writes == c.shortAt {
		return len(b) - 1, nil
	}
	return len(b), nil
}
func (c *fakeUBConn) SetReadDeadline(time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finalDeadline {
		for _, r := range c.onFinal {
			c.reads <- r
		}
		e := c.recvErr
		if e == nil {
			e = os.ErrDeadlineExceeded
		}
		c.reads <- ubRead{e: e}
	} else {
		c.finalDeadline = true
	}
	return nil
}
func (c *fakeUBConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fakeUBConn) Close() error                     { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func peer(ip string, port int) net.Addr                { return &net.UDPAddr{IP: net.ParseIP(ip), Port: port} }

func TestExchangeUbiquitiFiltersMalformedDuplicatesAndRetainsConflicts(t *testing.T) {
	c := newFakeUB()
	host := netip.MustParseAddr("192.0.2.8")
	c.onFinal = append(c.onFinal, ubRead{ubReply(1, 0, 20, "wrong-ip"), peer("192.0.2.9", 10001), nil}, ubRead{ubReply(1, 0, 20, "wrong-port"), peer(host.String(), 9999), nil}, ubRead{[]byte{1, 0, 0, 4, 20}, peer(host.String(), 10001), nil})
	first := ubReply(1, 0, 20, "Model A")
	second := ubReply(2, 6, 21, "Model B")
	c.onFinal = append(c.onFinal, ubRead{first, peer(host.String(), 10001), nil}, ubRead{first, peer(host.String(), 10001), nil}, ubRead{second, peer(host.String(), 10001), nil})
	got, err := exchangeUbiquiti(context.Background(), c, []netip.Addr{host}, 20*time.Millisecond, 10001)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Probed) != 1 || len(got.Replies) != 2 || got.Replies[0].Observation.Fields[0].Value != "Model A" || got.Replies[1].Observation.Fields[0].Value != "Model B" {
		t.Fatalf("%#v", got)
	}
}

func TestExchangeUbiquitiFailuresPreserveProgress(t *testing.T) {
	host := netip.MustParseAddr("192.0.2.8")
	for _, mode := range []string{"error", "short"} {
		t.Run(mode, func(t *testing.T) {
			c := newFakeUB()
			c.writeMode = mode
			got, err := exchangeUbiquiti(context.Background(), c, []netip.Addr{host}, time.Millisecond, 10001)
			if err == nil || len(got.Probed) != 1 || c.writes != 1 {
				t.Fatalf("%#v %v", got, err)
			}
		})
	}
	c := newFakeUB()
	c.onFinal = []ubRead{{ubReply(1, 0, 20, "partial"), peer(host.String(), 10001), nil}}
	c.recvErr = errors.New("receive failed")
	got, err := exchangeUbiquiti(context.Background(), c, []netip.Addr{host}, time.Millisecond, 10001)
	if err == nil || len(got.Probed) != 1 || c.writes != 2 || len(got.Replies) != 1 {
		t.Fatalf("%#v %v", got, err)
	}
	for _, mode := range []string{"error", "short"} {
		t.Run("later "+mode, func(t *testing.T) {
			c := newFakeUB()
			c.onFinal = []ubRead{{ubReply(1, 0, 20, "partial"), peer(host.String(), 10001), nil}}
			if mode == "error" {
				c.failAt = 3
			} else {
				c.shortAt = 3
			}
			got, err := exchangeUbiquiti(context.Background(), c, []netip.Addr{host, netip.MustParseAddr("192.0.2.9")}, time.Millisecond, 10001)
			if err == nil || len(got.Replies) != 1 || len(got.Probed) != 2 {
				t.Fatalf("%#v %v", got, err)
			}
		})
	}
}

func TestExchangeUbiquitiPreCanceledDoesNotWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := newFakeUB()
	got, err := exchangeUbiquiti(ctx, c, []netip.Addr{netip.MustParseAddr("192.0.2.8")}, time.Millisecond, 10001)
	if !errors.Is(err, context.Canceled) || c.writes != 0 || len(got.Probed) != 0 {
		t.Fatal(got, err, c.writes)
	}
}

func TestExchangeUbiquitiLimitsDistinctRepliesPerIP(t *testing.T) {
	c := newFakeUB()
	host := netip.MustParseAddr("192.0.2.8")
	for i := byte(0); i < 5; i++ {
		c.onFinal = append(c.onFinal, ubRead{ubReply(1, 0, 20, string([]byte{'A' + i})), peer(host.String(), 10001), nil})
	}
	got, err := exchangeUbiquiti(context.Background(), c, []netip.Addr{host}, time.Millisecond, 10001)
	if err == nil || err.Error() != "Ubiquiti response limit exceeded" {
		t.Fatalf("error = %v", err)
	}
	if len(got.Replies) != 4 {
		t.Fatalf("retained replies = %d, want 4", len(got.Replies))
	}
	for i, reply := range got.Replies {
		if got := reply.Observation.Fields[0].Value; got != string([]byte{'A' + byte(i)}) {
			t.Fatalf("reply %d = %q", i, got)
		}
	}
}
