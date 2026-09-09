package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

func unavailableMulticastSource() error {
	return &net.OpError{Op: "listen", Net: "udp6", Err: &os.SyscallError{Syscall: "bind", Err: syscall.EADDRNOTAVAIL}}
}

func TestMulticastSourceFallback(t *testing.T) {
	iface := &net.Interface{Name: "selected0"}
	sources := []netip.Addr{netip.MustParseAddr("fe80::1%selected0"), netip.MustParseAddr("fe80::2%selected0")}
	attempts := 0
	closed := false
	var previous time.Duration
	_, source, closeSocket, err := openMulticastSources(context.Background(), iface, sources, time.Now().Add(time.Second), func(ctx context.Context, address netip.Addr, link *net.Interface, remaining time.Duration) (*net.UDPConn, func(), error) {
		if link != iface || address != sources[attempts] {
			t.Fatal("changed scope or candidate order")
		}
		attempts++
		if attempts == 1 {
			previous = remaining
			return nil, nil, unavailableMulticastSource()
		}
		if remaining >= previous || remaining <= 0 {
			t.Fatal("deadline extended", remaining, previous)
		}
		return nil, func() { closed = true }, nil
	})
	if err != nil || attempts != 2 || source != sources[1] || closeSocket == nil || closed {
		t.Fatal(source, err, attempts, closed)
	}
	closeSocket()
	if !closed {
		t.Fatal("successful socket cleanup lost")
	}
}

func TestMulticastSourceFallbackOnlyForBindAddressFailure(t *testing.T) {
	sources := []netip.Addr{netip.MustParseAddr("fe80::1%selected0"), netip.MustParseAddr("fe80::2%selected0")}
	for _, failure := range []error{
		&net.OpError{Op: "listen", Err: syscall.EACCES},
		&net.OpError{Op: "setsockopt", Err: syscall.EADDRNOTAVAIL},
		net.ErrClosed,
	} {
		attempts := 0
		_, source, closeSocket, err := openMulticastSources(context.Background(), &net.Interface{}, sources, time.Now().Add(time.Second), func(context.Context, netip.Addr, *net.Interface, time.Duration) (*net.UDPConn, func(), error) {
			attempts++
			return nil, nil, failure
		})
		if attempts != 1 || source.IsValid() || closeSocket != nil || !errors.Is(err, failure) {
			t.Fatal(attempts, source, err)
		}
	}
	attempts := 0
	_, _, _, err := openMulticastSources(context.Background(), &net.Interface{}, sources, time.Now().Add(time.Second), func(context.Context, netip.Addr, *net.Interface, time.Duration) (*net.UDPConn, func(), error) {
		attempts++
		return nil, nil, unavailableMulticastSource()
	})
	if attempts != 2 || !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatal(attempts, err)
	}
}

func TestMulticastSourceFallbackCancellationAndDeadline(t *testing.T) {
	sources := []netip.Addr{netip.MustParseAddr("fe80::1%selected0"), netip.MustParseAddr("fe80::2%selected0")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	_, _, _, err := openMulticastSources(ctx, &net.Interface{}, sources, time.Now().Add(time.Second), func(context.Context, netip.Addr, *net.Interface, time.Duration) (*net.UDPConn, func(), error) {
		attempts++
		cancel()
		return nil, nil, unavailableMulticastSource()
	})
	if attempts != 1 || !errors.Is(err, context.Canceled) {
		t.Fatal(attempts, err)
	}
	_, _, _, err = openMulticastSources(context.Background(), &net.Interface{}, sources, time.Now().Add(-time.Second), func(context.Context, netip.Addr, *net.Interface, time.Duration) (*net.UDPConn, func(), error) {
		t.Fatal("opened after deadline")
		return nil, nil, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
