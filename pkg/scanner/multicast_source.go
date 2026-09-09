package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// Keep source fallback on the originally selected link. An unavailable address
// is not permission to send discovery on another network.
func multicastSources(target netip.Prefix, preferred string) (*net.Interface, []netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 || (preferred != "" && preferred != iface.Name) {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, nil, err
		}
		sources := []netip.Addr{}
		seen := map[netip.Addr]bool{}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil || prefix.Addr().Is6() != target.Addr().Is6() || !target.Overlaps(prefix) {
				continue
			}
			source := scoped(prefix.Addr(), iface.Name)
			if !seen[source] {
				sources = append(sources, source)
				seen[source] = true
			}
		}
		if len(sources) > 0 {
			return &iface, sources, nil
		}
	}
	return nil, nil, nil
}

type multicastOpener func(context.Context, netip.Addr, *net.Interface, time.Duration) (*net.UDPConn, func(), error)

func openMulticastSocket(ctx context.Context, target netip.Prefix, preferred string, timeout time.Duration) (*net.UDPConn, *net.Interface, netip.Addr, func(), error) {
	deadline := time.Now().Add(timeout)
	iface, sources, err := multicastSources(target, preferred)
	if err != nil || iface == nil {
		return nil, iface, netip.Addr{}, nil, err
	}
	c, source, closeSocket, err := openMulticastSources(ctx, iface, sources, deadline, multicastSocket)
	return c, iface, source, closeSocket, err
}

func openMulticastSources(ctx context.Context, iface *net.Interface, sources []netip.Addr, deadline time.Time, open multicastOpener) (*net.UDPConn, netip.Addr, func(), error) {
	var last error
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, netip.Addr{}, nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, netip.Addr{}, nil, context.DeadlineExceeded
		}
		c, closeSocket, err := open(ctx, source, iface, remaining)
		if err == nil {
			return c, source, closeSocket, nil
		}
		// Tentative, failed-DAD, or just-removed addresses can remain in the OS
		// inventory. Retry another address only when binding rejects that source.
		// Permission, socket configuration, and all other failures remain visible.
		last = err
		var operation *net.OpError
		if !errors.As(err, &operation) || operation.Op != "listen" || !errors.Is(err, syscall.EADDRNOTAVAIL) {
			break
		}
	}
	return nil, netip.Addr{}, nil, last
}
