package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/coupez/lantern/pkg/ubiquiti"
)

// UbiquitiReply binds a parsed device observation to its UDP source address.
// Payload interface addresses and MACs never supply this association.
type UbiquitiReply struct {
	IP          netip.Addr
	Observation ubiquiti.Observation
}

// UbiquitiResult retains valid replies and attempted addresses on partial scans.
type UbiquitiResult struct {
	Replies []UbiquitiReply
	Probed  []netip.Addr
}

func ubiquitiSweep(ctx context.Context, hosts []netip.Addr, timeout time.Duration, preferred string) (UbiquitiResult, error) {
	if err := validateUbiquitiTargets(hosts, timeout); err != nil {
		return UbiquitiResult{}, err
	}
	if len(hosts) == 0 || ctx.Err() != nil {
		return UbiquitiResult{}, ctx.Err()
	}
	local := "0.0.0.0:0"
	if preferred != "" {
		iface, err := net.InterfaceByName(preferred)
		if err != nil {
			return UbiquitiResult{}, err
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return UbiquitiResult{}, err
		}
		var source netip.Addr
		for _, address := range addresses {
			p, err := netip.ParsePrefix(address.String())
			if err == nil && p.Addr().Is4() {
				if !source.IsValid() || p.Contains(hosts[0]) {
					source = p.Addr()
				}
				if p.Contains(hosts[0]) {
					break
				}
			}
		}
		if !source.IsValid() {
			return UbiquitiResult{}, errors.New("selected Ubiquiti interface has no IPv4 source")
		}
		local = netip.AddrPortFrom(source, 0).String()
	}
	c, err := net.ListenPacket("udp4", local)
	if err != nil {
		return UbiquitiResult{}, err
	}
	defer c.Close()
	return exchangeUbiquiti(ctx, c, hosts, timeout, 10001)
}

func validateUbiquitiTargets(hosts []netip.Addr, timeout time.Duration) error {
	if timeout <= 0 || timeout > 30*time.Second || len(hosts) > 4096 {
		return errors.New("Ubiquiti discovery requires at most 4096 targets and timeout in (0,30s]")
	}
	seen := map[netip.Addr]bool{}
	for _, ip := range hosts {
		if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || seen[ip] {
			return errors.New("Ubiquiti discovery requires unique unicast IPv4 targets")
		}
		seen[ip] = true
	}
	return nil
}

// exchangeUbiquiti sends at most two four-byte queries per target. Pacing and
// writes have a separate two-second ceiling; one shared response window follows
// the final send. There is no per-host receive timeout or retry loop.
func exchangeUbiquiti(ctx context.Context, c echoConn, hosts []netip.Addr, timeout time.Duration, port uint16) (UbiquitiResult, error) {
	var result UbiquitiResult
	if err := validateUbiquitiTargets(hosts, timeout); err != nil {
		return result, err
	}
	if len(hosts) == 0 || ctx.Err() != nil {
		return result, ctx.Err()
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	sendDeadline := time.Now().Add(2 * time.Second)
	if err := c.SetReadDeadline(sendDeadline.Add(timeout)); err != nil {
		return result, err
	}
	var mu sync.Mutex
	sent := map[netip.Addr]bool{}
	byIP := map[netip.Addr][]ubiquiti.Observation{}
	done := make(chan struct{})
	var readErr error
	go func() {
		defer close(done)
		buffer := make([]byte, 8193)
		for packets := 0; packets < 8192; packets++ {
			n, peer, err := c.ReadFrom(buffer)
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
			eligible := sent[ip]
			mu.Unlock()
			if !eligible {
				continue
			}
			observation, err := ubiquiti.Parse(buffer[:n])
			if err != nil {
				continue
			}
			duplicate := false
			for _, previous := range byIP[ip] {
				if reflect.DeepEqual(previous, observation) {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			if len(byIP[ip]) >= 4 || len(result.Replies) >= 4096 {
				readErr = errors.New("Ubiquiti response limit exceeded")
				return
			}
			byIP[ip] = append(byIP[ip], observation)
			result.Replies = append(result.Replies, UbiquitiReply{IP: ip, Observation: observation})
		}
		readErr = errors.New("Ubiquiti packet limit exceeded")
	}()
	var sendErr error
send:
	for i, ip := range hosts {
		if i > 0 && i%32 == 0 {
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
		for _, version := range []uint8{1, 2} {
			select {
			case <-ctx.Done():
				break send
			case <-done:
				break send
			default:
			}
			if !time.Now().Before(sendDeadline) {
				sendErr = errors.New("Ubiquiti send budget exhausted")
				break send
			}
			if err := c.SetWriteDeadline(minTime(sendDeadline, time.Now().Add(2*time.Millisecond))); err != nil {
				sendErr = err
				break send
			}
			query, _ := ubiquiti.Query(version)
			if version == 1 {
				result.Probed = append(result.Probed, ip)
			}
			mu.Lock()
			n, err := c.WriteTo(query, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, port)))
			if err == nil && n == len(query) {
				sent[ip] = true
			}
			mu.Unlock()
			if err != nil {
				sendErr = err
				break send
			}
			if n != len(query) {
				sendErr = errors.New("short Ubiquiti UDP write")
				break send
			}
		}
	}
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		sendErr = errors.Join(sendErr, err)
		c.Close()
	}
	<-done
	sort.SliceStable(result.Replies, func(i, j int) bool { return result.Replies[i].IP.Less(result.Replies[j].IP) })
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if errors.Is(readErr, os.ErrDeadlineExceeded) {
		readErr = nil
	}
	if sendErr != nil {
		sendErr = fmt.Errorf("Ubiquiti send stopped after %d/%d targets: %w", len(result.Probed), len(hosts), sendErr)
	}
	return result, errors.Join(sendErr, readErr)
}
