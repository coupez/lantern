package scanner

import (
	"bytes"
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

var arpTestLocal = netip.MustParseAddr("192.0.2.1")
var arpTestMAC = net.HardwareAddr{2, 1, 2, 3, 4, 5}
var arpTestRemoteMAC = net.HardwareAddr{2, 6, 7, 8, 9, 10}

func arpReplyFixture(ip netip.Addr) []byte {
	b := arpRequest(ip, arpTestRemoteMAC, arpTestLocal)
	copy(b[:6], arpTestMAC)
	binary.BigEndian.PutUint16(b[20:22], 2)
	copy(b[32:38], arpTestMAC)
	return b
}
func TestARPWireFormat(t *testing.T) {
	remote := netip.MustParseAddr("192.0.2.9")
	request := arpRequest(arpTestLocal, arpTestMAC, remote)
	if len(request) != 60 || !bytes.Equal(request[:6], bytes.Repeat([]byte{255}, 6)) || !bytes.Equal(request[28:32], []byte{192, 0, 2, 1}) || !bytes.Equal(request[38:42], []byte{192, 0, 2, 9}) || binary.BigEndian.Uint16(request[20:22]) != 1 {
		t.Fatal(request)
	}
	reply := arpReplyFixture(remote)
	n, ok := parseARPReply(reply, arpTestLocal, arpTestMAC)
	if !ok || n.IP != remote || n.MAC != arpTestRemoteMAC.String() {
		t.Fatal(n, ok)
	}
	for _, offset := range []int{0, 6, 12, 14, 16, 18, 19, 20, 22, 32, 38} {
		b := append([]byte{}, reply...)
		b[offset] ^= 1
		if _, ok := parseARPReply(b, arpTestLocal, arpTestMAC); ok {
			t.Fatal("accepted malformed/foreign frame at offset", offset)
		}
	}
	for i := 0; i < 42; i++ {
		if _, ok := parseARPReply(reply[:i], arpTestLocal, arpTestMAC); ok {
			t.Fatal("accepted truncation", i)
		}
	}
	for _, ip := range []string{"0.0.0.0", "224.0.0.1", "255.255.255.255", "192.0.2.1"} {
		if _, ok := parseARPReply(arpReplyFixture(netip.MustParseAddr(ip)), arpTestLocal, arpTestMAC); ok {
			t.Fatal("accepted sender", ip)
		}
	}
}

type fakeARP struct {
	frames  chan []byte
	expired chan struct{}
	closed  chan struct{}
	once    sync.Once
	write   func([]byte) error
}

func newFakeARP() *fakeARP {
	return &fakeARP{frames: make(chan []byte, 32), expired: make(chan struct{}, 1), closed: make(chan struct{})}
}
func (f *fakeARP) ReadFrame() ([]byte, error) {
	select {
	case b := <-f.frames:
		return b, nil
	case <-f.expired:
		return nil, os.ErrDeadlineExceeded
	case <-f.closed:
		return nil, os.ErrClosed
	}
}
func (f *fakeARP) WriteFrame(b []byte) error {
	if f.write != nil {
		return f.write(b)
	}
	return nil
}
func (f *fakeARP) SetReadDeadline(t time.Time) error {
	time.AfterFunc(time.Until(t), func() {
		select {
		case f.expired <- struct{}{}:
		default:
		}
	})
	return nil
}
func (f *fakeARP) SetWriteDeadline(time.Time) error { return nil }
func (f *fakeARP) Close() error                     { f.once.Do(func() { close(f.closed) }); return nil }
func testARPLink() arpLink {
	return arpLink{iface: net.Interface{HardwareAddr: arpTestMAC}, address: arpTestLocal, prefix: netip.MustParsePrefix("192.0.2.0/24")}
}
func TestARPExchangeCorrelatesAndBounds(t *testing.T) {
	f := newFakeARP()
	defer f.Close()
	f.write = func(b []byte) error {
		ip := netip.AddrFrom4([4]byte(b[38:42]))
		f.frames <- arpReplyFixture(netip.MustParseAddr("192.0.2.88")) // unsolicited
		f.frames <- arpReplyFixture(ip)
		f.frames <- arpReplyFixture(ip) // duplicate
		return nil
	}
	hosts := []netip.Addr{arpTestLocal, netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("::1")}
	r, err := exchangeARP(context.Background(), f, testARPLink(), hosts, 20*time.Millisecond)
	if err != nil || len(r.Probed) != 1 || len(r.Neighbors) != 1 || r.Neighbors[0].IP != hosts[1] || r.Neighbors[0].RTT <= 0 {
		t.Fatal(r, err)
	}
}
func TestARPCancellationAndWriteError(t *testing.T) {
	for _, cancelled := range []bool{true, false} {
		f := newFakeARP()
		defer f.Close()
		ctx, cancel := context.WithCancel(context.Background())
		f.write = func([]byte) error {
			if cancelled {
				cancel()
				return nil
			}
			return errors.New("fixture send failure")
		}
		start := time.Now()
		r, err := exchangeARP(ctx, f, testARPLink(), []netip.Addr{netip.MustParseAddr("192.0.2.9")}, 20*time.Millisecond)
		cancel()
		if len(r.Probed) != 1 || time.Since(start) > time.Second || (cancelled && err != nil) || (!cancelled && err == nil) {
			t.Fatal(r, err)
		}
	}
}
func TestEngineARPIsLiveAndPreservesFreshMAC(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("192.0.2.9/32")
	o.ARP = true
	o.ICMP = false
	o.Multicast = false
	o.Resolve = false
	o.Ports = nil
	r, err := (Engine{ARPSource: func(context.Context, Options, []netip.Addr) (ARPResult, error) {
		return ARPResult{Neighbors: []Neighbor{{IP: o.Target.Addr(), MAC: arpTestRemoteMAC.String(), RTT: time.Millisecond}, {IP: netip.MustParseAddr("198.51.100.9"), MAC: arpTestRemoteMAC.String()}}, Probed: []netip.Addr{o.Target.Addr()}}, nil
	}, NeighborSource: func(context.Context) (map[netip.Addr]string, error) {
		return map[netip.Addr]string{o.Target.Addr(): "00:11:22:33:44:55"}, nil
	}}).Scan(context.Background(), o, nil)
	if err != nil || r.Probed != 1 || len(r.Devices) != 1 || r.Devices[0].MAC != arpTestRemoteMAC.String() || !contains(r.Devices[0].Evidence, "arp") || len(r.Devices[0].Ports) != 0 {
		t.Fatal(r, err)
	}
	o.Target = netip.MustParsePrefix("::1/128")
	if _, err := (Engine{}).Scan(context.Background(), o, nil); err == nil {
		t.Fatal("ARP IPv6 accepted")
	}
}
func FuzzARPReply(f *testing.F) {
	f.Add(arpReplyFixture(netip.MustParseAddr("192.0.2.9")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { parseARPReply(b, arpTestLocal, arpTestMAC) })
}
func TestARPNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	target, iface := os.Getenv("LANTERN_ARP_TARGET"), os.Getenv("LANTERN_ARP_INTERFACE")
	if target == "" || iface == "" {
		t.Skip("set LANTERN_ARP_TARGET and LANTERN_ARP_INTERFACE for a known local responder")
	}
	o := Defaults()
	var err error
	o.Target, err = ParseTarget(target)
	if err != nil || !o.Target.Addr().Is4() || o.Target.Bits() != 32 {
		t.Fatal("ARP test needs one IPv4 peer", err)
	}
	o.Interface = iface
	o.ARP = true
	o.Timeout = time.Second
	o.ICMP = false
	o.Multicast = false
	o.Resolve = false
	o.Ports = nil
	r, err := (Engine{NeighborSource: noNeighbors}).Scan(context.Background(), o, nil)
	if err != nil || len(r.Warnings) != 0 || len(r.Devices) != 1 || r.Probed != 1 || r.Devices[0].IP != o.Target.Addr() || !contains(r.Devices[0].Evidence, "arp") || r.Devices[0].MAC == "" {
		t.Fatal(r, err)
	}
}
