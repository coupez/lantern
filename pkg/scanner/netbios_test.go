package scanner

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
)

func nbName(name string, suffix byte, flags uint16) NetBIOSName {
	n := NetBIOSName{Flags: flags}
	copy(n.Name[:], strings.Repeat(" ", 15))
	copy(n.Name[:15], name)
	n.Name[15] = suffix
	return n
}
func nbFixture(id uint16, names ...NetBIOSName) []byte {
	// Independently encoded RFC header, wildcard owner, NBSTAT/IN and zero TTL.
	b, _ := hex.DecodeString("00008400000000010000000020434b4141414141414141414141414141414141414141414141414141414141410000210001000000000000")
	binary.BigEndian.PutUint16(b, id)
	data := []byte{byte(len(names))}
	for _, n := range names {
		data = append(data, n.Name[:]...)
		data = append(data, byte(n.Flags>>8), byte(n.Flags))
	}
	stats := make([]byte, 46)
	copy(stats, []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55})
	data = append(data, stats...)
	binary.BigEndian.PutUint16(b[54:], uint16(len(data)))
	return append(b, data...)
}
func TestNetBIOSWireAndIdentity(t *testing.T) {
	q := netbiosQuery(0x1234)
	want := "12340000000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001"
	if hex.EncodeToString(q) != want {
		t.Fatalf("%x", q)
	}
	reply, ok := parseNetBIOSReply(nbFixture(0x1234, nbName("WORKGROUP", 0, 0x8400), nbName("OFFICE-NAS", 0, 0x0400), nbName("OFFICE-NAS", 0x20, 0x0400), nbName("OLD", 0, 0x1c00), nbName("PERSON", 3, 0x0400)), 0x1234)
	if !ok || len(reply.Names) != 5 || reply.UnitID != "00:11:22:33:44:55" {
		t.Fatal(reply, ok)
	}
	reply.IP = netip.MustParseAddr("192.0.2.1")
	hit := netbiosHit(reply)
	if len(hit.Names) != 1 || hit.Names[0] != "OFFICE-NAS" {
		t.Fatal(hit.Names)
	}
	identity := identify(hit.Ads)
	if identity == nil || identity.Name != "OFFICE-NAS" || identity.Manufacturer != "" || identity.Model != "" {
		t.Fatal(identity)
	}
	for _, c := range identity.Claims {
		if !strings.HasPrefix(c.Source, "netbios:") || c.Basis != "advertised" {
			t.Fatal(c)
		}
	}
	if kind := inferKind(Device{Advertisements: hit.Ads}); kind != "computer / NAS" {
		t.Fatal(kind)
	}
	group := netbiosHit(NetBIOSReply{Names: []NetBIOSName{nbName("GROUP", 0, 0x8400)}})
	if len(group.Names) != 0 || identify(group.Ads) != nil {
		t.Fatal("workgroup mistaken for host", group)
	}
}
func TestNetBIOSRejectsMalformed(t *testing.T) {
	good := nbFixture(42, nbName("HOST", 0, 0x0400))
	for n := 0; n < len(good); n++ {
		if _, ok := parseNetBIOSReply(good[:n], 42); ok {
			t.Fatal("accepted truncation", n)
		}
	}
	for _, offset := range []int{0, 2, 3, 4, 6, 8, 10, 12, 13, 45, 46, 48, 50, 54, 56} {
		b := append([]byte(nil), good...)
		b[offset] ^= 1
		if _, ok := parseNetBIOSReply(b, 42); ok {
			t.Fatal("accepted malformed header/count", offset)
		}
	}
	for _, flags := range []uint16{0x8000, 0x8600, 0x8403, 0x8500, 0x0400} {
		b := append([]byte(nil), good...)
		binary.BigEndian.PutUint16(b[2:], flags)
		if _, ok := parseNetBIOSReply(b, 42); ok {
			t.Fatalf("flags %x", flags)
		}
	}
	if _, ok := parseNetBIOSReply(append(good, 0), 42); ok {
		t.Fatal("trailing bytes")
	}
	reply, ok := parseNetBIOSReply(nbFixture(42), 42)
	if !ok || len(reply.Names) != 0 {
		t.Fatal("valid empty name table", ok)
	}
}
func TestNetBIOSNameBytesAreLosslessAndSafe(t *testing.T) {
	n := nbName("A\x1b\x80\\B", 0, 0x0400)
	hit := netbiosHit(NetBIOSReply{Names: []NetBIOSName{n}})
	if hit.Names[0] != "A\\x1b\\x80\\x5cB" || hit.Ads[1].Properties["raw_name_hex"] != hex.EncodeToString(n.Name[:]) {
		t.Fatal(hit)
	}
}
func TestNetBIOSExchangeCorrelatesReplies(t *testing.T) {
	f := newFakeEcho()
	defer f.Close()
	ip := netip.MustParseAddr("192.0.2.1")
	f.write = func(b []byte, peer net.Addr) (int, error) {
		id := binary.BigEndian.Uint16(b)
		good := nbFixture(id, nbName("VALID", 0, 0x0400))
		f.reads <- echoPacket{data: nbFixture(id + 1), peer: peer}
		f.reads <- echoPacket{data: good, peer: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 137}}
		f.reads <- echoPacket{data: good, peer: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 138}}
		f.reads <- echoPacket{data: good, peer: peer}
		f.reads <- echoPacket{data: good, peer: peer}
		return len(b), nil
	}
	start := time.Now()
	r, err := exchangeNetBIOS(context.Background(), f, []netip.Addr{ip, ip}, time.Second, 137)
	if err != nil || len(r.Replies) != 1 || len(r.Probed) != 1 || r.Replies[0].IP != ip || time.Since(start) > 500*time.Millisecond {
		t.Fatal(r, err, time.Since(start))
	}
}
func TestNetBIOSBoundedErrorsAndCancellation(t *testing.T) {
	ips := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	t.Run("silence", func(t *testing.T) {
		f := newFakeEcho()
		defer f.Close()
		start := time.Now()
		r, e := exchangeNetBIOS(context.Background(), f, ips, 30*time.Millisecond, 137)
		if e != nil || len(r.Replies) != 0 || len(r.Probed) != 2 || time.Since(start) < 25*time.Millisecond || time.Since(start) > time.Second {
			t.Fatal(r, e)
		}
	})
	t.Run("write-error", func(t *testing.T) {
		f := newFakeEcho()
		defer f.Close()
		f.write = func([]byte, net.Addr) (int, error) { return 0, syscall.ENOBUFS }
		r, e := exchangeNetBIOS(context.Background(), f, ips, 5*time.Millisecond, 137)
		if e == nil || len(r.Probed) != 1 || !errors.Is(e, syscall.ENOBUFS) {
			t.Fatal(r, e)
		}
	})
	t.Run("deadline-error", func(t *testing.T) {
		f := newFakeEcho()
		defer f.Close()
		f.readDeadlineErr = errors.New("deadline failed")
		_, e := exchangeNetBIOS(context.Background(), f, ips, time.Second, 137)
		if e == nil || !strings.Contains(e.Error(), "deadline failed") {
			t.Fatal(e)
		}
	})
	t.Run("cancel-partial", func(t *testing.T) {
		f := newFakeEcho()
		defer f.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.write = func(b []byte, peer net.Addr) (int, error) {
			if peer.(*net.UDPAddr).IP.String() == ips[0].String() {
				f.reads <- echoPacket{data: nbFixture(binary.BigEndian.Uint16(b)), peer: peer}
			}
			time.AfterFunc(20*time.Millisecond, cancel)
			return len(b), nil
		}
		r, e := exchangeNetBIOS(ctx, f, ips, time.Second, 137)
		if e != nil || len(r.Replies) != 1 || ctx.Err() == nil {
			t.Fatal(r, e)
		}
	})
}
func TestNetBIOSOnlyDiscoveryPreservesLinkMAC(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	o := Defaults()
	o.Target = netip.MustParsePrefix("192.0.2.0/30")
	o.NetBIOS = true
	o.ICMP = false
	o.Multicast = false
	o.Resolve = false
	o.Descriptions = false
	o.Ports = nil
	e := Engine{NeighborSource: func(context.Context) (map[netip.Addr]string, error) {
		return map[netip.Addr]string{ip: "02:11:22:33:44:55"}, nil
	}, NetBIOSSource: func(context.Context, []netip.Addr, time.Duration) (NetBIOSResult, error) {
		return NetBIOSResult{Probed: []netip.Addr{ip}, Replies: []NetBIOSReply{{IP: ip, Names: []NetBIOSName{nbName("OFFICE-NAS", 0x20, 0x0400)}, UnitID: "00:aa:bb:cc:dd:ee"}, {IP: netip.MustParseAddr("198.51.100.1")}}}, nil
	}}
	r, err := e.Scan(context.Background(), o, nil)
	if err != nil || len(r.Devices) != 1 || r.Probed != 1 {
		t.Fatal(r, err)
	}
	d := r.Devices[0]
	if d.MAC != "02:11:22:33:44:55" || len(d.Ports) != 0 || !contains(d.Evidence, "netbios") || d.Identity == nil || d.Identity.Name != "OFFICE-NAS" {
		t.Fatal(d)
	}
	o.Target = netip.MustParsePrefix("::1/128")
	if _, err = e.Scan(context.Background(), o, nil); err == nil {
		t.Fatal("accepted IPv6")
	}
}
func FuzzNetBIOSReply(f *testing.F) {
	f.Add(nbFixture(42, nbName("HOST", 0, 0x0400)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, ok := parseNetBIOSReply(b, 42); ok {
			h := netbiosHit(r)
			if len(h.Ads) > 256 {
				t.Fatal("unbounded records")
			}
			for _, a := range h.Ads {
				if strings.Contains(a.Instance, "\x1b") {
					t.Fatal("control")
				}
			}
		}
	})
}

type netbiosPortDialer struct{}

func (netbiosPortDialer) Probe(_ context.Context, ip netip.Addr, port uint16, _ time.Duration) (bool, bool, time.Duration, error) {
	open := ip.String() == "192.0.2.1" && port == 445
	return open, open, 0, nil
}
func TestNetBIOSResponseSchedulesRequestedPorts(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("192.0.2.0/30")
	o.NetBIOS = true
	o.ICMP = false
	o.Multicast = false
	o.Resolve = false
	o.Descriptions = false
	o.Ports = []uint16{445}
	engine := Engine{Dialer: netbiosPortDialer{}, NeighborSource: noNeighbors, NetBIOSSource: func(context.Context, []netip.Addr, time.Duration) (NetBIOSResult, error) {
		return NetBIOSResult{Replies: []NetBIOSReply{{IP: netip.MustParseAddr("192.0.2.1")}}}, nil
	}}
	r, err := engine.Scan(context.Background(), o, nil)
	if err != nil || len(r.Devices) != 1 || len(r.Devices[0].Ports) != 1 || r.Devices[0].Ports[0].Number != 445 {
		t.Fatal(r, err)
	}
}

func TestNetBIOSPacingAndReadError(t *testing.T) {
	t.Run("paced", func(t *testing.T) {
		f := newFakeEcho()
		defer f.Close()
		var hosts []netip.Addr
		for i := 1; i <= 65; i++ {
			hosts = append(hosts, netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
		}
		var writes []time.Time
		f.write = func(b []byte, _ net.Addr) (int, error) { writes = append(writes, time.Now()); return len(b), nil }
		r, e := exchangeNetBIOS(context.Background(), f, hosts, time.Millisecond, 137)
		if e != nil || len(r.Probed) != 65 {
			t.Fatal(r, e)
		}
		if writes[32].Sub(writes[31]) < 9*time.Millisecond || writes[64].Sub(writes[63]) < 9*time.Millisecond {
			t.Fatal("missing burst pauses")
		}
	})
	t.Run("read-error", func(t *testing.T) {
		f := newFakeEcho()
		defer f.Close()
		fail := errors.New("read failed")
		f.reads <- echoPacket{err: fail}
		_, err := exchangeNetBIOS(context.Background(), f, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, time.Second, 137)
		if !errors.Is(err, fail) {
			t.Fatal(err)
		}
	})
}

func TestNetBIOSNameAndKindPrecedence(t *testing.T) {
	h := netbiosHit(NetBIOSReply{Names: []NetBIOSName{nbName("ALIAS", 0x20, 0x0400), nbName("WORKSTATION", 0, 0x0400), nbName("OLD", 0, 0x1c00)}})
	if identify(h.Ads).Name != "WORKSTATION" {
		t.Fatal("file-server alias displaced workstation")
	}
	if h.Ads[3].Properties["active"] != "true" || h.Ads[3].Properties["conflict"] != "true" {
		t.Fatal("misrepresented registration flags")
	}
	h.Ads = append(h.Ads, Advertisement{Protocol: "mdns", Service: "_googlecast._tcp", Properties: map[string]string{"fn": "Friendly Name"}})
	if identify(h.Ads).Name != "Friendly Name" {
		t.Fatal("NetBIOS displaced friendly name")
	}
	h = netbiosHit(NetBIOSReply{Names: []NetBIOSName{nbName("PRINTER", 0, 0x0400)}})
	if kind := inferKind(Device{Advertisements: h.Ads, Ports: []Port{{Number: 631}}}); kind != "printer" {
		t.Fatal(kind)
	}
}
