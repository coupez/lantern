package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

var ndpLocal = netip.MustParseAddr("fd77:123::1")
var ndpRemote = netip.MustParseAddr("fd77:123::abcd:1234")

func testNDPLink() ndpLink {
	return ndpLink{net.Interface{Name: "fixture0", HardwareAddr: arpTestMAC}, []netip.Prefix{
		netip.PrefixFrom(ndpLocal, 64), netip.MustParsePrefix("fe80::1/64"),
	}}
}

func ndpReplyFixture(local, remote netip.Addr) []byte {
	b := ndpRequest(remote, arpTestRemoteMAC, local)
	copy(b[:6], arpTestMAC)
	copy(b[38:54], local.AsSlice())
	b[54], b[58], b[78] = 136, 0x60, 2
	copy(b[62:78], remote.AsSlice())
	fixNDPChecksum(b)
	return b
}

func fixNDPChecksum(b []byte) {
	b[56], b[57] = 0, 0
	binary.BigEndian.PutUint16(b[18:20], uint16(len(b)-54))
	binary.BigEndian.PutUint16(b[56:58], ndpChecksum(b[22:38], b[38:54], b[54:]))
}

func TestNDPWireAndValidation(t *testing.T) {
	request := ndpRequest(ndpLocal, arpTestMAC, ndpRemote)
	if !bytes.Equal(request[:6], []byte{0x33, 0x33, 0xff, 0xcd, 0x12, 0x34}) ||
		netip.AddrFrom16([16]byte(request[38:54])).String() != "ff02::1:ffcd:1234" ||
		request[54] != 135 || request[21] != 255 || request[78] != 1 ||
		!bytes.Equal(request[62:78], ndpRemote.AsSlice()) || ndpChecksum(request[22:38], request[38:54], request[54:]) != 0 {
		t.Fatal(request)
	}
	valid := ndpReplyFixture(ndpLocal, ndpRemote)
	n, destination, ok := parseNDPReply(valid, arpTestMAC)
	if !ok || n.IP != ndpRemote || destination != ndpLocal || n.MAC != arpTestRemoteMAC.String() {
		t.Fatal(n, destination, ok)
	}
	for i := 0; i < len(valid); i++ {
		if _, _, ok := parseNDPReply(valid[:i], arpTestMAC); ok {
			t.Fatal("accepted truncated packet", i)
		}
	}
	for name, mutate := range map[string]func([]byte){
		"wrong destination MAC": func(b []byte) { b[0] ^= 1 },
		"different sender MAC":  func(b []byte) { b[7] ^= 1 },
		"multicast sender MAC":  func(b []byte) { b[6] |= 1 },
		"ARP frame":             func(b []byte) { b[12], b[13] = 8, 6 },
		"wrong version":         func(b []byte) { b[14] = 0x40 },
		"hop limit":             func(b []byte) { b[21] = 254 },
		"unspecified source":    func(b []byte) { clear(b[22:38]) },
		"multicast destination": func(b []byte) { b[38] = 255 },
		"solicitation":          func(b []byte) { b[54] = 135 },
		"code":                  func(b []byte) { b[55] = 1 },
		"unsolicited":           func(b []byte) { b[58] = 0x20 },
		"unspecified target":    func(b []byte) { clear(b[62:78]) },
		"multicast target":      func(b []byte) { b[62] = 255 },
		"zero option length":    func(b []byte) { b[79] = 0 },
		"truncated option":      func(b []byte) { b[79] = 2 },
		"missing target MAC":    func(b []byte) { b[78] = 1 },
		"zero target MAC":       func(b []byte) { clear(b[80:86]) },
		"multicast target MAC":  func(b []byte) { b[80] |= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			b := bytes.Clone(valid)
			mutate(b)
			fixNDPChecksum(b)
			if _, _, ok := parseNDPReply(b, arpTestMAC); ok {
				t.Fatal("accepted invalid packet")
			}
		})
	}
	b := bytes.Clone(valid)
	b[57] ^= 1
	if _, _, ok := parseNDPReply(b, arpTestMAC); ok {
		t.Fatal("accepted bad checksum")
	}
	b = append(bytes.Clone(valid), valid[78:]...)
	fixNDPChecksum(b)
	if _, _, ok := parseNDPReply(b, arpTestMAC); ok {
		t.Fatal("accepted duplicate target option")
	}
	b = append(bytes.Clone(valid), []byte{99, 1, 0, 0, 0, 0, 0, 0}...)
	fixNDPChecksum(b)
	if _, _, ok := parseNDPReply(b, arpTestMAC); !ok {
		t.Fatal("unknown well-formed option rejected")
	}
	// Hop-by-hop and destination extensions preserve the ICMP checksum. A
	// fragment header is forbidden even when it describes an atomic fragment.
	for _, next := range []byte{0, 60, 44, 43, 51} {
		b = append(bytes.Clone(valid[:54]), append([]byte{58, 0, 0, 0, 0, 0, 0, 0}, valid[54:]...)...)
		b[20] = next
		binary.BigEndian.PutUint16(b[18:20], 40)
		_, _, ok := parseNDPReply(b, arpTestMAC)
		if ok != (next == 0 || next == 60) {
			t.Fatal("extension", next, ok)
		}
	}
}

func TestNDPSourceScope(t *testing.T) {
	link := testNDPLink()
	wide := link
	wide.prefixes = []netip.Prefix{netip.MustParsePrefix("2001:db8::1/0")}
	if _, ok := wide.source(netip.IPv6Loopback()); ok {
		t.Fatal("loopback is never an Ethernet target")
	}
	for _, target := range []string{"fd77:123::1", "fe80::1", "fd88::1", "::1", "::", "ff02::1", "192.0.2.1", "fe80::2%other0"} {
		if _, ok := link.source(netip.MustParseAddr(target)); ok {
			t.Fatal("selected out-of-scope/self address", target)
		}
	}
	for target, expected := range map[string]string{"fd77:123::2": ndpLocal.String(), "fe80::2%fixture0": "fe80::1"} {
		source, ok := link.source(netip.MustParseAddr(target))
		if !ok || source.String() != expected {
			t.Fatal(source, ok)
		}
	}
}

func TestNDPExchangeCorrelatesAndCompletesEarly(t *testing.T) {
	f := newFakeARP()
	defer f.Close()
	f.write = func(b []byte) error {
		local, target := netip.AddrFrom16([16]byte(b[22:38])), netip.AddrFrom16([16]byte(b[62:78]))
		f.frames <- ndpReplyFixture(local, netip.MustParseAddr("fd77:123::999"))  // unsolicited target
		f.frames <- ndpReplyFixture(netip.MustParseAddr("fd77:123::999"), target) // foreign destination
		f.frames <- ndpReplyFixture(local, target)
		f.frames <- ndpReplyFixture(local, target)
		return nil
	}
	linkLocal := netip.MustParseAddr("fe80::2%fixture0")
	start := time.Now()
	r, err := exchangeNDP(context.Background(), f, testNDPLink(), []netip.Addr{ndpLocal, ndpRemote, ndpRemote, linkLocal, netip.MustParseAddr("fd88::1")}, 30*time.Second)
	if err != nil || len(r.Probed) != 2 || len(r.Neighbors) != 2 || time.Since(start) > time.Second {
		t.Fatal(r, err)
	}
	for i, ip := range []netip.Addr{ndpRemote, linkLocal} {
		if r.Neighbors[i].IP != ip || r.Neighbors[i].MAC != arpTestRemoteMAC.String() || r.Neighbors[i].RTT <= 0 {
			t.Fatal(r)
		}
	}
}

type failedNDPReader struct {
	*fakeARP
	read bool
}

func (f *failedNDPReader) ReadFrame() ([]byte, error) {
	if f.read {
		return nil, os.ErrClosed
	}
	f.read = true
	return f.fakeARP.ReadFrame()
}

func TestNDPPartialFailureAndCancellation(t *testing.T) {
	f := &failedNDPReader{fakeARP: newFakeARP()}
	defer f.Close()
	f.write = func([]byte) error { f.frames <- ndpReplyFixture(ndpLocal, ndpRemote); return nil }
	r, err := exchangeNDP(context.Background(), f, testNDPLink(), []netip.Addr{ndpRemote, netip.MustParseAddr("fd77:123::9")}, 20*time.Millisecond)
	if !errors.Is(err, os.ErrClosed) || len(r.Neighbors) != 1 {
		t.Fatal(r, err)
	}
	for _, cancelBefore := range []bool{true, false} {
		f := newFakeARP()
		defer f.Close()
		ctx, cancel := context.WithCancel(context.Background())
		if cancelBefore {
			cancel()
		}
		f.write = func([]byte) error { cancel(); return nil }
		start := time.Now()
		r, err := exchangeNDP(ctx, f, testNDPLink(), []netip.Addr{ndpRemote}, 30*time.Second)
		cancel()
		if err != nil || time.Since(start) > time.Second || (cancelBefore && len(r.Probed) != 0) {
			t.Fatal(r, err)
		}
	}
}

type ndpDeadlineFailure struct {
	*fakeARP
	readDeadline bool
}

func (f *ndpDeadlineFailure) SetReadDeadline(t time.Time) error {
	if f.readDeadline {
		return errors.New("read deadline unavailable")
	}
	return f.fakeARP.SetReadDeadline(t)
}

func (f *ndpDeadlineFailure) SetWriteDeadline(time.Time) error {
	if !f.readDeadline {
		return errors.New("write deadline unavailable")
	}
	return nil
}

func TestNDPDeadlineAndInitialWriteFailuresAreBounded(t *testing.T) {
	for _, failRead := range []bool{true, false} {
		f := &ndpDeadlineFailure{fakeARP: newFakeARP(), readDeadline: failRead}
		defer f.Close()
		start := time.Now()
		r, err := exchangeNDP(context.Background(), f, testNDPLink(), []netip.Addr{ndpRemote}, 30*time.Second)
		if err == nil || len(r.Probed) != 1 || time.Since(start) > time.Second {
			t.Fatal(r, err)
		}
	}
	f := newFakeARP()
	defer f.Close()
	sendErr := errors.New("send failed")
	f.write = func([]byte) error { return sendErr }
	start := time.Now()
	r, err := exchangeNDP(context.Background(), f, testNDPLink(), []netip.Addr{ndpRemote}, 30*time.Second)
	if !errors.Is(err, sendErr) || len(r.Probed) != 1 || time.Since(start) > time.Second {
		t.Fatal(r, err)
	}
}

func TestNDPBurstPacingAndCancellation(t *testing.T) {
	f := newFakeARP()
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var writes []time.Time
	f.write = func([]byte) error {
		writes = append(writes, time.Now())
		if len(writes) == 33 {
			cancel()
		}
		return nil
	}
	var hosts []netip.Addr
	for ip := ndpRemote; len(hosts) < 100; ip = ip.Next() {
		hosts = append(hosts, ip)
	}
	r, err := exchangeNDP(ctx, f, testNDPLink(), hosts, 30*time.Second)
	if err != nil || len(r.Probed) != 33 || len(writes) != 33 || writes[32].Sub(writes[31]) < 9*time.Millisecond {
		t.Fatal(r, err, writes)
	}
}

func TestEngineNDPFreshEvidenceAndValidation(t *testing.T) {
	o := Defaults()
	o.Target = netip.PrefixFrom(ndpRemote, 128)
	o.NDP, o.ICMP, o.Multicast, o.Resolve, o.Descriptions = true, false, false, false, false
	o.Ports = nil
	e := Engine{NDPSource: func(context.Context, Options, []netip.Addr) (NDPResult, error) {
		return NDPResult{Neighbors: []Neighbor{{IP: ndpRemote, MAC: arpTestRemoteMAC.String()}, {IP: netip.MustParseAddr("fd99::1"), MAC: arpTestRemoteMAC.String()}}, Probed: []netip.Addr{ndpRemote}}, nil
	}, NeighborSource: func(context.Context) (map[netip.Addr]string, error) {
		return map[netip.Addr]string{ndpRemote: "00:11:22:33:44:55"}, nil
	}}
	r, err := e.Scan(context.Background(), o, nil)
	if err != nil || r.Probed != 1 || len(r.Devices) != 1 || r.Devices[0].MAC != arpTestRemoteMAC.String() || !r.Devices[0].Responsive() || !contains(r.Devices[0].Evidence, "ndp") || !r.Coverage.NDP {
		t.Fatal(r, err)
	}
	o.Target = netip.MustParsePrefix("192.0.2.1/32")
	if _, err := e.Scan(context.Background(), o, nil); err == nil {
		t.Fatal("NDP accepted IPv4")
	}
	before := Report{Target: r.Target, Coverage: &ScanCoverage{}, Devices: []Device{{IP: netip.MustParseAddr("fd99::1")}}}
	for _, change := range Diff(before, r) {
		if change.Type != "scan" {
			t.Fatal("NDP coverage changed presence", change)
		}
	}
}
