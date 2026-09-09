package snmp

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func requireSNMPNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("LANTERN_NETWORK_TESTS") != "1" {
		t.Skip("set LANTERN_NETWORK_TESTS=1 for loopback UDP tests")
	}
}

func inventoryResponse(community string, id int32, bindings []Value) []byte {
	var list []byte
	for _, v := range bindings {
		oid, _ := encOID(v.OID)
		var value []byte
		switch v.Kind {
		case "octets":
			value = tlv(4, v.Bytes)
		case "oid":
			value, _ = encOID(v.Text)
		case "integer":
			value = encInt(v.Integer)
		case "end-of-mib":
			value = []byte{0x82, 0}
		default:
			value = []byte{0x80, 0}
		}
		list = append(list, tlv(0x30, append(oid, value...))...)
	}
	pdu := append(append(encInt(int64(id)), encInt(0)...), append(encInt(0), tlv(0x30, list)...)...)
	return tlv(0x30, append(append(encInt(1), tlv(4, []byte(community))...), tlv(0xa2, pdu)...))
}

func requestIDFromPacket(b []byte) (string, int32, byte, bool) {
	outer, err := only(0x30, b)
	if err != nil {
		return "", 0, 0, false
	}
	r := reader{b: outer}
	_, _, err = r.readTLV()
	if err != nil {
		return "", 0, 0, false
	}
	tag, community, err := r.readTLV()
	if err != nil || tag != 4 {
		return "", 0, 0, false
	}
	pduTag, pdu, err := r.readTLV()
	if err != nil {
		return "", 0, 0, false
	}
	pr := reader{b: pdu}
	tag, v, err := pr.readTLV()
	if err != nil || tag != 2 {
		return "", 0, 0, false
	}
	id, err := decInt(v)
	if err != nil {
		return "", 0, 0, false
	}
	return string(community), int32(id), pduTag, true
}

func requestOIDs(b []byte) (byte, int64, []string, bool) {
	outer, e := only(0x30, b)
	if e != nil {
		return 0, 0, nil, false
	}
	r := reader{b: outer}
	_, _, e = r.readTLV()
	if e != nil {
		return 0, 0, nil, false
	}
	_, _, e = r.readTLV()
	if e != nil {
		return 0, 0, nil, false
	}
	tag, pdu, e := r.readTLV()
	if e != nil {
		return 0, 0, nil, false
	}
	p := reader{b: pdu}
	_, v, e := p.readTLV()
	if e != nil {
		return 0, 0, nil, false
	}
	_, v, e = p.readTLV()
	if e != nil {
		return 0, 0, nil, false
	}
	zero, e := decInt(v)
	if e != nil || zero != 0 {
		return 0, 0, nil, false
	}
	_, v, e = p.readTLV()
	if e != nil {
		return 0, 0, nil, false
	}
	second, e := decInt(v)
	if e != nil {
		return 0, 0, nil, false
	}
	_, list, e := p.readTLV()
	if e != nil {
		return 0, 0, nil, false
	}
	lr := reader{b: list}
	var out []string
	for lr.n < len(lr.b) {
		_, vb, e := lr.readTLV()
		if e != nil {
			return 0, 0, nil, false
		}
		vr := reader{b: vb}
		_, ob, e := vr.readTLV()
		if e != nil {
			return 0, 0, nil, false
		}
		oid, e := decOID(ob)
		if e != nil {
			return 0, 0, nil, false
		}
		out = append(out, oid)
	}
	return tag, second, out, true
}

func TestReadUDPThreeBoundedQueries(t *testing.T) {
	requireSNMPNetwork(t)
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host), Port: 0})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			var calls atomic.Int32
			done := make(chan struct{})
			go func() {
				defer close(done)
				for calls.Load() < 3 {
					b := make([]byte, 65536)
					n, peer, e := ln.ReadFromUDP(b)
					if e != nil {
						return
					}
					community, id, tag, ok := requestIDFromPacket(b[:n])
					if !ok || community != "synthetic-test-community" {
						continue
					}
					step := calls.Add(1)
					shape, repetition, oids, ok := requestOIDs(b[:n])
					want := [][]string{{sysDescrOID, sysObjectOID, sysNameOID}, {classOID}, {parentOID + ".1", mfgOID + ".1", modelOID + ".1"}}
					if !ok || shape != []byte{0xa0, 0xa5, 0xa0}[step-1] || tag != shape || len(oids) != len(want[step-1]) {
						return
					}
					for i := range oids {
						if oids[i] != want[step-1][i] {
							return
						}
					}
					if (step == 2 && repetition != 33) || (step != 2 && repetition != 0) {
						return
					}
					var values []Value
					switch step {
					case 1:
						values = []Value{{OID: sysDescrOID, Kind: "octets", Bytes: []byte("fixture")}, {OID: sysObjectOID, Kind: "oid", Text: "1.3.6.1.4.1.1"}, {OID: sysNameOID, Kind: "octets", Bytes: []byte("router")}}
					case 2:
						if tag != 0xa5 {
							return
						}
						values = []Value{{OID: classOID + ".1", Kind: "integer", Integer: 3}, {OID: "1.3.6.1.2.1.47.1.1.1.1.6.1", Kind: "octets", Bytes: []byte("exit")}}
					case 3:
						values = []Value{{OID: parentOID + ".1", Kind: "integer", Integer: 0}, {OID: mfgOID + ".1", Kind: "octets", Bytes: []byte("Example")}, {OID: modelOID + ".1", Kind: "octets", Bytes: []byte("Router 1")}}
					}
					_, _ = ln.WriteToUDP(inventoryResponse(community, id, values), peer)
				}
			}()
			ap, _ := netip.ParseAddrPort(ln.LocalAddr().String())
			c, _ := NewCredentials("synthetic-test-community")
			report, err := Read(context.Background(), ap, c, time.Second)
			if err != nil || calls.Load() != 3 || report.Model != "Router 1" || report.ModelOID != modelOID+".1" {
				t.Fatal(report, err, calls.Load())
			}
			ln.Close()
			<-done
		})
	}
}

func TestReadUDPCorrelationAndPreCancellation(t *testing.T) {
	requireSNMPNetwork(t)
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var calls atomic.Int32
	go func() {
		b := make([]byte, 65536)
		n, p, e := ln.ReadFromUDP(b)
		if e != nil {
			return
		}
		community, id, _, ok := requestIDFromPacket(b[:n])
		if !ok {
			return
		}
		calls.Add(1)
		_, _ = ln.WriteToUDP(inventoryResponse(community, id+1, []Value{}), p)
	}()
	ap, _ := netip.ParseAddrPort(ln.LocalAddr().String())
	c, _ := NewCredentials("synthetic-test-community")
	report, err := Read(context.Background(), ap, c, 80*time.Millisecond)
	if err == nil || report.EntityStatus != "failed" || calls.Load() != 1 {
		t.Fatal(report, err, calls.Load())
	}
	silent, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer silent.Close()
	sap, _ := netip.ParseAddrPort(silent.LocalAddr().String())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Read(ctx, sap, c, time.Second)
	if err == nil {
		t.Fatal("cancelled read succeeded")
	}
	_ = silent.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	b := make([]byte, 1)
	if _, _, e = silent.ReadFromUDP(b); e == nil {
		t.Fatal("pre-cancelled read sent UDP")
	}
}

func TestReadUDPThirdQueryTimeoutKeepsPartialReport(t *testing.T) {
	requireSNMPNetwork(t)
	ln, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for step := 0; step < 2; step++ {
			b := make([]byte, 65536)
			n, p, e := ln.ReadFromUDP(b)
			if e != nil {
				return
			}
			community, id, _, ok := requestIDFromPacket(b[:n])
			if !ok {
				return
			}
			if step == 0 {
				_, _ = ln.WriteToUDP(inventoryResponse(community, id, []Value{{OID: sysDescrOID, Kind: "octets", Bytes: []byte("fixture")}, {OID: sysObjectOID, Kind: "oid", Text: "1.3.6.1.4.1.1"}, {OID: sysNameOID, Kind: "octets", Bytes: []byte("name")}}), p)
			} else {
				_, _ = ln.WriteToUDP(inventoryResponse(community, id, []Value{{OID: classOID + ".1", Kind: "integer", Integer: 3}, {OID: "1.3.6.1.2.1.47.1.1.1.1.6.1", Kind: "octets", Bytes: []byte("exit")}}), p)
			}
		}
	}()
	ap, _ := netip.ParseAddrPort(ln.LocalAddr().String())
	c, _ := NewCredentials("synthetic-test-community")
	start := time.Now()
	report, err := Read(context.Background(), ap, c, 80*time.Millisecond)
	if err == nil || report.System.Name != "name" || len(report.Entities) != 1 || report.EntityStatus != "failed" || time.Since(start) > time.Second {
		t.Fatal(report, err)
	}
	ln.Close()
	<-done
}
