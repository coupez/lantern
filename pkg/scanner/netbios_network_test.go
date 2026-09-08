package scanner

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestNetBIOSNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 512)
		server.SetReadDeadline(time.Now().Add(time.Second))
		n, peer, e := server.ReadFromUDP(b)
		if e != nil || n != 50 {
			return
		}
		server.WriteToUDP(nbFixture(binary.BigEndian.Uint16(b), nbName("LOOPBACK-NAS", 0, 0x0400), nbName("LAB", 0, 0x8400)), peer)
	}()
	r, err := exchangeNetBIOS(context.Background(), client, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, 300*time.Millisecond, uint16(server.LocalAddr().(*net.UDPAddr).Port))
	<-done
	if err != nil || len(r.Replies) != 1 || netbiosHit(r.Replies[0]).Names[0] != "LOOPBACK-NAS" {
		t.Fatal(r, err)
	}
}
