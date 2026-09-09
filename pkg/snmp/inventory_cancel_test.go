package snmp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestReadUDPInFlightCancellation(t *testing.T) {
	requireSNMPNetwork(t)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	credentials, _ := NewCredentials("synthetic-test-community")
	done := make(chan error, 1)
	go func() {
		_, err := Read(ctx, listener.LocalAddr().(*net.UDPAddr).AddrPort(), credentials, 5*time.Second)
		done <- err
	}()
	listener.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := listener.ReadFromUDP(make([]byte, 2048)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight cancellation did not close the socket promptly")
	}
}
