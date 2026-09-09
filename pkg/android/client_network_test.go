package android

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func requireAndroidNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("LANTERN_NETWORK_TESTS") != "1" {
		t.Skip("set LANTERN_NETWORK_TESTS=1")
	}
}

func readSmartRequest(r *bufio.Reader) (string, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return "", err
	}
	n, err := strconv.ParseUint(string(h[:]), 16, 16)
	if err != nil {
		return "", err
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

func listenADB(t *testing.T, network, address string, serve func(net.Conn) error) (netip.AddrPort, <-chan error) {
	t.Helper()
	ln, err := net.Listen(network, address)
	if err != nil {
		t.Fatalf("listen %s: %v", network, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		defer ln.Close()
		c, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		done <- serve(c)
	}()
	a, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return a, done
}

func successfulADB(c net.Conn) error {
	r := bufio.NewReader(c)
	first, err := readSmartRequest(r)
	if err != nil {
		return err
	}
	if first != "host:transport-id:42" {
		return fmt.Errorf("first request %q", first)
	}
	if _, err = c.Write([]byte("OKAY")); err != nil {
		return err
	}
	second, err := readSmartRequest(r)
	if err != nil {
		return err
	}
	want := "shell,v2,raw:/system/bin/getprop ro.product.manufacturer && /system/bin/getprop ro.product.model && /system/bin/getprop ro.product.device && /system/bin/getprop ro.build.fingerprint"
	if second != want {
		return fmt.Errorf("second request %q", second)
	}
	if _, err = c.Write([]byte("OKAY")); err != nil {
		return err
	}
	// Literal independent shell-v2 wire: stdout split across two frames,
	// followed by the required one-byte successful exit packet.
	wire := append(shellFrame(1, []byte("Google\nPixel 8 Pro\n")), shellFrame(1, []byte("husky\ngoogle/husky:14/release\n"))...)
	wire = append(wire, []byte{3, 1, 0, 0, 0, 0}...)
	_, err = c.Write(wire)
	return err
}

func TestReadExistingADBServerIPv4AndIPv6(t *testing.T) {
	requireAndroidNetwork(t)
	for _, tc := range []struct{ network, address string }{{"tcp4", "127.0.0.1:0"}, {"tcp6", "[::1]:0"}} {
		t.Run(tc.network, func(t *testing.T) {
			server, done := listenADB(t, tc.network, tc.address, successfulADB)
			got, err := Read(context.Background(), server, 42, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Complete || got.Properties.Model != "Pixel 8 Pro" || len(got.Claims) != 4 || got.Server != server.String() || got.TransportID != 42 {
				t.Fatalf("%#v", got)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadADBFailuresDoNotExposeServerText(t *testing.T) {
	requireAndroidNetwork(t)
	secret := "device-serial-SECRET"
	for _, phase := range []string{"transport", "shell"} {
		t.Run(phase, func(t *testing.T) {
			server, done := listenADB(t, "tcp4", "127.0.0.1:0", func(c net.Conn) error {
				r := bufio.NewReader(c)
				if _, e := readSmartRequest(r); e != nil {
					return e
				}
				if phase == "shell" {
					if _, e := c.Write([]byte("OKAY")); e != nil {
						return e
					}
					if _, e := readSmartRequest(r); e != nil {
						return e
					}
				}
				_, e := fmt.Fprintf(c, "FAIL%04x%s", len(secret), secret)
				return e
			})
			got, err := Read(context.Background(), server, 42, time.Second)
			if err == nil || strings.Contains(err.Error(), secret) || got.Complete || len(got.Claims) != 0 {
				t.Fatalf("%#v, %v", got, err)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestReadADBPreCanceledAndInflightCancellation(t *testing.T) {
	requireAndroidNetwork(t)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Read(ctx, listener.Addr().(*net.TCPAddr).AddrPort(), 1, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	listener.SetDeadline(time.Now().Add(80 * time.Millisecond))
	if c, err := listener.Accept(); err == nil {
		c.Close()
		t.Fatal("pre-cancelled read connected to server")
	} else if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	server, done := listenADB(t, "tcp4", "127.0.0.1:0", func(c net.Conn) error {
		r := bufio.NewReader(c)
		if _, e := readSmartRequest(r); e != nil {
			return e
		}
		if _, e := c.Write([]byte("OKAY")); e != nil {
			return e
		}
		if _, e := readSmartRequest(r); e != nil {
			return e
		}
		close(entered)
		_, e := io.Copy(io.Discard, c)
		return e
	})
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := Read(ctx, server, 42, time.Second); result <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("server did not receive property request")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancellation did not return promptly")
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestReadADBDeadline(t *testing.T) {
	requireAndroidNetwork(t)
	server, done := listenADB(t, "tcp4", "127.0.0.1:0", func(c net.Conn) error {
		_, e := io.Copy(io.Discard, c)
		return e
	})
	start := time.Now()
	_, err := Read(context.Background(), server, 42, 40*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 500*time.Millisecond {
		t.Fatal(err)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
