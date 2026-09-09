package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/coupez/lantern/pkg/fingerprints"
)

func TestMailGreetingBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, service, wire, want string }{
		{"imap", "imap", "* OK example.com Cyrus IMAP4 v2.3.7 server ready\r\n", "example.com Cyrus IMAP4 v2.3.7 server ready"},
		{"preauth", "imap", "* PREAUTH hello\r\n", "hello"},
		{"case", "imap", "* oK hello\r\n", "hello"},
		{"capability retained", "imap", "* OK [CAPABILITY IMAP4rev1] hello\r\n", "[CAPABILITY IMAP4rev1] hello"},
		{"pop", "pop3", "+OK Dovecot ready.\r\n", "Dovecot ready."},
		{"bye", "imap", "* BYE hello\r\n* OK hello\r\n", ""},
		{"tagged", "imap", "A001 OK hello\r\n", ""},
		{"refused", "pop3", "-ERR Dovecot ready.\r\n+OK Dovecot ready.\r\n", ""},
		{"pop case", "pop3", "+ok Dovecot ready.\r\n", ""},
		{"prefix", "pop3", "+OKAY Dovecot ready.\r\n", ""},
		{"LF", "imap", "* OK hello\n", ""},
		{"partial", "pop3", "+OK Dovecot ready.", ""},
		{"first only", "pop3", "+OK unknown\r\n+OK Dovecot ready.\r\n", "unknown"},
		{"imap limit", "imap", "* PREAUTH " + strings.Repeat("x", 2048) + "\r\n", strings.Repeat("x", 2048)},
		{"imap oversized", "imap", "* OK " + strings.Repeat("x", 2049) + "\r\n", ""},
		{"pop limit", "pop3", "+OK " + strings.Repeat("x", 506) + "\r\n", strings.Repeat("x", 506)},
		{"pop oversized", "pop3", "+OK " + strings.Repeat("x", 507) + "\r\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, reader := range []io.Reader{strings.NewReader(tc.wire), iotest.OneByteReader(strings.NewReader(tc.wire))} {
				got := observeBannerResponse(reader, tc.service)
				if got.Value != tc.want || (got.Field != "") != (tc.want != "") {
					t.Fatalf("%+v", got)
				}
			}
		})
	}
	for _, service := range []string{"imap", "pop3"} {
		text, prefix := "example.com Cyrus IMAP4 v2.3.7 server ready", "* OK "
		if service == "pop3" {
			text, prefix = "Dovecot ready.", "+OK "
		}
		for _, taint := range []string{"\x00", "\x1b", "\r", "\u202e", "\xff"} {
			got := observeBannerResponse(strings.NewReader(prefix+text+taint+"\r\n"), service)
			if fingerprints.Lookup(got.Field, got.Value) != nil {
				t.Fatal("taint matched", service, taint)
			}
		}
	}
}

func TestMailTLSExchange(t *testing.T) {
	certificate := bannerTestCertificate(t)
	for _, service := range []string{"imaps", "pop3s"} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(fmt.Sprintf("%s/%x", service, version), func(t *testing.T) {
				client, peer := net.Pipe()
				defer peer.Close()
				done := make(chan error, 1)
				text, prefix, field, product := "example.com Cyrus IMAP4 v2.3.7 server ready", "* OK ", fingerprints.IMAPBanner, "Cyrus IMAP"
				if service == "pop3s" {
					text, prefix, field, product = "Dovecot ready.", "+OK ", fingerprints.POP3Banner, "Dovecot"
				}
				go func() {
					defer peer.Close()
					peer.SetDeadline(time.Now().Add(2 * time.Second))
					server := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: version, MaxVersion: version, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
						if hello.ServerName != "" || len(hello.SupportedProtos) != 0 {
							return nil, fmt.Errorf("unexpected SNI/ALPN")
						}
						return nil, nil
					}})
					if err := server.Handshake(); err != nil {
						done <- err
						return
					}
					state := server.ConnectionState()
					if state.ServerName != "" || state.NegotiatedProtocol != "" || len(state.PeerCertificates) != 0 {
						done <- fmt.Errorf("unexpected TLS state")
						return
					}
					if _, err := io.WriteString(server, prefix+text+"\r\n"); err != nil {
						done <- err
						return
					}
					var b [1]byte
					n, _ := server.Read(b[:])
					if n != 0 {
						done <- fmt.Errorf("unexpected application command %x", b[:n])
						return
					}
					done <- nil
				}()
				calls := 0
				got := readBannerObservationWithDialer(context.Background(), netip.MustParseAddr("::1"), Port{Number: 993, Service: service}, time.Second, func(context.Context, string, string) (net.Conn, error) { calls++; return client, nil })
				match := fingerprints.Lookup(got.Field, got.Value)
				if calls != 1 || got.Field != field || got.Value != text || match == nil || match.Fields["service.product"] != product {
					t.Fatalf("%+v %+v calls %d", got, match, calls)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestMailGreetingCancellation(t *testing.T) {
	for _, service := range []string{"imap", "pop3", "imaps", "pop3s"} {
		t.Run(service, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{})
			done := make(chan bannerObservation, 1)
			go func() {
				done <- readBannerObservationWithDialer(ctx, netip.MustParseAddr("127.0.0.1"), Port{Number: 143, Service: service}, time.Minute, func(context.Context, string, string) (net.Conn, error) { close(started); return client, nil })
			}()
			<-started
			cancel()
			select {
			case got := <-done:
				if got.Field != "" {
					t.Fatal(got)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation hung")
			}
		})
	}
}
