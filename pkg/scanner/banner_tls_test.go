package scanner

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coupez/lantern/pkg/fingerprints"
)

// Deliberately expired, self-signed, and unrelated to the numeric scan target.
func bannerTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture.invalid"}, DNSNames: []string{"fixture.invalid"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(86400, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestHTTPSBannerExchange(t *testing.T) {
	certificate := bannerTestCertificate(t)
	for _, tc := range []struct {
		name, response, wantText, wantProduct string
		version                               uint16
	}{
		{"TLS 1.2", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.65\r\n\r\n", "Apache/2.4.65", "HTTPD", tls.VersionTLS12},
		{"TLS 1.3", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.65\r\n\r\n", "Apache/2.4.65", "HTTPD", tls.VersionTLS13},
		{"controls", "HTTP/1.1 200 OK\r\nServer: Apa\x1bche/2.4.65\r\n\r\n", "Apache/2.4.65", "", tls.VersionTLS13},
		{"body excluded", "HTTP/1.1 200 OK\r\n\r\nServer: Apache/2.4.65\r\n", "HTTP/1.1 200 OK", "", tls.VersionTLS13},
		{"redirect not followed", "HTTP/1.1 302 Found\r\nLocation: https://other.invalid/\r\nServer: Apache/2.4.65\r\n\r\n", "Apache/2.4.65", "HTTPD", tls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			conn := &observedBannerConn{Conn: client}
			done := make(chan error, 1)
			go func() {
				defer peer.Close()
				peer.SetDeadline(time.Now().Add(2 * time.Second))
				server := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tc.version, MaxVersion: tc.version, NextProtos: []string{"h2", "http/1.1"}})
				if err := server.Handshake(); err != nil {
					done <- err
					return
				}
				state := server.ConnectionState()
				if state.ServerName != "" || state.NegotiatedProtocol != "http/1.1" || len(state.PeerCertificates) != 0 {
					done <- fmt.Errorf("unexpected TLS state: %+v", state)
					return
				}
				reader := bufio.NewReader(server)
				var request strings.Builder
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						done <- err
						return
					}
					request.WriteString(line)
					if line == "\r\n" {
						break
					}
				}
				if request.String() != "HEAD / HTTP/1.0\r\nHost: [fe80::1]:8443\r\nConnection: close\r\n\r\n" {
					done <- fmt.Errorf("request: %q", request.String())
					return
				}
				_, err := io.WriteString(server, tc.response)
				done <- err
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			observation := readBannerObservationWithDialer(ctx, netip.MustParseAddr("fe80::1%fixture"), Port{Number: 8443, Service: "https"}, time.Minute, func(dialCtx context.Context, network, address string) (net.Conn, error) {
				calls++
				if network != "tcp" || address != "[fe80::1%fixture]:8443" {
					t.Fatalf("dial %s %s", network, address)
				}
				return conn, nil
			})
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			deadline, _ := ctx.Deadline()
			if calls != 1 || !conn.deadline.Equal(deadline) || observation.Text != tc.wantText {
				t.Fatal(calls, conn.deadline, observation)
			}
			match := fingerprints.Lookup(observation.Field, observation.Value)
			if tc.wantProduct == "" {
				if match != nil {
					t.Fatal(match)
				}
			} else if match == nil || match.Fields["service.product"] != tc.wantProduct {
				t.Fatal(match)
			}
		})
	}
}

func TestHTTPSBannerHandshakeCancellation(t *testing.T) {
	for _, cancelNow := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelNow), func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan bannerObservation, 1)
			go func() {
				done <- readBannerObservationWithDialer(ctx, netip.MustParseAddr("127.0.0.1"), Port{Number: 443, Service: "https"}, 100*time.Millisecond, func(context.Context, string, string) (net.Conn, error) { return client, nil })
			}()
			peer.SetReadDeadline(time.Now().Add(time.Second))
			// A ClientHello proves the handshake is live; leave it unanswered.
			header := make([]byte, 5)
			if _, err := io.ReadFull(peer, header); err != nil {
				t.Fatal(err)
			}
			if header[0] != 22 {
				t.Fatal("not a TLS handshake", header)
			}
			if _, err := io.CopyN(io.Discard, peer, int64(header[3])<<8|int64(header[4])); err != nil {
				t.Fatal(err)
			}
			if cancelNow {
				cancel()
			}
			select {
			case observation := <-done:
				if observation != (bannerObservation{}) {
					t.Fatal(observation)
				}
			case <-time.After(time.Second):
				t.Fatal("handshake ignored cancellation/deadline")
			}
		})
	}
}

func TestHTTPSBannerFailedHandshakeDoesNotRetry(t *testing.T) {
	certificate := bannerTestCertificate(t)
	for _, mode := range []string{"plaintext", "http2 only", "client certificate required", "TLS wire budget"} {
		t.Run(mode, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			counted := &countedBannerConn{Conn: client}
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer peer.Close()
				peer.SetDeadline(time.Now().Add(time.Second))
				if mode == "plaintext" {
					// Drain the ClientHello so a plaintext reply can arrive on net.Pipe.
					header := make([]byte, 5)
					if _, err := io.ReadFull(peer, header); err != nil {
						return
					}
					io.CopyN(io.Discard, peer, int64(header[3])<<8|int64(header[4]))
					io.WriteString(peer, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.65\r\n\r\n")
					return
				}
				config := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
				switch mode {
				case "http2 only":
					config.NextProtos = []string{"h2"}
					// Go's default server allows an HTTP/1.1 fallback for h2.
					// Require h2 explicitly to model a genuinely h2-only peer.
					config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
						for _, protocol := range hello.SupportedProtos {
							if protocol == "h2" {
								return nil, nil
							}
						}
						return nil, errors.New("fixture requires h2")
					}
				case "client certificate required":
					config.ClientAuth = tls.RequireAnyClientCert
				case "TLS wire budget":
					config.MaxVersion = tls.VersionTLS12
					chain := certificate
					chain.Certificate = nil
					chain.OCSPStaple = make([]byte, 1024)
					// The certificate message itself stays below Go's 256 KiB limit;
					// A separate OCSP response and record overhead exceed our total wire budget.
					for size := 7; size+len(certificate.Certificate[0])+3 < 256*1024-64; size += len(certificate.Certificate[0]) + 3 {
						chain.Certificate = append(chain.Certificate, certificate.Certificate[0])
					}
					config.Certificates = []tls.Certificate{chain}
				}
				server := tls.Server(peer, config)
				if err := server.Handshake(); err == nil {
					t.Error("unexpected successful handshake", mode)
					// A valid HTTPS response would expose an unintended accepted handshake.
					reader := bufio.NewReader(server)
					for {
						line, err := reader.ReadString('\n')
						if err != nil {
							return
						}
						if line == "\r\n" {
							break
						}
					}
					io.WriteString(server, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.65\r\n\r\n")
				}
			}()
			calls := 0
			observation := readBannerObservationWithDialer(context.Background(), netip.MustParseAddr("127.0.0.1"), Port{Number: 443, Service: "https"}, time.Second, func(context.Context, string, string) (net.Conn, error) { calls++; return counted, nil })
			<-done
			if mode == "TLS wire budget" && counted.received != 256*1024 {
				t.Fatalf("wire budget not exercised: %d bytes", counted.received)
			}
			if calls != 1 || observation != (bannerObservation{}) {
				t.Fatal(calls, observation)
			}
		})
	}
}

// Read accounting is inspected after the exchange returns; no concurrent reader.
type countedBannerConn struct {
	net.Conn
	received int
}

func (c *countedBannerConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.received += n
	return n, err
}

func TestHTTPSBannerResponseCancellation(t *testing.T) {
	certificate := bannerTestCertificate(t)
	client, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requestRead := make(chan error, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer peer.Close()
		peer.SetDeadline(time.Now().Add(2 * time.Second))
		server := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		reader := bufio.NewReader(server)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				requestRead <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		requestRead <- nil
		// Keep the response pending until cancellation closes the transport.
		io.Copy(io.Discard, server)
	}()
	done := make(chan bannerObservation, 1)
	go func() {
		done <- readBannerObservationWithDialer(ctx, netip.MustParseAddr("127.0.0.1"), Port{Number: 443, Service: "https"}, time.Minute, func(context.Context, string, string) (net.Conn, error) { return client, nil })
	}()
	if err := <-requestRead; err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case observation := <-done:
		if observation != (bannerObservation{}) {
			t.Fatal(observation)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not stop the encrypted response read")
	}
	<-serverDone
}
