package scanner

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestMailNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	certificate := bannerTestCertificate(t)
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, service := range []string{"imap", "pop3", "imaps", "pop3s"} {
			t.Run(host+"/"+service, func(t *testing.T) {
				listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				greeting, prefix, field := "example.com Cyrus IMAP4 v2.3.7 server ready", "* OK ", "imap4.banner"
				if service == "pop3" || service == "pop3s" {
					greeting, prefix, field = "Dovecot ready.", "+OK ", "pop3.banner"
				}
				done := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(time.Second))
					if service == "imaps" || service == "pop3s" {
						conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}})
					}
					if _, err = io.WriteString(conn, prefix+greeting+"\r\n"); err != nil {
						done <- err
						return
					}
					data, err := io.ReadAll(conn)
					if len(data) != 0 {
						t.Errorf("unexpected protocol commands: %q", data)
					}
					done <- err
				}()
				d := Device{IP: netip.MustParseAddr(host), Ports: []Port{{Number: uint16(listener.Addr().(*net.TCPAddr).Port), Service: service}}}
				enrichBannerObservations(context.Background(), &d, time.Second, make(chan struct{}, 1), readBannerObservation)
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				match := d.Ports[0].Fingerprint
				if match == nil || match.Input != greeting || match.Field != field || d.MAC != "" || d.Identity != nil || len(d.Names) != 0 {
					t.Fatal(d, match)
				}
			})
		}
	}
}
