package scanner

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestGreetingNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, service := range []string{"ftp", "smtp"} {
			t.Run(host+"/"+service, func(t *testing.T) {
				listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				greeting := "SYNOLOGY FTP server ready."
				if service == "smtp" {
					greeting = "foo.bar ESMTP Postfix (3.1.4)"
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
					if _, err = io.WriteString(conn, "220-Notice\r\n220 "+greeting+"\r\n"); err != nil {
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
				if match == nil || match.Input != "Notice\r\n"+greeting || match.Field != service+".banner" || d.MAC != "" || d.Identity != nil || len(d.Names) != 0 {
					t.Fatal(d, match)
				}
			})
		}
	}
}
