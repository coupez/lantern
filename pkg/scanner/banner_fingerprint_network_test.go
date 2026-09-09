package scanner

import (
	"context"
	"fmt"
	"github.com/coupez/lantern/pkg/fingerprints"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestBannerFingerprintSSHNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				_, err = fmt.Fprint(conn, "Owned test service\r\nSSH-2.0-OpenSSH_9.9\r\n")
				done <- err
			}()
			observation := readBannerObservation(context.Background(), netip.MustParseAddr(host), Port{Number: uint16(listener.Addr().(*net.TCPAddr).Port), Service: "ssh"}, time.Second)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			match := fingerprints.Lookup(observation.Field, observation.Value)
			if observation.Text != "SSH-2.0-OpenSSH_9.9" || match == nil || match.Fields["service.version"] != "9.9" || match.Fields["service.product"] != "OpenSSH" {
				t.Fatal(observation, match)
			}
		})
	}
}
