package scanner

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/coupez/lantern/pkg/fingerprints"
)

func TestGreetingResponseBoundaries(t *testing.T) {
	const ftp = "Synology FTP server ready."
	const smtp = "foo.bar ESMTP Postfix (3.1.4)"
	for _, tc := range []struct{ name, service, wire, value string }{
		{"FTP single", "ftp", "220 " + ftp + "\r\n", ftp},
		{"SMTP single", "smtp", "220 " + smtp + "\r\n", smtp},
		{"FTP later line", "ftp", "220-Notice\r\n220 " + ftp + "\r\n", "Notice\r\n" + ftp},
		{"FTP plain intermediate", "ftp", "220-Notice\r\n" + ftp + "\r\n220 Done\r\n", "Notice\r\n" + ftp + "\r\nDone"},
		{"FTP pending", "ftp", "120 Wait\r\n220 " + ftp + "\r\n", ftp},
		{"FTP multiline pending", "ftp", "120-Wait\r\nnotice\r\n120 Ready soon\r\n220 " + ftp + "\r\n", ftp},
		{"SMTP multiline", "smtp", "220-" + smtp + "\r\n220 Ready\r\n", smtp + "\r\nReady"},
		{"SMTP bare end", "smtp", "220-" + smtp + "\r\n220\r\n", smtp + "\r\n"},
		{"FTP case flag", "ftp", "220 SYNOLOGY FTP server ready.\r\n", "SYNOLOGY FTP server ready."},
		{"FTP partial block", "ftp", "220-" + ftp + "\r\n", ""},
		{"FTP partial terminator", "ftp", "220-Notice\r\n220 " + ftp, ""},
		{"FTP EOF", "ftp", "220 " + ftp, ""},
		{"FTP LF", "ftp", "220 " + ftp + "\n", ""},
		{"FTP refusal", "ftp", "421 " + ftp + "\r\n220 " + ftp + "\r\n", ""},
		{"FTP wrong code", "ftp", "220-Notice\r\n221 " + ftp + "\r\n220 Done\r\n", ""},
		{"FTP bad prefix", "ftp", "220x" + ftp + "\r\n", ""},
		{"FTP padded first", "ftp", " 220 " + ftp + "\r\n", ""},
		{"FTP bare end rejected", "ftp", "220-" + ftp + "\r\n220\r\n", ""},
		{"SMTP plain intermediate rejected", "smtp", "220-" + smtp + "\r\ntext\r\n220 Done\r\n", ""},
		{"SMTP wrong code", "smtp", "220-" + smtp + "\r\n250 Done\r\n", ""},
		{"SMTP pending rejected", "smtp", "120 Wait\r\n220 " + smtp + "\r\n", ""},
		{"SMTP overlong line", "smtp", "220 " + smtp + strings.Repeat(" ", 512) + "\r\n", ""},
		{"FTP overlong line", "ftp", "220-Notice\r\n" + strings.Repeat("x", 2048) + "\r\n220 " + ftp + "\r\n", ""},
		{"FTP line budget", "ftp", "220-Notice\r\n" + strings.Repeat("text\r\n", 63) + "220 " + ftp + "\r\n", ""},
		{"FTP last line", "ftp", "220-Notice\r\n" + strings.Repeat("x\r\n", 62) + "220 " + ftp + "\r\n", "Notice\r\n" + strings.Repeat("x\r\n", 62) + ftp},
		{"FTP exact input budget", "ftp", "220-" + strings.Repeat("x", 1020) + "\r\n220 " + strings.Repeat("y", 1026) + "\r\n", strings.Repeat("x", 1020) + "\r\n" + strings.Repeat("y", 1026)},
		{"FTP one byte over input", "ftp", "220-" + strings.Repeat("x", 1020) + "\r\n220 " + strings.Repeat("y", 1027) + "\r\n", ""},
		{"SMTP exact line budget", "smtp", "220 " + strings.Repeat("x", 506) + "\r\n", strings.Repeat("x", 506)},
		{"SMTP one byte over line", "smtp", "220 " + strings.Repeat("x", 507) + "\r\n", ""},
		{"FTP input budget", "ftp", "220-" + strings.Repeat("x", 1020) + "\r\n220 " + strings.Repeat("y", 1030) + "\r\n", ""},
		{"FTP pending byte budget", "ftp", strings.Repeat("120 "+strings.Repeat("x", 1018)+"\r\n", 8) + "220 " + ftp + "\r\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := observeBannerResponse(iotest.OneByteReader(strings.NewReader(tc.wire)), tc.service)
			if got.Value != tc.value || tc.value == "" && got.Field != "" {
				t.Fatalf("%+v, want value %q", got, tc.value)
			}
			if tc.value != "" && got.Field != map[string]string{"ftp": fingerprints.FTPBanner, "smtp": fingerprints.SMTPBanner}[tc.service] {
				t.Fatal(got)
			}
		})
	}
}

func TestGreetingControlAndIdentityIsolation(t *testing.T) {
	wire := "220 ET000400CEA560 Lexmark T640 FTP Server NS.NP.N219 ready.\r\n"
	d := Device{IP: netip.MustParseAddr("192.0.2.1"), Ports: []Port{{Number: 21, Service: "ftp"}}}
	enrichBannerObservations(context.Background(), &d, time.Second, make(chan struct{}, 1), func(context.Context, netip.Addr, Port, time.Duration) bannerObservation {
		return observeBannerResponse(strings.NewReader(wire), "ftp")
	})
	match := d.Ports[0].Fingerprint
	if match == nil || match.Fields["host.mac"] != "000400CEA560" || match.Fields["hw.product"] != "T640" || d.MAC != "" || d.Identity != nil || d.Vendor.Name != "" || d.Kind != "" || len(d.Names) != 0 {
		t.Fatal(d, match)
	}
	clone := d.Clone()
	clone.Ports[0].Fingerprint.Fields["host.mac"] = "changed"
	if match.Fields["host.mac"] != "000400CEA560" {
		t.Fatal("shared catalog map")
	}
	for _, value := range []string{"SYNOLOGY FTP server ready.\x1b", "SYNOLOGY FTP server ready.\u202e", "SYNOLOGY FTP server ready.\rhidden"} {
		observation := observeBannerResponse(strings.NewReader("220 "+value+"\r\n"), "ftp")
		if fingerprints.Lookup(observation.Field, observation.Value) != nil {
			t.Fatal(observation)
		}
	}
}

func TestGreetingCancellationAndNoCommands(t *testing.T) {
	for _, service := range []string{"ftp", "smtp"} {
		t.Run(service, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan bannerObservation, 1)
			go func() {
				done <- readBannerObservationWithDialer(ctx, netip.MustParseAddr("127.0.0.1"), Port{Number: 21, Service: service}, time.Minute, func(context.Context, string, string) (net.Conn, error) { return client, nil })
			}()
			server.SetDeadline(time.Now().Add(time.Second))
			if _, err := io.WriteString(server, "220-Incomplete greeting\r\n"); err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case observation := <-done:
				if observation.Field != "" || observation.Value != "" {
					t.Fatal(observation)
				}
			case <-time.After(time.Second):
				t.Fatal("cancel did not stop greeting read")
			}
			data, err := io.ReadAll(server)
			if len(data) != 0 || err != nil {
				t.Fatal("unexpected client commands or open connection", string(data), err)
			}
		})
	}
}
