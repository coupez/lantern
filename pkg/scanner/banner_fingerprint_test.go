package scanner

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/coupez/lantern/pkg/fingerprints"
)

func TestBannerFingerprintInputBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, service, wire, want string }{
		{"HTTP header", "http", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.65\r\n\r\n", "HTTPD"},
		{"HTTP fallback", "http", "Apache/2.4.65\r\n\r\n", ""},
		{"invalid status", "http", "not HTTP\r\nServer: Apache/2.4.65\r\n\r\n", ""},
		{"indented status", "http", " HTTP/1.1 200 OK\r\nServer: Apache/2.4.65\r\n\r\n", ""},
		{"body", "http", "HTTP/1.1 200 OK\r\n\r\nServer: Apache/2.4.65\r\n", ""},
		{"Unicode field is not Server", "http", "HTTP/1.1 200 OK\r\nſerver: Apache/2.4.65\r\n\r\n", ""},
		{"header EOF", "http", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.65", ""},
		{"cleaning cannot manufacture match", "http", "HTTP/1.1 200 OK\r\nServer: Apa\x1bche/2.4.65\r\n\r\n", ""},
		{"SSH preamble", "ssh", "Notice\r\nSSH-2.0-OpenSSH_9.9\r\n", "OpenSSH"},
		{"SSH old compatible", "ssh", "SSH-1.99-OpenSSH_9.9\n", "OpenSSH"},
		{"SSH diagnostic", "ssh", "OpenSSH_9.9\r\n", ""},
		{"SSH unsupported version", "ssh", "SSH-7.0-OpenSSH_9.9\r\n", ""},
		{"SSH EOF", "ssh", "SSH-2.0-OpenSSH_9.9", ""},
		{"SSH controls", "ssh", "SSH-2.0-Open\x1bSSH_9.9\r\n", ""},
		{"SSH oversized", "ssh", "SSH-2.0-dropbear_" + strings.Repeat("1", 255) + "\r\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observation := observeBannerResponse(iotest.OneByteReader(strings.NewReader(tc.wire)), tc.service)
			match := fingerprints.Lookup(observation.Field, observation.Value)
			if tc.want == "" {
				if match != nil {
					t.Fatal("unexpected match", match)
				}
				return
			}
			if match == nil || match.Fields["service.product"] != tc.want {
				t.Fatal(match, observation)
			}
		})
	}
}
func TestBannerFingerprintOwnershipAndSnapshots(t *testing.T) {
	d := Device{IP: netip.MustParseAddr("192.0.2.1"), Ports: []Port{{Number: 80, Service: "http"}}, Evidence: []string{"tcp"}}
	enrichBannerObservations(context.Background(), &d, time.Second, make(chan struct{}, 4), func(context.Context, netip.Addr, Port, time.Duration) bannerObservation {
		return observeBannerResponse(strings.NewReader("HTTP/1.0 200 OK\r\nServer: Eltex TAU-72\r\n\r\n"), "http")
	})
	if d.Identity != nil || d.Vendor.Name != "" || d.Ports[0].Fingerprint.Fields["hw.product"] != "TAU-72" {
		t.Fatal(d)
	}
	clone := d.Clone()
	clone.Ports[0].Fingerprint.Fields["hw.product"] = "mutated"
	if d.Ports[0].Fingerprint.Fields["hw.product"] != "TAU-72" {
		t.Fatal("shared field map")
	}
	report := Report{Schema: 1, Devices: []Device{d}}
	path := t.TempDir() + "/snapshot.json"
	if err := Save(path, report); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.Devices[0].Ports[0].Fingerprint.Fields["hw.product"] != "TAU-72" {
		t.Fatal(loaded, err)
	}
	legacy := d.Clone()
	legacy.Ports[0].Fingerprint = nil
	if changes := Diff(Report{Devices: []Device{legacy}}, report); len(changes) > 0 {
		t.Fatal("catalog update fabricated observed port change", changes)
	}
}
