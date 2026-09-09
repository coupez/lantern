package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coupez/lantern/pkg/android"
)

func TestAndroidCommandValidatesBeforeRead(t *testing.T) {
	invalid := [][]string{
		nil,
		{"--transport-id", "0"},
		{"--transport-id", "-1"},
		{"--transport-id", "not-a-number"},
		{"--transport-id", "1", "unexpected"},
		{"--transport-id", "1", "--server", "localhost:5037"},
		{"--transport-id", "1", "--server", "192.0.2.1:5037"},
		{"--transport-id", "1", "--server", "[::ffff:127.0.0.1]:5037"},
		{"--transport-id", "1", "--server", "[::1%en0]:5037"},
		{"--transport-id", "1", "--server", "127.0.0.1:0"},
		{"--transport-id", "1", "--timeout", "0s"},
		{"--transport-id", "1", "--timeout", "31s"},
	}
	for _, args := range invalid {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			read := func(context.Context, netip.AddrPort, uint64, time.Duration) (android.Report, error) {
				t.Fatal("called read with invalid arguments")
				return android.Report{}, nil
			}
			if err := androidCommand(context.Background(), args, &bytes.Buffer{}, read); err == nil {
				t.Fatal("accepted invalid arguments")
			}
		})
	}
}

func TestAndroidCommandPreservesExplicitSelection(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "caller-context")
	read := func(got context.Context, server netip.AddrPort, transportID uint64, timeout time.Duration) (android.Report, error) {
		if got != ctx {
			t.Fatal("did not preserve caller context")
		}
		if server.String() != "[::1]:5038" || transportID != 18446744073709551615 || timeout != 7*time.Second {
			t.Fatalf("server=%s transport=%d timeout=%s", server, transportID, timeout)
		}
		return android.Report{Schema: 1, Source: "adb", Server: server.String(), TransportID: transportID, Complete: true}, nil
	}
	var out bytes.Buffer
	if err := androidCommand(ctx, []string{"--transport-id", "18446744073709551615", "--server", "[::1]:5038", "--timeout", "7s", "--json"}, &out, read); err != nil {
		t.Fatal(err)
	}
	var got android.Report
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Server != "[::1]:5038" || got.TransportID != 18446744073709551615 || !got.Complete {
		t.Fatalf("%+v", got)
	}
}

func TestAndroidCommandWritesPartialReportAndReturnsReadError(t *testing.T) {
	readFailure := errors.New("authorized transport became unavailable")
	report := android.Report{
		Schema: 1, Source: "adb", Server: "127.0.0.1:5037", TransportID: 9,
		Properties:  android.Properties{Manufacturer: "Acme", Model: "Reported M", Device: "board-m", BuildFingerprint: "raw/fingerprint"},
		Unavailable: []string{"ro.product.model"},
	}
	read := func(context.Context, netip.AddrPort, uint64, time.Duration) (android.Report, error) {
		return report, readFailure
	}
	for _, jsonMode := range []bool{false, true} {
		args := []string{"--transport-id", "9"}
		if jsonMode {
			args = append(args, "--json")
		}
		var out bytes.Buffer
		if err := androidCommand(context.Background(), args, &out, read); !errors.Is(err, readFailure) {
			t.Fatal(err)
		}
		if jsonMode {
			var got map[string]any
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["schema"] != float64(1) || got["transport_id"] != float64(9) || got["error"] != readFailure.Error() {
				t.Fatalf("%v", got)
			}
		} else {
			for _, want := range []string{"Reported model", "Device codename", "Build fingerprint", "Unavailable"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %q from %q", want, out.String())
				}
			}
		}
	}
	if err := androidCommand(context.Background(), []string{"--transport-id", "9", "--json"}, evaluationFailWriter{}, read); err == nil || !strings.Contains(err.Error(), "sink closed") {
		t.Fatal(err)
	}
}

func TestPrintAndroidCleansControlsAndShowsClaimSources(t *testing.T) {
	report := android.Report{
		Source: "adb\x1b[2J", Server: "127.0.0.1:5037\n",
		Properties:  android.Properties{Manufacturer: "\t", Model: "M\x1b[2J", Device: "device", BuildFingerprint: ""},
		Claims:      []android.Claim{{Field: "model", Value: "M\x1b[2J", Key: "ro.product.model", Reference: "https://source.example/\x1b"}},
		Unavailable: []string{"ro.build.fingerprint\r"},
	}
	var out bytes.Buffer
	if err := printAndroid(&out, report); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if strings.ContainsAny(text, "\x1b\r\t") {
		t.Fatalf("unsafe terminal output: %q", text)
	}
	for _, want := range []string{"Manufacturer      unknown", "Complete", "Reported model", "Source", "ro.product.model", "Unavailable"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q from %q", want, text)
		}
	}
	if err := printAndroid(evaluationFailWriter{}, report); err == nil || !strings.Contains(err.Error(), "sink closed") {
		t.Fatal(err)
	}
}
