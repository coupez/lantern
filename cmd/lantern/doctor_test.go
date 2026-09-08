package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/coupez/lantern/pkg/scanner"
)

func fixtureDiagnostics() scanner.Diagnostics {
	return scanner.Diagnostics{Schema: 1, OS: "linux", Arch: "arm64", Networks: []scanner.Network{{Interface: "test0", CIDR: "192.0.2.0/24", Address: "192.0.2.1"}}, Checks: []scanner.DiagnosticCheck{{Name: "icmp4", Status: "available", Detail: "socket opened"}, {Name: "arp", Status: "unavailable", Detail: "permission denied\x1b\u202e", Hint: "ARP is optional"}, {Name: "remote_reachability", Status: "not_checked", Detail: "requires a scan"}}}
}

func TestDoctorStructuredAndPlainReports(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		var b bytes.Buffer
		args := []string{"--interface", "test0"}
		if asJSON {
			args = append(args, "--json")
		}
		err := doctorCommand(context.Background(), args, &b, func(_ context.Context, iface string) (scanner.Diagnostics, error) {
			if iface != "test0" {
				t.Fatal(iface)
			}
			return fixtureDiagnostics(), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if asJSON {
			var r struct {
				scanner.Diagnostics
				Version           string `json:"version"`
				VendorAssignments int    `json:"vendor_assignments"`
			}
			if err := json.Unmarshal(b.Bytes(), &r); err != nil || r.Version == "" || r.VendorAssignments == 0 || len(r.Checks) != 3 || r.Checks[1].Status != "unavailable" {
				t.Fatal(b.String(), err)
			}
		} else if !strings.Contains(b.String(), "ARP is optional") || !strings.Contains(b.String(), "not_checked") || strings.ContainsAny(b.String(), "\x1b\u202e") {
			t.Fatal(b.String())
		}
	}
}

func TestDoctorValidatesBeforeChecks(t *testing.T) {
	for _, args := range [][]string{{"192.0.2.1"}, {"--unknown"}, {"--json=maybe"}, {"--interface"}} {
		err := doctorCommand(context.Background(), args, io.Discard, func(context.Context, string) (scanner.Diagnostics, error) {
			t.Fatal("checks ran for invalid flags")
			return scanner.Diagnostics{}, nil
		})
		if err == nil {
			t.Fatal(args)
		}
	}
}

type failedDiagnosticWriter struct{}

func (failedDiagnosticWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestDoctorReturnsWriteErrorsAndRetainsCancelledReport(t *testing.T) {
	for _, args := range [][]string{nil, {"--json"}} {
		err := doctorCommand(context.Background(), args, failedDiagnosticWriter{}, func(context.Context, string) (scanner.Diagnostics, error) { return fixtureDiagnostics(), nil })
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	}
	var b bytes.Buffer
	err := doctorCommand(context.Background(), []string{"--json"}, &b, func(context.Context, string) (scanner.Diagnostics, error) {
		r := fixtureDiagnostics()
		r.Cancelled = true
		return r, context.Canceled
	})
	var r scanner.Diagnostics
	if !errors.Is(err, context.Canceled) || json.Unmarshal(b.Bytes(), &r) != nil || !r.Cancelled {
		t.Fatal(err, b.String())
	}
}
