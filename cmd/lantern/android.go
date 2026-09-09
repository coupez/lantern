package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/coupez/lantern/pkg/android"
	"github.com/coupez/lantern/pkg/scanner"
)

// androidCommand collects the four explicitly requested build properties from
// one already-connected Android Debug Bridge transport. It deliberately does
// not select a device by serial or infer one from an address.
func androidCommand(ctx context.Context, args []string, out io.Writer, read func(context.Context, netip.AddrPort, uint64, time.Duration) (android.Report, error)) error {
	fs := flag.NewFlagSet("android", flag.ContinueOnError)
	fs.SetOutput(out)
	transportText := fs.String("transport-id", "", "required positive ADB transport ID")
	serverText := fs.String("server", "127.0.0.1:5037", "existing local ADB server")
	timeout := fs.Duration("timeout", 5*time.Second, "collection deadline (maximum 30s)")
	asJSON := fs.Bool("json", false, "emit structured Android observation")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: lantern android --transport-id ID [--server 127.0.0.1:5037] [--timeout 5s] [--json]")
	}
	transportID, err := parseAndroidTransportID(*transportText)
	if err != nil {
		return err
	}
	server, err := parseAndroidServer(*serverText)
	if err != nil {
		return err
	}
	if *timeout <= 0 || *timeout > 30*time.Second {
		return errors.New("Android timeout must be greater than zero and at most 30s")
	}

	report, readErr := read(ctx, server, transportID, *timeout)
	if *asJSON {
		payload := struct {
			android.Report
			Error string `json:"error,omitempty"`
		}{Report: report}
		if readErr != nil {
			payload.Error = readErr.Error()
		}
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			return err
		}
	} else if err := printAndroid(out, report); err != nil {
		return err
	}
	return readErr
}

func parseAndroidTransportID(s string) (uint64, error) {
	if s == "" {
		return 0, errors.New("Android transport-id is required")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("Android transport-id must be a positive unsigned integer")
		}
	}
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil || id == 0 {
		return 0, errors.New("Android transport-id must be a positive unsigned integer")
	}
	return id, nil
}

func parseAndroidServer(s string) (netip.AddrPort, error) {
	server, err := netip.ParseAddrPort(s)
	if err != nil || !server.IsValid() || server.Port() == 0 {
		return netip.AddrPort{}, errors.New("Android server must be a literal local address and port")
	}
	addr := server.Addr()
	if addr.Is4In6() || addr.Zone() != "" || !addr.IsLoopback() {
		return netip.AddrPort{}, errors.New("Android server must be a literal native loopback address without a zone")
	}
	return server, nil
}

func printAndroid(out io.Writer, r android.Report) error {
	clean := func(s string) string {
		if s = scanner.CleanText(s); strings.TrimSpace(s) != "" {
			return s
		}
		return "unknown"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Android properties · %s\n", clean(r.Source))
	fmt.Fprintf(&b, "ADB server        %s\n", clean(r.Server))
	fmt.Fprintf(&b, "Transport ID      %d\n", r.TransportID)
	fmt.Fprintf(&b, "Complete          %t\n", r.Complete)
	fmt.Fprintf(&b, "Manufacturer      %s\n", clean(r.Properties.Manufacturer))
	fmt.Fprintf(&b, "Reported model    %s\n", clean(r.Properties.Model))
	fmt.Fprintf(&b, "Device codename   %s\n", clean(r.Properties.Device))
	fmt.Fprintf(&b, "Build fingerprint %s\n", clean(r.Properties.BuildFingerprint))
	for _, claim := range r.Claims {
		fmt.Fprintf(&b, "Source %-9s %s · %s\n", clean(claim.Field), clean(claim.Key), clean(claim.Reference))
	}
	for _, unavailable := range r.Unavailable {
		fmt.Fprintf(&b, "Unavailable       %s\n", clean(unavailable))
	}
	_, err := io.WriteString(out, b.String())
	return err
}
