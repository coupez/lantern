package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"github.com/coupez/lantern/pkg/scanner"
	"github.com/coupez/lantern/pkg/snmp"
)

type snmpReader func(context.Context, netip.AddrPort, snmp.Credentials, time.Duration) (snmp.Report, error)

func snmpCommand(ctx context.Context, args []string, out io.Writer, lookup func(string) (string, bool), read snmpReader) error {
	fs := flag.NewFlagSet("snmp", flag.ContinueOnError)
	fs.SetOutput(out)
	communityEnv := fs.String("community-env", "", "environment variable holding the configured SNMPv2c community")
	port := fs.Int("port", 161, "target UDP port")
	timeout := fs.Duration("timeout", 2*time.Second, "total inventory deadline (maximum 30s)")
	asJSON := fs.Bool("json", false, "emit structured inventory, including partial results")
	if err := fs.Parse(reorder(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 || *communityEnv == "" {
		return errors.New("usage: lantern snmp IP --community-env NAME [--port 161] [--timeout 2s] [--json]")
	}
	addr, err := netip.ParseAddr(fs.Arg(0))
	if err != nil || addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return errors.New("SNMP target must be one literal unicast IPv4 or IPv6 address")
	}
	if addr.Is6() && addr.IsLinkLocalUnicast() && addr.Zone() == "" {
		return errors.New("link-local IPv6 SNMP targets require an interface zone, such as fe80::1%en0")
	}
	if len(addr.Zone()) > 255 || strings.ContainsFunc(addr.Zone(), func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) || unicode.In(r, unicode.Cf) }) {
		return errors.New("invalid IPv6 interface zone")
	}
	if *port < 1 || *port > 65535 || *timeout <= 0 || *timeout > 30*time.Second {
		return errors.New("SNMP port must be 1..65535 and timeout must be greater than zero and at most 30s")
	}
	for i, r := range *communityEnv {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return errors.New("community-env must name a shell environment variable")
		}
	}
	secret, ok := lookup(*communityEnv)
	if !ok || secret == "" {
		return errors.New("the configured SNMP community environment variable is unset or empty")
	}
	credentials, err := snmp.NewCredentials(secret)
	if err != nil {
		return err
	}
	report, readErr := read(ctx, netip.AddrPortFrom(addr, uint16(*port)), credentials, *timeout)
	if *asJSON {
		payload := struct {
			Schema   int    `json:"schema"`
			Protocol string `json:"protocol"`
			snmp.Report
			Error string `json:"error,omitempty"`
		}{Schema: 1, Protocol: "snmpv2c", Report: report}
		if readErr != nil {
			payload.Error = readErr.Error()
		}
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			return err
		}
	} else if err := printSNMP(out, report); err != nil {
		return err
	}
	return readErr
}

func printSNMP(out io.Writer, r snmp.Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "SNMP inventory · %s\nDevice-reported fields; SNMPv2c uses an unencrypted community.\n", scanner.CleanText(r.Target))
	field := func(label, value string) {
		if value != "" {
			fmt.Fprintf(&b, "%-15s %s\n", label, scanner.CleanText(value))
		}
	}
	field("Name", r.System.Name)
	field("Description", r.System.Description)
	field("Agent OID", r.System.ObjectID)
	field("Manufacturer", r.Manufacturer)
	field("Chassis model", r.Model)
	field("Entity status", r.EntityStatus)
	for _, entity := range r.Entities {
		if entity.Class != 3 {
			continue
		}
		parent := "unknown"
		if entity.Parent != nil {
			parent = fmt.Sprint(*entity.Parent)
		}
		fmt.Fprintf(&b, "Chassis %d      parent=%s", entity.Index, parent)
		if entity.Manufacturer != "" {
			fmt.Fprintf(&b, " · %s", scanner.CleanText(entity.Manufacturer))
		}
		if entity.Model != "" {
			fmt.Fprintf(&b, " · %s", scanner.CleanText(entity.Model))
		}
		b.WriteByte('\n')
	}
	for _, warning := range r.Warnings {
		fmt.Fprintf(&b, "Warning         %s\n", scanner.CleanText(warning))
	}
	_, err := io.WriteString(out, b.String())
	return err
}
