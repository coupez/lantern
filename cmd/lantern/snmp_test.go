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

	"github.com/coupez/lantern/pkg/snmp"
)

func TestSNMPCommandValidation(t *testing.T) {
	for _, args := range [][]string{
		{}, {"192.0.2.1"}, {"router.example", "--community-env", "COMMUNITY"},
		{"192.0.2.0/24", "--community-env", "COMMUNITY"},
		{"0.0.0.0", "--community-env", "COMMUNITY"},
		{"224.0.0.1", "--community-env", "COMMUNITY"},
		{"255.255.255.255", "--community-env", "COMMUNITY"},
		{"::ffff:192.0.2.1", "--community-env", "COMMUNITY"},
		{"fe80::1", "--community-env", "COMMUNITY"},
		{"fe80::1%bad\nzone", "--community-env", "COMMUNITY"},
		{"192.0.2.1", "--community-env", "bad-name"},
		{"192.0.2.1", "--community-env", "1NAME"},
		{"192.0.2.1", "--community-env", "COMMUNITY", "--port", "0"},
		{"192.0.2.1", "--community-env", "COMMUNITY", "--port", "65536"},
		{"192.0.2.1", "--community-env", "COMMUNITY", "--timeout", "0s"},
		{"192.0.2.1", "--community-env", "COMMUNITY", "--timeout", "31s"},
		{"192.0.2.1", "192.0.2.2", "--community-env", "COMMUNITY"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			lookup := func(string) (string, bool) { t.Fatal("read credentials before valid arguments"); return "", false }
			read := func(context.Context, netip.AddrPort, snmp.Credentials, time.Duration) (snmp.Report, error) {
				t.Fatal("sent SNMP request with invalid arguments")
				return snmp.Report{}, nil
			}
			if err := snmpCommand(context.Background(), args, &bytes.Buffer{}, lookup, read); err == nil {
				t.Fatal("accepted invalid arguments")
			}
		})
	}
}

func TestSNMPCommandCredentialRequirements(t *testing.T) {
	for _, secret := range []string{"", strings.Repeat("x", 256)} {
		lookup := func(string) (string, bool) { return secret, secret != "" }
		read := func(context.Context, netip.AddrPort, snmp.Credentials, time.Duration) (snmp.Report, error) {
			t.Fatal("sent request without valid credentials")
			return snmp.Report{}, nil
		}
		if err := snmpCommand(context.Background(), []string{"192.0.2.1", "--community-env", "COMMUNITY"}, &bytes.Buffer{}, lookup, read); err == nil {
			t.Fatal("missing credential validation")
		}
	}
}

func TestSNMPCommandPartialOutput(t *testing.T) {
	readFailure := errors.New("SNMP entity read timed out")
	lookup := func(name string) (string, bool) {
		if name != "TEST_COMMUNITY" {
			t.Fatal(name)
		}
		return "synthetic-secret-do-not-print", true
	}
	read := func(ctx context.Context, target netip.AddrPort, credentials snmp.Credentials, timeout time.Duration) (snmp.Report, error) {
		if target.String() != "[fe80::1%en0]:1161" || timeout != time.Second {
			t.Fatal(target, timeout)
		}
		if _, err := snmp.BuildGet(credentials, 1, []string{"1.3.6.1.2.1.1.1.0"}); err != nil {
			t.Fatal(err)
		}
		r := snmp.Report{Target: target.String(), EntityStatus: "failed"}
		r.System.Name = "Example\x1b[2JRouter"
		return r, readFailure
	}
	for _, jsonMode := range []bool{false, true} {
		args := []string{"fe80::1%en0", "--community-env", "TEST_COMMUNITY", "--port", "1161", "--timeout", "1s"}
		if jsonMode {
			args = append(args, "--json")
		}
		var out bytes.Buffer
		err := snmpCommand(context.Background(), args, &out, lookup, read)
		if !errors.Is(err, readFailure) {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "synthetic-secret") || strings.Contains(out.String(), "\x1b") {
			t.Fatal(out.String())
		}
		if jsonMode {
			var result map[string]any
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result["schema"] != float64(1) || result["protocol"] != "snmpv2c" || result["error"] != readFailure.Error() || result["entity_status"] != "failed" {
				t.Fatal(result)
			}
		} else if !strings.Contains(out.String(), "Example") {
			t.Fatal(out.String())
		}
		if err := snmpCommand(context.Background(), args, evaluationFailWriter{}, lookup, read); err == nil || !strings.Contains(err.Error(), "sink closed") {
			t.Fatal(err)
		}
	}
}
