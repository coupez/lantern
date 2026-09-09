package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coupez/lantern/pkg/capture"
	"github.com/coupez/lantern/pkg/dhcp"
	"github.com/coupez/lantern/pkg/fingerbank"
	"github.com/coupez/lantern/pkg/observe"
)

func fingerbankFixture() fingerbankInput {
	row := observe.Observation{Packet: 1, SourcePort: 68, DestinationPort: 67, SourceIP: "0.0.0.0", DestinationIP: "255.255.255.255", Message: dhcp.Message{Version: 4, Type: 1,
		ClientHardwareAddress: "02:00:00:00:00:01", Options: []dhcp.Option{
			{Code: 53, Data: []byte{1}, Area: "options"}, {Code: 55, Data: []byte{1, 3, 6, 3}, Area: "options"},
			{Code: 60, Data: []byte("SyntheticVendor"), Area: "options"}, {Code: 12, Data: []byte("private-hostname"), Area: "options"},
		}, Hints: dhcp.Hints{Hostname: "private-hostname", RequestedOptions: []uint16{99}, ClientID: []byte("private-client-id")}}}
	other := row
	other.Packet = 2
	return fingerbankInput{Summary: observe.Summary{Schema: 1, Observations: 2, Capture: capture.Stats{Packets: 2, Format: "pcap"}}, Observations: []observe.Observation{row, other}}
}

func TestFingerbankPreviewAndSingleSubmission(t *testing.T) {
	p := filepath.Join(t.TempDir(), "observe.json")
	writeTestJSON(t, p, fingerbankFixture())
	envCalls, requestCalls := 0, 0
	env := func(name string) (string, bool) {
		envCalls++
		if name != "TEST_KEY" {
			t.Fatal(name)
		}
		return "test-secret", true
	}
	request := func(_ context.Context, key string, a fingerbank.Attributes) (fingerbank.Result, error) {
		requestCalls++
		if key != "test-secret" || a.DHCPFingerprint != "1,3,6,3" || a.DHCPVendor != "SyntheticVendor" {
			t.Fatalf("unexpected request: %+v", a)
		}
		return fingerbank.Result{Status: "unknown"}, nil
	}
	var out bytes.Buffer
	if err := fingerbankCommand(context.Background(), []string{"--read", p}, &out, env, request); err != nil {
		t.Fatal(err)
	}
	if envCalls != 0 || requestCalls != 0 {
		t.Fatal("preview accessed credentials or network")
	}
	var preview fingerbankOutput
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if len(preview.Rows) != 2 || preview.Rows[0].Packet != 1 || preview.Rows[1].Packet != 2 || preview.Rows[0].PayloadSHA256 != preview.Rows[1].PayloadSHA256 {
		t.Fatalf("packet provenance: %+v", preview)
	}
	if strings.Contains(out.String(), "private-") || strings.Contains(out.String(), "02:00:") || strings.Contains(out.String(), "255.255.") {
		t.Fatal("unrelated identifiers escaped into output")
	}
	raw, _ := os.ReadFile(p)
	h := sha256.Sum256(raw)
	if preview.SourceSHA256 != hex.EncodeToString(h[:]) {
		t.Fatal("wrong source hash")
	}
	body, _ := json.Marshal(preview.Rows[0].Payload)
	h = sha256.Sum256(body)
	if preview.Rows[0].PayloadSHA256 != hex.EncodeToString(h[:]) {
		t.Fatal("wrong payload hash")
	}
	out.Reset()
	if err := fingerbankCommand(context.Background(), []string{"--read", p, "--packet", "2", "--submit", "--key-env", "TEST_KEY"}, &out, env, request); err != nil {
		t.Fatal(err)
	}
	if envCalls != 1 || requestCalls != 1 {
		t.Fatal("submission must issue exactly one request")
	}
	var result fingerbankOutput
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Mode != "submitted" || result.SubmittedAt == nil || len(result.Rows) != 1 || result.Rows[0].Packet != 2 || result.Rows[0].Provider.Status != "unknown" {
		t.Fatalf("result %+v", result)
	}
}

func TestFingerbankRejectsBeforeCredentialsOrNetwork(t *testing.T) {
	for _, name := range []string{"no-packet", "missing-packet", "server", "duplicate-packet", "summary-count", "schema", "duplicate-json", "unknown-json", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "observe.json")
			input := fingerbankFixture()
			args := []string{"--read", p, "--packet", "1", "--submit", "--key-env", "TEST_KEY"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "no-packet":
				args = []string{"--read", p, "--submit", "--key-env", "TEST_KEY"}
			case "missing-packet":
				args[3] = "3"
			case "server":
				input.Observations[0].SourcePort = 67
				input.Observations[0].DestinationPort = 68
			case "duplicate-packet":
				input.Observations[1].Packet = 1
			case "summary-count":
				input.Summary.Observations = 3
			case "schema":
				input.Summary.Schema = 2
			case "cancelled":
				cancel()
			}
			writeTestJSON(t, p, input)
			if name == "duplicate-json" || name == "unknown-json" {
				raw, _ := os.ReadFile(p)
				prefix := `{"summary":{},`
				if name == "unknown-json" {
					prefix = `{"extra":true,`
				}
				if err := os.WriteFile(p, append([]byte(prefix), raw[1:]...), 0600); err != nil {
					t.Fatal(err)
				}
			}
			env := func(string) (string, bool) { t.Fatal("unexpected credential read"); return "", false }
			request := func(context.Context, string, fingerbank.Attributes) (fingerbank.Result, error) {
				t.Fatal("unexpected network lookup")
				return fingerbank.Result{}, nil
			}
			var out bytes.Buffer
			if err := fingerbankCommand(ctx, args, &out, env, request); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestFingerbankFailureKeepsProvenanceWithoutSecret(t *testing.T) {
	p := filepath.Join(t.TempDir(), "observe.json")
	in := fingerbankFixture()
	in.Summary.Incomplete = true
	writeTestJSON(t, p, in)
	var out bytes.Buffer
	err := fingerbankCommand(context.Background(), []string{"--read", p, "--packet", "1", "--submit", "--key-env", "TEST_KEY"}, &out,
		func(string) (string, bool) { return "private-key", true }, func(context.Context, string, fingerbank.Attributes) (fingerbank.Result, error) {
			return fingerbank.Result{}, errors.New("private-key reflected by provider")
		})
	if err == nil || strings.Contains(err.Error()+out.String(), "private-key") {
		t.Fatal("missing error or leaked secret")
	}
	var got fingerbankOutput
	if e := json.Unmarshal(out.Bytes(), &got); e != nil {
		t.Fatal(e)
	}
	if got.Error == "" || !got.SourceIncomplete || got.Rows[0].PayloadSHA256 == "" || got.Rows[0].Provider != nil {
		t.Fatalf("partial provenance %+v", got)
	}
}
