package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coupez/lantern/pkg/evaluation"
	"github.com/coupez/lantern/pkg/scanner"
)

const testInventoryTime = "2026-09-09T12:00:00Z"

func writeTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func testScan() scanner.Report {
	return scanner.Report{Schema: 1, Target: "192.0.2.0/24", Started: mustTestTime(), DurationMS: 42,
		Targets: 1, Probed: 1, Devices: []scanner.Device{{IP: mustTestIP("192.0.2.10"), Evidence: []string{"mdns"},
			Identity: &scanner.Identity{Model: "NetworkModel"}}}}
}

func mustTestTime() (t time.Time)    { return time.Date(2026, 9, 9, 11, 0, 0, 0, time.UTC) }
func mustTestIP(s string) netip.Addr { return netip.MustParseAddr(s) }

func androidSource() map[string]any {
	return map[string]any{"schema": 1, "source": "adb", "server": "127.0.0.1:5037", "transport_id": 1,
		"collected_at": testInventoryTime, "complete": true,
		"properties": map[string]string{"manufacturer": "Acme", "model": "Pixel X", "device": "oriole", "build_fingerprint": "acme/oriole/oriole:14/UP1A/1:user/release-keys"}}
}

func androidManifest(path string, addresses []string) map[string]any {
	return map[string]any{"schema": 1, "bindings": []any{map[string]any{"id": "adb-1", "kind": "android", "path": path, "observed_at": testInventoryTime, "addresses": addresses}}}
}

func TestEnrichRelativePathHashesAndStrictJSON(t *testing.T) {
	d := t.TempDir()
	scanPath := filepath.Join(d, "scan.json")
	sourcePath := filepath.Join(d, "android.json")
	manifestPath := filepath.Join(d, "manifest.json")
	writeTestJSON(t, scanPath, testScan())
	writeTestJSON(t, sourcePath, androidSource())
	writeTestJSON(t, manifestPath, androidManifest("android.json", []string{"192.0.2.10"}))
	var out bytes.Buffer
	if err := enrichCommand([]string{"--scan", scanPath, "--inventory", manifestPath, "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var got scanner.Report
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Devices) != 1 || len(got.Devices[0].Inventory) != 1 {
		t.Fatalf("inventory = %#v", got.Devices)
	}
	o := got.Devices[0].Inventory[0]
	sourceBytes, _ := os.ReadFile(sourcePath)
	manifestBytes, _ := os.ReadFile(manifestPath)
	wantHash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	if o.SourceSHA256 != wantHash(sourceBytes) || o.BindingSHA256 != wantHash(manifestBytes) {
		t.Fatalf("hashes = %#v", o)
	}
	if o.BindingAddress != "192.0.2.10" || o.Claims[1].Value != "Pixel X" {
		t.Fatalf("observation = %#v", o)
	}
	for name, raw := range map[string]string{"unknown": `{"schema":1,"source":"adb","server":"127.0.0.1:5037","transport_id":1,"collected_at":"2026-09-09T12:00:00Z","complete":true,"properties":{},"extra":1}`, "duplicate": `{"schema":1,"schema":1}`} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(d, name+".json")
			os.WriteFile(p, []byte(raw), 0600)
			m := filepath.Join(d, name+"-manifest.json")
			writeTestJSON(t, m, androidManifest(filepath.Base(p), []string{"192.0.2.10"}))
			if err := enrichCommand([]string{"--scan", scanPath, "--inventory", m}, &bytes.Buffer{}); err == nil {
				t.Fatal("accepted malformed source")
			}
		})
	}
}

func TestEnrichSNMPRootModelMayHaveEmptyManufacturer(t *testing.T) {
	d := t.TempDir()
	scanPath := filepath.Join(d, "scan.json")
	sourcePath := filepath.Join(d, "snmp.json")
	manifestPath := filepath.Join(d, "manifest.json")
	writeTestJSON(t, scanPath, testScan())
	source := map[string]any{"schema": 1, "protocol": "snmpv2c", "target": "192.0.2.10:161", "entity_status": "complete", "entities": []any{map[string]any{"index": 1, "class": 3, "parent": 0, "model": "Switch42"}}, "system": map[string]any{}}
	source["model"], source["model_oid"] = "Switch42", "1.3.6.1.2.1.47.1.1.1.1.13.1"
	writeTestJSON(t, sourcePath, source)
	writeTestJSON(t, manifestPath, map[string]any{"schema": 1, "bindings": []any{map[string]any{"id": "snmp-1", "kind": "snmp", "path": "snmp.json", "observed_at": testInventoryTime, "addresses": []string{"192.0.2.10"}}}})
	var out bytes.Buffer
	if err := enrichCommand([]string{"--scan", scanPath, "--inventory", manifestPath, "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var got scanner.Report
	json.Unmarshal(out.Bytes(), &got)
	o := got.Devices[0].Inventory[0]
	if o.Status != "complete" || o.Claims[len(o.Claims)-1].Value != "Switch42" {
		t.Fatalf("SNMP observation = %#v", o)
	}
}

func TestEnrichAbsentAddressDoesNotOverwriteSave(t *testing.T) {
	d := t.TempDir()
	scanPath := filepath.Join(d, "scan.json")
	sourcePath := filepath.Join(d, "android.json")
	manifestPath := filepath.Join(d, "manifest.json")
	savePath := filepath.Join(d, "saved.json")
	writeTestJSON(t, scanPath, testScan())
	writeTestJSON(t, sourcePath, androidSource())
	writeTestJSON(t, manifestPath, androidManifest("android.json", []string{"192.0.2.99"}))
	os.WriteFile(savePath, []byte("sentinel"), 0600)
	if err := enrichCommand([]string{"--scan", scanPath, "--inventory", manifestPath, "--save", savePath}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted absent address")
	}
	b, _ := os.ReadFile(savePath)
	if string(b) != "sentinel" {
		t.Fatalf("save changed: %q", b)
	}
}

func TestEvaluateInventoryModeAndFlagValidation(t *testing.T) {
	d := t.TempDir()
	scanPath := filepath.Join(d, "scan.json")
	sourcePath := filepath.Join(d, "android.json")
	manifestPath := filepath.Join(d, "manifest.json")
	enriched := filepath.Join(d, "enriched.json")
	truthPath := filepath.Join(d, "truth.json")
	bindingsPath := filepath.Join(d, "bindings.json")
	writeTestJSON(t, scanPath, testScan())
	writeTestJSON(t, sourcePath, androidSource())
	writeTestJSON(t, manifestPath, androidManifest("android.json", []string{"192.0.2.10"}))
	if err := enrichCommand([]string{"--scan", scanPath, "--inventory", manifestPath, "--save", enriched}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	writeTestJSON(t, truthPath, evaluation.Truth{Schema: 1, ID: "truth", Kind: "synthetic", Cases: []evaluation.Case{{ID: "case-1", Class: "phone", Truth: map[string]evaluation.Label{evaluation.ReportedModel: {Accepted: []string{"Pixel X"}, SourceKind: "synthetic", Source: "fixture"}}}}})
	writeTestJSON(t, bindingsPath, evaluation.Bindings{Schema: 1, Dataset: "truth", RunID: "run", Version: "v1", Context: "test", Source: "fixture", Addresses: map[string]string{"192.0.2.10": "case-1"}})
	read := func(include bool) evaluationOutput {
		args := []string{"--truth", truthPath, "--scan", enriched, "--bindings", bindingsPath, "--json"}
		if include {
			args = append(args, "--include-inventory")
		}
		var b bytes.Buffer
		if err := evaluateCommand(args, &b); err != nil {
			t.Fatal(err)
		}
		var o evaluationOutput
		if err := json.Unmarshal(b.Bytes(), &o); err != nil {
			t.Fatal(err)
		}
		return o
	}
	without, with := read(false), read(true)
	if without.Evaluation.Overall.Observed != with.Evaluation.Overall.Observed || without.Evaluation.Overall.Responsive != with.Evaluation.Overall.Responsive {
		t.Fatal("inventory changed presence counts")
	}
	if with.Evaluation.System != "lantern+inventory" || with.Evaluation.DurationMS != nil || with.Evaluation.Overall.Fields[evaluation.ReportedModel].Ambiguous != 1 {
		t.Fatalf("include result = %#v", with.Evaluation)
	}
	if without.Evaluation.System != "lantern" || without.Evaluation.Overall.Fields[evaluation.ReportedModel].Correct != 0 {
		t.Fatalf("default result = %#v", without.Evaluation)
	}
	if err := evaluateCommand([]string{"--truth", truthPath, "--run", filepath.Join(d, "missing-run.json"), "--include-inventory"}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted include-inventory with run")
	}
}

type enrichFailWriter struct{}

func (enrichFailWriter) Write([]byte) (int, error) { return 0, errors.New("sink closed") }

func TestEnrichOutputWriterFailure(t *testing.T) {
	d := t.TempDir()
	scanPath := filepath.Join(d, "scan.json")
	sourcePath := filepath.Join(d, "android.json")
	manifestPath := filepath.Join(d, "manifest.json")
	writeTestJSON(t, scanPath, testScan())
	writeTestJSON(t, sourcePath, androidSource())
	writeTestJSON(t, manifestPath, androidManifest("android.json", []string{"192.0.2.10"}))
	for _, mode := range [][]string{nil, {"--json"}} {
		args := []string{"--scan", scanPath, "--inventory", manifestPath}
		args = append(args, mode...)
		if err := enrichCommand(args, enrichFailWriter{}); err == nil || !strings.Contains(err.Error(), "sink closed") {
			t.Fatalf("mode %v: %v", mode, err)
		}
	}
}
