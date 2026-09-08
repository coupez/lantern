package main

import (
	"bytes"
	"encoding/csv"
	"github.com/coupez/lantern/pkg/scanner"
	"github.com/coupez/lantern/pkg/vendors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestReorder(t *testing.T) {
	got := reorder([]string{"192.168.1.0/24", "--ports", "22,80", "--json"})
	want := []string{"--ports", "22,80", "--json", "192.168.1.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}
func TestCSVFormulaProtection(t *testing.T) {
	var b bytes.Buffer
	r := scanner.Report{Devices: []scanner.Device{{IP: netip.MustParseAddr("10.0.0.1"), Vendor: vendors.Match{Name: "=HYPERLINK(bad)"}}}}
	if e := writeCSV(&b, r); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(b.String(), "'=HYPERLINK") {
		t.Fatal(b.String())
	}
}
func TestInvalidCLI(t *testing.T) {
	for _, args := range [][]string{{"scan", "127.0.0.1", "--ndp"}, {"scan", "127.0.0.1", "--ipv6"}, {"scan", "fe80::1%en0", "--interface", "en1"}, {"scan", "127.0.0.1", "--profile", "missing"}, {"scan", "127.0.0.1", "--json", "--csv"}, {"scan", "0.0.0.0/0"}, {"watch", "--interval", "0s"}, {"scan", "127.0.0.1", "--concurrency", "0"}} {
		if e := run(args); e == nil {
			t.Fatal("accepted invalid args", args)
		}
	}
}

func TestCSVIncludesIdentity(t *testing.T) {
	var b bytes.Buffer
	r := scanner.Report{Devices: []scanner.Device{{IP: netip.MustParseAddr("10.0.0.1"), Identity: &scanner.Identity{Name: "Living Room", Manufacturer: "Example", Model: "Model 42"}}}}
	if err := writeCSV(&b, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "reported_name,manufacturer,model") || !strings.Contains(b.String(), "Living Room,Example,Model 42") {
		t.Fatal(b.String())
	}
}

func TestCSVCatalogCandidates(t *testing.T) {
	var b bytes.Buffer
	r := scanner.Report{Devices: []scanner.Device{{IP: netip.MustParseAddr("192.0.2.1"), Identity: &scanner.Identity{Model: "AppleTV14,1", ModelNames: []string{"Wi-Fi", "Wi-Fi + Ethernet"}}}}}
	if err := writeCSV(&b, r); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&b).ReadAll()
	if err != nil || len(rows) != 2 || len(rows[1]) != 12 || rows[0][9] != "model_candidates" || rows[1][8] != "AppleTV14,1" || rows[1][9] != "Wi-Fi;Wi-Fi + Ethernet" {
		t.Fatal(rows, err)
	}
}

func TestCSVFirmwareFieldsAndFormulaProtection(t *testing.T) {
	var b bytes.Buffer
	r := scanner.Report{Devices: []scanner.Device{{IP: netip.MustParseAddr("192.0.2.1"), Identity: &scanner.Identity{Firmware: "ESPHome", FirmwareVersion: "=untrusted"}}, {IP: netip.MustParseAddr("192.0.2.2")}}}
	if err := writeCSV(&b, r); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&b).ReadAll()
	if err != nil || len(rows) != 3 || len(rows[0]) != 12 || rows[0][10] != "firmware" || rows[0][11] != "firmware_version" || rows[1][10] != "ESPHome" || rows[1][11] != "'=untrusted" || rows[2][10] != "" || rows[2][11] != "" {
		t.Fatal(rows, err)
	}
}
