package main

import (
	"bytes"
	"lantern/pkg/scanner"
	"lantern/pkg/vendors"
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
	for _, args := range [][]string{{"scan", "127.0.0.1", "--profile", "missing"}, {"scan", "127.0.0.1", "--json", "--csv"}, {"scan", "0.0.0.0/0"}, {"watch", "--interval", "0s"}, {"scan", "127.0.0.1", "--concurrency", "0"}} {
		if e := run(args); e == nil {
			t.Fatal("accepted invalid args", args)
		}
	}
}
