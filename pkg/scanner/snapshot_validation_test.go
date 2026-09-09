package scanner

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadRejectsInvalidOrDuplicateDeviceAddresses(t *testing.T) {
	for name, document := range map[string]string{
		"missing":          `{"schema":1,"devices":[{}]}`,
		"null":             `{"schema":1,"devices":[{"ip":null}]}`,
		"unspecified4":     `{"schema":1,"devices":[{"ip":"0.0.0.0"}]}`,
		"unspecified6":     `{"schema":1,"devices":[{"ip":"::"}]}`,
		"unspecified-zone": `{"schema":1,"devices":[{"ip":"::%eth0"}]}`,
		"multicast4":       `{"schema":1,"devices":[{"ip":"224.0.0.1"}]}`,
		"multicast6":       `{"schema":1,"devices":[{"ip":"ff02::1"}]}`,
		"mapped":           `{"schema":1,"devices":[{"ip":"::ffff:192.0.2.1"}]}`,
		"duplicate4":       `{"schema":1,"devices":[{"ip":"192.0.2.1","names":["first"]},{"ip":"192.0.2.1","names":["second"]}]}`,
		"duplicate6":       `{"schema":1,"devices":[{"ip":"2001:db8::1"},{"ip":"2001:db8:0:0:0:0:0:1"}]}`,
		"duplicate-zone":   `{"schema":1,"devices":[{"ip":"fe80::1%eth0"},{"ip":"fe80::1%eth0"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, []byte(document), 0600); err != nil {
				t.Fatal(err)
			}
			report, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "device") || !reflect.DeepEqual(report, Report{}) {
				t.Fatal("accepted invalid snapshot", report, err)
			}
		})
	}
}

func TestSaveValidationPreservesExistingSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	original := []byte("existing snapshot content\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.1")
	for _, report := range []Report{
		{Schema: 2},
		{Schema: 1, Devices: []Device{{}}},
		{Schema: 1, Devices: []Device{{IP: ip}, {IP: ip}}},
	} {
		if err := Save(path, report); err == nil {
			t.Fatal("saved invalid report", report)
		}
		after, err := os.ReadFile(path)
		if err != nil || string(after) != string(original) {
			t.Fatal("replaced existing snapshot", string(after), err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary files left behind", entries, err)
	}
}

func TestSnapshotValidationPreservesLegacyAndScopedReports(t *testing.T) {
	report := Report{Schema: 1, Devices: []Device{
		{IP: netip.MustParseAddr("fe80::1%eth0")},
		{IP: netip.MustParseAddr("fe80::1%eth1")},
		{IP: netip.MustParseAddr("192.0.2.1"), Ports: []Port{{Number: 80}, {Number: 80}}},
	}}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := Save(path, report); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || !reflect.DeepEqual(loaded, report) {
		t.Fatal(loaded, err)
	}
	// Unknown extension fields and optional legacy metadata remain supported.
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Replace(string(b), `"schema":1`, `"schema":1,"future_extension":{"value":true}`, 1)
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if loaded, err = Load(path); err != nil || !reflect.DeepEqual(loaded, report) {
		t.Fatal(loaded, err)
	}
}

type snapshotRangeDialer struct {
	t    *testing.T
	want netip.Addr
}

func (d snapshotRangeDialer) Probe(_ context.Context, ip netip.Addr, _ uint16, _ time.Duration) (bool, bool, time.Duration, error) {
	if ip != d.want {
		d.t.Errorf("probed %s; want only %s", ip, d.want)
	}
	return true, true, time.Millisecond, nil
}

func TestZeroContainingRangeSnapshotRoundTrip(t *testing.T) {
	for _, target := range []string{"0.0.0.0/31", "::/127"} {
		t.Run(target, func(t *testing.T) {
			o := Defaults()
			o.Target = netip.MustParsePrefix(target)
			o.MaxHosts = 1
			o.ICMP, o.Multicast, o.Resolve, o.Descriptions = false, false, false, false
			o.AllHosts = true
			o.Ports = []uint16{8080}
			f := snapshotRangeDialer{t: t, want: o.Target.Addr().Next()}
			report, err := (Engine{Dialer: f, NeighborSource: noNeighbors}).Scan(context.Background(), o, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Devices) != 1 || report.Devices[0].IP != o.Target.Addr().Next() {
				t.Fatal("expected enumeration of the one eligible address", report)
			}
			path := filepath.Join(t.TempDir(), "report.json")
			if err := Save(path, report); err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(path)
			if err != nil || len(Diff(report, loaded)) != 0 {
				t.Fatal("scan snapshot changed during persistence", loaded, err)
			}
		})
	}
}
