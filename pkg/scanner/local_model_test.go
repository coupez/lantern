package scanner

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLocalTargetModelsScopeAndSingleRead(t *testing.T) {
	networks := []Network{
		{Interface: "en1", Address: "192.0.2.1"}, {Interface: "en1", Address: "192.0.2.2"},
		{Interface: "en1", Address: "fe80::1%en1"}, {Interface: "en2", Address: "fe80::1%en2"},
		{Interface: "en2", Address: "192.0.2.3"}, {Interface: "en1", Address: "bad"},
	}
	targets := map[netip.Addr]bool{}
	for _, raw := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.99", "fe80::1%en1", "fe80::1%en2"} {
		targets[netip.MustParseAddr(raw)] = true
	}
	calls := 0
	got := localTargetModels(networks, targets, "en1", func() string { calls++; return "Mac16,9" })
	if calls != 1 || len(got) != 3 {
		t.Fatal(calls, got)
	}
	for _, raw := range []string{"192.0.2.99", "192.0.2.3", "fe80::1%en2", "fe80::1"} {
		if got[netip.MustParseAddr(raw)] != "" {
			t.Fatal("local model escaped interface scope", got)
		}
	}
	calls = 0
	got = localTargetModels(networks, map[netip.Addr]bool{netip.MustParseAddr("192.0.2.99"): true}, "", func() string { calls++; return "Mac16,9" })
	if calls != 0 || len(got) != 0 {
		t.Fatal("queried local model for remote-only target", calls, got)
	}
}
func TestLocalModelOverridesDisplayButPreservesClaims(t *testing.T) {
	ads := []Advertisement{{Protocol: "mdns", Service: "_ipp._tcp", Instance: "Shared._ipp._tcp.local", Properties: map[string]string{"usb_mfg": "Printer Maker", "usb_mdl": "Printer 42"}}}
	id := identifyWithLocalModel(ads, "Mac16,9")
	if id.Model != "Mac16,9" || id.Manufacturer != "Apple" || !reflect.DeepEqual(id.ModelNames, []string{"Mac Studio (M4 Max, 2025)"}) {
		t.Fatalf("%+v", id)
	}
	raw, printer := false, false
	for _, c := range id.Claims {
		if c.Source == localModelSource && c.Basis == "local-system" && c.Key == "hw.model" && c.Field == "model" && c.Value == "Mac16,9" && c.Reference == localModelReference {
			raw = true
		}
		if c.Value == "Printer 42" && c.Basis == "advertised" {
			printer = true
		}
	}
	if !raw || !printer {
		t.Fatal(id.Claims)
	}
	if kind := inferKind(Device{Identity: id, Advertisements: ads, Ports: []Port{{Number: 631}}}); kind != "computer" {
		t.Fatal(kind)
	}
	remote := identify(ads)
	if remote.Model != "Printer 42" || remote.Manufacturer != "Printer Maker" || inferKind(Device{Identity: remote, Advertisements: ads}) != "printer" {
		t.Fatal(remote)
	}
}
func TestLocalUnknownAndInvalidModels(t *testing.T) {
	ads := []Advertisement{{Protocol: "upnp", Instance: "d", Properties: map[string]string{"modelName": "Other Model", "manufacturer": "Other Maker"}}}
	id := identifyWithLocalModel(ads, "VirtualMac999,1")
	if id.Model != "VirtualMac999,1" || id.Manufacturer != "" || len(id.ModelNames) != 0 {
		t.Fatal(id)
	}
	for _, v := range []string{"", "Mac16,9\x00", "Mac16,9\u202e", strings.Repeat("x", 257)} {
		if got := identifyWithLocalModel(ads, v); !reflect.DeepEqual(got, identify(ads)) {
			t.Fatalf("unsafe local model changed identity: %q %+v", v, got)
		}
	}
	// Lookalike advertisements cannot create direct kernel evidence.
	forged := identify([]Advertisement{{Protocol: "local:sysctl", Service: "hw.model", Properties: map[string]string{"model": "Mac16,9"}}})
	if forged != nil {
		t.Fatal(forged)
	}
}
func TestLocalModelEngineAndFailure(t *testing.T) {
	networks, err := Networks()
	if err != nil || len(networks) == 0 {
		t.Skip("no enumerated local IPv4 interface")
	}
	ip := netip.MustParseAddr(networks[0].Address)
	o := Options{Target: netip.PrefixFrom(ip, 32), Interface: networks[0].Interface, Concurrency: 1, Timeout: time.Millisecond, MaxHosts: 1, AllHosts: true}
	for _, failure := range []bool{false, true} {
		calls := 0
		engine := Engine{Dialer: &fakeDialer{}, NeighborSource: noNeighbors, LocalModelSource: func() (string, error) {
			calls++
			if failure {
				return "", errors.New("fixture local read error")
			}
			return "Mac16,9", nil
		}}
		var updates []Device
		r, err := engine.Scan(context.Background(), o, func(e Event) {
			if e.Type == "device_update" {
				updates = append(updates, e.Device.Clone())
			}
		})
		if err != nil || calls != 1 || len(r.Devices) != 1 || !contains(r.Devices[0].Evidence, "local-interface") {
			t.Fatal(r, err, calls)
		}
		if failure {
			if r.Devices[0].Identity != nil || !contains(r.IncompleteMethods, "local-model") {
				t.Fatal(r)
			}
		} else {
			if r.Devices[0].Identity == nil || r.Devices[0].Identity.Model != "Mac16,9" || len(updates) != 1 || !reflect.DeepEqual(updates[0].Identity, r.Devices[0].Identity) {
				t.Fatal(r, updates)
			}
			path := t.TempDir() + "/local.json"
			if err := Save(path, r); err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(path)
			if err != nil || !reflect.DeepEqual(loaded.Devices[0].Identity, r.Devices[0].Identity) {
				t.Fatal(loaded, err)
			}
		}
	}
}

func TestLocalModelFailureKeepsIndependentDiffs(t *testing.T) {
	before := Report{Target: "192.0.2.0/24", Coverage: &ScanCoverage{TCPPorts: []uint16{80}}, Devices: []Device{
		{IP: netip.MustParseAddr("192.0.2.1"), Evidence: []string{"local-interface"}, Identity: identifyWithLocalModel(nil, "Mac16,9"), Names: []string{"old"}, Ports: []Port{{Number: 80}}},
		{IP: netip.MustParseAddr("192.0.2.2"), Evidence: []string{"tcp-open"}},
	}}
	after := Report{Target: before.Target, Coverage: before.Coverage, IncompleteMethods: []string{"local-model"}, Devices: []Device{{IP: before.Devices[0].IP, Evidence: []string{"local-interface"}, Names: []string{"new"}}}}
	changes := Diff(before, after)
	fields := map[string]bool{}
	missing := false
	for _, c := range changes {
		fields[c.Field] = true
		if strings.HasPrefix(c.Field, "identity.") || c.Field == "kind" {
			t.Fatal("local read failure manufactured identity loss", changes)
		}
		if c.Type == "missing" {
			missing = true
		}
	}
	if !fields["names"] || !fields["ports"] || !missing {
		t.Fatal("inventory failure suppressed unrelated observations", changes)
	}
}
