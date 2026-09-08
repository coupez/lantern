package scanner

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeviceCloneOwnsAllNestedFields(t *testing.T) {
	original := Device{IP: netip.MustParseAddr("192.0.2.1"), Names: []string{"original"}, Ports: []Port{{Number: 80}}, Evidence: []string{"mdns"}, Advertisements: []Advertisement{{Properties: map[string]string{"model": "Original"}}}, Identity: &Identity{Name: "Original", ModelNames: []string{"Candidate"}, Claims: []IdentityClaim{{Field: "model", Value: "Original"}}}}
	before, _ := json.Marshal(original)
	clone := original.Clone()
	clone.Names[0], clone.Ports[0].Banner, clone.Evidence[0] = "changed", "changed", "changed"
	clone.Advertisements[0].Properties["model"] = "changed"
	clone.Identity.Name, clone.Identity.ModelNames[0], clone.Identity.Claims[0].Value = "changed", "changed", "changed"
	after, _ := json.Marshal(original)
	if string(before) != string(after) {
		t.Fatal("nested fields shared with source", string(after))
	}
	if !reflect.DeepEqual(Device{}.Clone(), Device{}) {
		t.Fatal("nil fields changed")
	}
}

func eventFixtureEngine() (Engine, Options) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("192.0.2.0/29")
	o.ICMP, o.Multicast, o.Resolve, o.Descriptions = false, false, false, false
	o.NetBIOS = true
	o.Ports = nil
	e := Engine{NeighborSource: noNeighbors, NetBIOSSource: func(context.Context, []netip.Addr, time.Duration) (NetBIOSResult, error) {
		var result NetBIOSResult
		for _, raw := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
			ip := netip.MustParseAddr(raw)
			result.Replies = append(result.Replies, NetBIOSReply{IP: ip, Names: []NetBIOSName{nbName("FIXTURE", 0, 0x0400)}})
			result.Probed = append(result.Probed, ip)
		}
		return result, nil
	}}
	return e, o
}

func TestEnginePublishesOwnedEnrichedDevicesBeforeDone(t *testing.T) {
	e, o := eventFixtureEngine()
	var active atomic.Int32
	var types []string
	updates := map[netip.Addr]Device{}
	initial := map[netip.Addr]Device{}
	phaseStarted := false
	r, err := e.Scan(context.Background(), o, func(event Event) {
		if active.Add(1) != 1 {
			t.Error("callbacks overlapped")
		}
		defer active.Add(-1)
		runtime.Gosched()
		types = append(types, event.Type)
		switch event.Type {
		case "device":
			initial[event.Device.IP] = *event.Device
		case "progress":
			if event.Phase == "enrichment" {
				phaseStarted = true
				if event.Completed != 0 || event.Total != 3 {
					t.Error(event)
				}
			}
		case "device_update":
			if !phaseStarted || event.Phase != "enrichment" || event.Completed != len(updates)+1 || event.Total != 3 {
				t.Error(event)
			}
			if _, ok := initial[event.Device.IP]; !ok {
				t.Error("update preceded discovery")
			}
			if event.Device.Identity == nil || event.Device.Identity.Name != "FIXTURE" || event.Device.Kind != "computer / NAS" {
				t.Error("missing enrichment", event.Device)
			}
			updates[event.Device.IP] = *event.Device
		case "done":
			if len(updates) != 3 {
				t.Error("done preceded device updates")
			}
		}
	})
	if err != nil || len(r.Devices) != 3 || types[len(types)-1] != "done" {
		t.Fatal(r, types, err)
	}
	for _, d := range r.Devices {
		if !reflect.DeepEqual(d, updates[d.IP]) {
			t.Fatal("update differed from final record", d, updates[d.IP])
		}
		if initial[d.IP].Identity != nil || len(initial[d.IP].Names) != 0 {
			t.Fatal("initial snapshot changed")
		}
	}
	// Report owners and event owners can mutate their objects independently.
	before, _ := json.Marshal(updates[r.Devices[0].IP])
	r.Devices[0].Names[0] = "report changed"
	r.Devices[0].Identity.Claims[0].Value = "report changed"
	for key := range r.Devices[0].Advertisements[0].Properties {
		r.Devices[0].Advertisements[0].Properties[key] = "report changed"
	}
	after, _ := json.Marshal(updates[r.Devices[0].IP])
	if string(before) != string(after) {
		t.Fatal("report mutation changed retained event")
	}
}

func TestCallbackMutationCannotChangeReport(t *testing.T) {
	e, o := eventFixtureEngine()
	r, err := e.Scan(context.Background(), o, func(event Event) {
		if event.Device == nil {
			return
		}
		event.Device.Evidence[0] = "consumer changed"
		if event.Type == "device_update" {
			event.Device.Names[0] = "consumer changed"
			event.Device.Identity.Name = "consumer changed"
			event.Device.Identity.Claims[0].Value = "consumer changed"
			for key := range event.Device.Advertisements[0].Properties {
				event.Device.Advertisements[0].Properties[key] = "consumer changed"
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range r.Devices {
		if d.Identity.Name != "FIXTURE" || d.Names[0] != "FIXTURE" || d.Evidence[0] != "netbios" || d.Identity.Claims[0].Value != "FIXTURE" {
			t.Fatal(d)
		}
		for _, value := range d.Advertisements[0].Properties {
			if value == "consumer changed" {
				t.Fatal("shared advertisement")
			}
		}
	}
}
