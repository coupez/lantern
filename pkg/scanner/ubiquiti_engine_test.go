package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/coupez/lantern/pkg/ubiquiti"
)

func ubiquitiEngineOptions() Options {
	o := Defaults()
	o.Target = netip.MustParsePrefix("192.0.2.8/32")
	o.Ubiquiti = true
	o.ICMP, o.ARP, o.NDP, o.Multicast, o.Resolve, o.Descriptions = false, false, false, false, false, false
	o.NetBIOS, o.AllHosts = false, false
	o.Ports = nil
	return o
}

func TestEngineUbiquitiOnlyDiscoveryAndEventClone(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.8")
	iface := firstTestInterface(t)
	var gotHosts []netip.Addr
	var gotInterface string
	engine := Engine{NeighborSource: noNeighbors, UbiquitiSource: func(_ context.Context, hosts []netip.Addr, _ time.Duration, selected string) (UbiquitiResult, error) {
		gotHosts, gotInterface = append([]netip.Addr(nil), hosts...), selected
		return UbiquitiResult{Probed: []netip.Addr{ip}, Replies: []UbiquitiReply{{IP: ip, Observation: ubiquitiObservation(2,
			ubiquiti.Field{Tag: 0x14, Value: "USW-Lite-8"}, ubiquiti.Field{Tag: 0x03, Value: "build-1"}, ubiquiti.Field{Tag: 0x16, Value: "1.2.3"})}}}, nil
	}, LocalModelSource: func() (string, error) { return "", nil }}
	o := ubiquitiEngineOptions()
	o.Interface = iface
	mutated := false
	r, err := engine.Scan(context.Background(), o, func(e Event) {
		if e.Device != nil && len(e.Device.Advertisements) > 0 {
			mutated = true
			e.Device.Identity = &Identity{Model: "mutated"}
			e.Device.Advertisements[0].Properties["0x14"] = "mutated"
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotHosts, []netip.Addr{ip}) || gotInterface != iface {
		t.Fatalf("source args hosts=%v interface=%q", gotHosts, gotInterface)
	}
	if !mutated || len(r.Devices) != 1 {
		t.Fatalf("events/devices = %v/%#v", mutated, r.Devices)
	}
	d := r.Devices[0]
	if d.IP != ip || !d.Responsive() || len(d.Ports) != 0 || d.MAC != "" || d.Identity == nil || d.Identity.Model != "USW-Lite-8" {
		t.Fatalf("device = %#v", d)
	}
	if d.Advertisements[0].Properties["0x14"] != "USW-Lite-8" || !contains(d.Evidence, "ubiquiti") {
		t.Fatalf("mutation leaked: %#v", d)
	}
}

func TestEngineUbiquitiIgnoresOutOfTargetAndRetainsPartialError(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.8")
	outside := netip.MustParseAddr("192.0.2.99")
	o := ubiquitiEngineOptions()
	engine := Engine{NeighborSource: noNeighbors, UbiquitiSource: func(context.Context, []netip.Addr, time.Duration, string) (UbiquitiResult, error) {
		return UbiquitiResult{Probed: []netip.Addr{ip, outside}, Replies: []UbiquitiReply{{IP: ip, Observation: ubiquitiObservation(1, ubiquiti.Field{Tag: 0x15, Value: "EdgeRouter X"})}, {IP: outside, Observation: ubiquitiObservation(1, ubiquiti.Field{Tag: 0x15, Value: "wrong"})}}}, errors.New("synthetic partial failure")
	}}
	r, err := engine.Scan(context.Background(), o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Devices) != 1 || r.Devices[0].IP != ip || r.Devices[0].Identity == nil || r.Devices[0].Identity.Model != "EdgeRouter X" {
		t.Fatalf("partial result = %#v", r)
	}
	if len(r.IncompleteMethods) != 1 || r.IncompleteMethods[0] != "ubiquiti" {
		t.Fatalf("incomplete = %#v", r.IncompleteMethods)
	}
}

func TestEngineUbiquitiDisabledDoesNotInvokeSource(t *testing.T) {
	called := false
	o := ubiquitiEngineOptions()
	o.Ubiquiti = false
	engine := Engine{NeighborSource: noNeighbors, UbiquitiSource: func(context.Context, []netip.Addr, time.Duration, string) (UbiquitiResult, error) {
		called = true
		return UbiquitiResult{}, nil
	}}
	if _, err := engine.Scan(context.Background(), o, nil); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("disabled Ubiquiti source was invoked")
	}
}

func TestEngineUbiquitiRejectsIPv6AndHostLimitBeforeSource(t *testing.T) {
	called := false
	engine := Engine{UbiquitiSource: func(context.Context, []netip.Addr, time.Duration, string) (UbiquitiResult, error) {
		called = true
		return UbiquitiResult{}, nil
	}}
	for name, target := range map[string]netip.Prefix{"ipv6": netip.MustParsePrefix("2001:db8::8/128"), "too-many": netip.MustParsePrefix("192.0.2.8/32")} {
		t.Run(name, func(t *testing.T) {
			o := ubiquitiEngineOptions()
			o.Target = target
			if name == "too-many" {
				o.MaxHosts = 4097
			}
			if _, err := engine.Scan(context.Background(), o, nil); err == nil {
				t.Fatal("accepted invalid Ubiquiti bounds")
			}
		})
	}
	if called {
		t.Fatal("source invoked for invalid bounds")
	}
}

func firstTestInterface(t *testing.T) string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Name != "" {
			return iface.Name
		}
	}
	t.Fatal("no test interface")
	return ""
}
