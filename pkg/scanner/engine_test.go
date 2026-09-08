package scanner

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type fakeDialer struct {
	active, max atomic.Int32
	calls       atomic.Int32
	block       bool
}

func (f *fakeDialer) Probe(ctx context.Context, ip netip.Addr, p uint16, d time.Duration) (bool, bool, time.Duration, error) {
	n := f.active.Add(1)
	defer f.active.Add(-1)
	for {
		old := f.max.Load()
		if n <= old || f.max.CompareAndSwap(old, n) {
			break
		}
	}
	f.calls.Add(1)
	if f.block {
		<-ctx.Done()
		return false, false, 0, nil
	}
	select {
	case <-ctx.Done():
		return false, false, 0, nil
	case <-time.After(time.Millisecond):
	}
	return ip.String() == "10.0.0.1", p == 8080, time.Millisecond, nil
}
func noNeighbors(context.Context) (map[netip.Addr]string, error) { return nil, nil }
func TestEngineBoundedAndAccurate(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("10.0.0.0/29")
	o.ICMP = false
	o.Multicast = false
	o.Resolve = false
	o.Ports = []uint16{8080}
	o.Concurrency = 4
	f := &fakeDialer{}
	events := 0
	r, e := (Engine{Dialer: f, NeighborSource: noNeighbors}).Scan(context.Background(), o, func(v Event) {
		if v.Type == "device" {
			events++
		}
	})
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Devices) != 1 || len(r.Devices[0].Ports) != 1 || r.Devices[0].Ports[0].Number != 8080 || events != 1 {
		t.Fatalf("%+v events %d", r, events)
	}
	if f.max.Load() > 4 {
		t.Fatal("concurrency exceeded")
	}
	if f.calls.Load() != 19 {
		t.Fatal("expected 18 discovery + 1 enrichment probes", f.calls.Load())
	}
}
func TestCancellation(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("10.0.0.0/24")
	o.ICMP = false
	o.Multicast = false
	o.Resolve = false
	f := &fakeDialer{block: true}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	r, e := (Engine{Dialer: f, NeighborSource: noNeighbors}).Scan(ctx, o, nil)
	if e != nil || !r.Cancelled || time.Since(start) > time.Second || f.active.Load() != 0 {
		t.Fatal(r, e)
	}
}
func TestCachedNeighborNotLive(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("10.0.0.2/32")
	o.ICMP = false
	o.Multicast = false
	o.Resolve = false
	o.Ports = nil
	r, e := (Engine{Dialer: &fakeDialer{}, NeighborSource: func(context.Context) (map[netip.Addr]string, error) {
		return map[netip.Addr]string{netip.MustParseAddr("10.0.0.2"): "00:11:22:33:44:55"}, nil
	}}).Scan(context.Background(), o, nil)
	if e != nil || len(r.Devices) != 1 || fmt.Sprint(r.Devices[0].Evidence) != "[neighbor-cache]" {
		t.Fatal(r, e)
	}
}
func TestSnapshotDiff(t *testing.T) {
	a := Report{Schema: 1, Devices: []Device{{IP: netip.MustParseAddr("10.0.0.1"), Ports: []Port{{Number: 80}}}}}
	b := a
	b.Devices = []Device{{IP: netip.MustParseAddr("10.0.0.1"), Ports: []Port{{Number: 443}}}, {IP: netip.MustParseAddr("10.0.0.2")}}
	d := Diff(a, b)
	if len(d) != 2 {
		t.Fatal(d)
	}
	p := t.TempDir() + "/report.json"
	if e := Save(p, b); e != nil {
		t.Fatal(e)
	}
	loaded, e := Load(p)
	if e != nil || len(loaded.Devices) != 2 {
		t.Fatal(loaded, e)
	}
}
func TestCleanText(t *testing.T) {
	if s := CleanText("host\x1b[2J\r\n\x07"); s != "host[2J" {
		t.Fatalf("unsafe text %q", s)
	}
}

func TestHugePortPlanCancelsWithoutMaterializingJobs(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("10.0.0.0/20")
	o.ICMP = false
	o.Multicast = false
	o.Resolve = false
	o.AllHosts = true
	o.Ports, _ = ParsePorts("1-65535")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	r, e := (Engine{Dialer: &fakeDialer{}, NeighborSource: noNeighbors}).Scan(ctx, o, nil)
	if e != nil || !r.Cancelled || r.Probed != 0 || time.Since(start) > time.Second {
		t.Fatal(r.Probed, r.Cancelled, e)
	}
}
func TestCancelledDiffDoesNotDeclareMissing(t *testing.T) {
	before := Report{Devices: []Device{{IP: netip.MustParseAddr("10.0.0.1")}}}
	if changes := Diff(before, Report{Cancelled: true}); len(changes) != 0 {
		t.Fatal(changes)
	}
}

func TestKindIsIndependentOfProbeCompletionOrder(t *testing.T) {
	a := Device{Ports: []Port{{Number: 445}, {Number: 631}}}
	b := Device{Ports: []Port{{Number: 631}, {Number: 445}}}
	if inferKind(a) != "printer" || inferKind(a) != inferKind(b) {
		t.Fatal(inferKind(a), inferKind(b))
	}
	if inferKind(Device{Advertisements: []Advertisement{{Protocol: "mdns", Service: "_ipp._tcp"}}}) != "printer" {
		t.Fatal("missed advertised printer")
	}
}

func TestCleanTextPreservesJoinersButRejectsDirectionControls(t *testing.T) {
	const text = "👩‍💻 فارسی\u200cمتن"
	if got := CleanText(text + "\u202e\u2066\u2069\u200b\x1b\u009b"); got != text {
		t.Fatalf("%q", got)
	}
}

func TestCorePortPlanDeduplicatesWithoutMutatingCaller(t *testing.T) {
	o := Defaults()
	o.Target = netip.MustParsePrefix("10.0.0.1/32")
	o.ICMP, o.Multicast, o.Resolve, o.Descriptions = false, false, false, false
	o.Ports = []uint16{8080, 22, 8080, 443, 80, 8080, 443}
	before := fmt.Sprint(o.Ports)
	f := &fakeDialer{}
	r, err := (Engine{Dialer: f, NeighborSource: noNeighbors}).Scan(context.Background(), o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.calls.Load() != 4 || len(r.Devices) != 1 || len(r.Devices[0].Ports) != 1 {
		t.Fatalf("duplicate probes: calls=%d devices=%+v", f.calls.Load(), r.Devices)
	}
	if fmt.Sprint(o.Ports) != before || fmt.Sprint(r.Coverage.TCPPorts) != "[22 80 443 8080]" {
		t.Fatalf("caller=%v coverage=%+v", o.Ports, r.Coverage)
	}
	o.Ports = append(o.Ports, 0)
	_, err = (Engine{Dialer: f, NeighborSource: noNeighbors}).Scan(context.Background(), o, nil)
	if err == nil || f.calls.Load() != 4 {
		t.Fatal("zero port must fail before probing", err, f.calls.Load())
	}
}
