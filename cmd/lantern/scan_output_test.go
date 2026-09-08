package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/coupez/lantern/pkg/scanner"
)

type deniedDialer struct{}

func (deniedDialer) Probe(context.Context, netip.Addr, uint16, time.Duration) (bool, bool, time.Duration, error) {
	return false, false, 0, syscall.EACCES
}

func TestFailedScanPublishesAndSavesPartialReport(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	o := scanner.Defaults()
	o.Target = netip.PrefixFrom(ip, 32)
	o.ICMP, o.Multicast, o.Resolve, o.Descriptions = false, false, false, false
	e := scanner.Engine{Dialer: deniedDialer{}, NeighborSource: func(context.Context) (map[netip.Addr]string, error) {
		return map[netip.Addr]string{ip: "00:11:22:33:44:55"}, nil
	}}
	path := filepath.Join(t.TempDir(), "scan.json")
	var out bytes.Buffer
	report, err := scanWithOutput(context.Background(), func(ctx context.Context, emit func(scanner.Event)) (scanner.Report, error) {
		if emit != nil {
			t.Fatal("report-only output should not request events")
		}
		return e.Scan(ctx, o, emit)
	}, scanOutput{
		Save:   func(r scanner.Report) error { return scanner.Save(path, r) },
		Report: func(r scanner.Report) error { return json.NewEncoder(&out).Encode(r) },
	})
	if err == nil || report.Error == "" || report.Cancelled || len(report.Devices) != 1 || report.Devices[0].IP != ip {
		t.Fatalf("report=%+v error=%v", report, err)
	}
	saved, loadErr := scanner.Load(path)
	var printed scanner.Report
	decodeErr := json.Unmarshal(out.Bytes(), &printed)
	if loadErr != nil || decodeErr != nil || !reflect.DeepEqual(saved, printed) || saved.Error != report.Error || len(saved.Devices) != 1 {
		t.Fatal(saved, printed, loadErr, decodeErr)
	}
}

func TestOutputFailureCancelsAndSavesAfterWorkersFinish(t *testing.T) {
	parent, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	workerDone := make(chan struct{})
	writes, saves, publishes := 0, 0, 0
	path := filepath.Join(t.TempDir(), "partial.json")
	report, err := scanWithOutput(parent, func(ctx context.Context, emit func(scanner.Event)) (scanner.Report, error) {
		go func() { <-ctx.Done(); close(workerDone) }()
		emit(scanner.Event{Type: "device"})
		<-workerDone
		// Updates can still arrive as workers join after cancellation.
		emit(scanner.Event{Type: "device_update"})
		emit(scanner.Event{Type: "done"})
		return scanner.Report{Schema: 1, Cancelled: true, Devices: []scanner.Device{{IP: netip.MustParseAddr("192.0.2.1")}}}, nil
	}, scanOutput{
		Event: func(scanner.Event) error { writes++; return syscall.EPIPE },
		Save: func(r scanner.Report) error {
			select {
			case <-workerDone:
			default:
				t.Fatal("save ran before workers finished")
			}
			saves++
			return scanner.Save(path, r)
		},
		Report: func(scanner.Report) error { publishes++; return nil },
	})
	if !errors.Is(err, syscall.EPIPE) || parent.Err() != nil || writes != 1 || saves != 1 || publishes != 0 || !report.Cancelled {
		t.Fatal(err, parent.Err(), writes, saves, publishes, report)
	}
	saved, err := scanner.Load(path)
	if err != nil || !saved.Cancelled || len(saved.Devices) != 1 {
		t.Fatal(saved, err)
	}
}

func TestValidationFailureDoesNotReplaceSnapshotOrPublish(t *testing.T) {
	errInput := errors.New("invalid options")
	_, err := scanWithOutput(context.Background(), func(context.Context, func(scanner.Event)) (scanner.Report, error) {
		return scanner.Report{Schema: 1}, errInput
	}, scanOutput{
		Save:   func(scanner.Report) error { t.Fatal("saved invalid scan"); return nil },
		Report: func(scanner.Report) error { t.Fatal("published invalid scan"); return nil },
	})
	if !errors.Is(err, errInput) {
		t.Fatal(err)
	}
}

func TestScanSaveAndReportErrorsRemainAvailable(t *testing.T) {
	scanErr, saveErr, printErr := errors.New("scan failed"), errors.New("save failed"), errors.New("print failed")
	_, err := scanWithOutput(context.Background(), func(context.Context, func(scanner.Event)) (scanner.Report, error) {
		return scanner.Report{Error: scanErr.Error()}, scanErr
	}, scanOutput{
		Save:   func(scanner.Report) error { return saveErr },
		Report: func(scanner.Report) error { return printErr },
	})
	for _, want := range []error{scanErr, saveErr, printErr} {
		if !errors.Is(err, want) {
			t.Fatal("lost error", want, err)
		}
	}
}
