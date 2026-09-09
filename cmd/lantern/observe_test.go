package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/coupez/lantern/pkg/observe"
)

func observationCapture(n int) []byte {
	// Independent classic PCAP fixture: Ethernet/IP/UDP/DHCP Discover.
	dhcp := make([]byte, 240)
	dhcp[0] = 1
	dhcp[1] = 1
	dhcp[2] = 6
	copy(dhcp[28:34], []byte{2, 1, 2, 3, 4, 5})
	copy(dhcp[236:], []byte{99, 130, 83, 99})
	dhcp = append(dhcp, 53, 1, 1, 12, 4, 't', 'e', 's', 't', 255)
	packet := make([]byte, 14+20+8)
	packet[12] = 8
	packet[14] = 0x45
	packet[22] = 64
	packet[23] = 17
	binary.BigEndian.PutUint16(packet[16:], uint16(28+len(dhcp)))
	copy(packet[30:34], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(packet[34:], 68)
	binary.BigEndian.PutUint16(packet[36:], 67)
	binary.BigEndian.PutUint16(packet[38:], uint16(8+len(dhcp)))
	packet = append(packet, dhcp...)
	out := new(bytes.Buffer)
	for _, v := range []any{uint32(0xa1b2c3d4), uint16(2), uint16(4), uint32(0), uint32(0), uint32(65535), uint32(1)} {
		binary.Write(out, binary.LittleEndian, v)
	}
	for i := 0; i < n; i++ {
		for _, v := range []uint32{1700000000, uint32(i), uint32(len(packet)), uint32(len(packet))} {
			binary.Write(out, binary.LittleEndian, v)
		}
		out.Write(packet)
	}
	return out.Bytes()
}

func TestObservationRejectsFIFOWithoutWaiting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	// Opening without O_NONBLOCK would hang here without a producer.
	if err := observeCommand([]string{"--read", path, "--json"}); err == nil || err.Error() != "capture input must be a regular file" {
		t.Fatalf("expected regular-file rejection, got %v", err)
	}
}
func TestObservationJSONAndLimits(t *testing.T) {
	for _, tt := range []struct {
		name        string
		input       []byte
		limit, want int
		partial     bool
	}{
		{"complete", observationCapture(2), 3, 2, false},
		{"exact-limit", observationCapture(2), 2, 2, false},
		{"limit", observationCapture(2), 1, 1, true},
		{"truncated", append(observationCapture(1), 1, 2), 3, 1, true},
		{"empty-valid", observationCapture(0), 3, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := writeObservations(context.Background(), bytes.NewReader(tt.input), &out, true, false, tt.limit, nil, nil)
			var got struct {
				Summary      observe.Summary       `json:"summary"`
				Observations []observe.Observation `json:"observations"`
			}
			if e := json.Unmarshal(out.Bytes(), &got); e != nil {
				t.Fatal(e, out.String())
			}
			if (err != nil) != tt.partial || got.Summary.Incomplete != tt.partial || len(got.Observations) != tt.want || got.Summary.Observations != tt.want {
				t.Fatalf("%+v err=%v", got, err)
			}
			if tt.want > 0 && got.Observations[0].Message.Hints.Hostname != "test" {
				t.Fatal(got.Observations)
			}
			if got.Observations == nil {
				t.Fatal("empty observations must be []")
			}
		})
	}
}
func TestObservationJSONLPartialAndWriterError(t *testing.T) {
	var out bytes.Buffer
	err := writeObservations(context.Background(), bytes.NewReader(observationCapture(2)), &out, false, true, 1, nil, nil)
	if err == nil {
		t.Fatal("expected limit")
	}
	dec := json.NewDecoder(&out)
	var first struct {
		Type        string
		Observation observe.Observation
	}
	var last struct {
		Type    string
		Summary observe.Summary
	}
	if err := dec.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(&last); err != nil {
		t.Fatal(err)
	}
	if first.Type != "observation" || first.Observation.Packet != 1 || last.Type != "complete" || !last.Summary.Incomplete || last.Summary.Error == "" {
		t.Fatal(first, last)
	}
	if err := dec.Decode(&last); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	want := errors.New("broken output")
	w := &observationFailWriter{err: want}
	err = writeObservations(context.Background(), bytes.NewReader(observationCapture(2)), w, false, true, 3, nil, nil)
	if !errors.Is(err, want) || w.calls != 1 {
		t.Fatal(err, w.calls)
	}
}

type observationFailWriter struct {
	err   error
	calls int
}

func (w *observationFailWriter) Write([]byte) (int, error) { w.calls++; return 0, w.err }
func TestObservationCancellationPreservesJSON(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	err := writeObservations(ctx, bytes.NewReader(observationCapture(1)), &out, true, false, 2, nil, nil)
	if !errors.Is(err, context.Canceled) || !json.Valid(out.Bytes()) {
		t.Fatal(err, out.String())
	}
}
