//go:build darwin

package scanner

import (
	"encoding/binary"
	"testing"
)

func TestBPFRecordBoundaries(t *testing.T) {
	b := make([]byte, 48)
	binary.NativeEndian.PutUint16(b[16:18], 18)
	binary.NativeEndian.PutUint32(b[8:12], 3)
	copy(b[18:], []byte{1, 2, 3})
	binary.NativeEndian.PutUint16(b[40:42], 18)
	binary.NativeEndian.PutUint32(b[32:36], 2)
	copy(b[42:], []byte{4, 5})
	frame, rest, err := splitBPF(b)
	if err != nil || len(frame) != 3 || len(rest) != 24 || frame[2] != 3 {
		t.Fatal(frame, rest, err)
	}
	frame, _, err = splitBPF(rest)
	if err != nil || len(frame) != 2 || frame[0] != 4 {
		t.Fatal(frame, err)
	}
	for _, bad := range [][]byte{b[:17], b[:20]} {
		if _, _, err := splitBPF(bad); err == nil {
			t.Fatal("truncation accepted")
		}
	}
	binary.NativeEndian.PutUint32(b[8:12], 0xffffffff)
	if _, _, err := splitBPF(b); err == nil {
		t.Fatal("oversized record accepted")
	}
}
func FuzzBPFRecords(f *testing.F) {
	f.Add(make([]byte, 20))
	f.Fuzz(func(t *testing.T, b []byte) { splitBPF(b) })
}
