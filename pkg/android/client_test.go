package android

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// shellFrame is deliberately independent of the production parser: these are
// the literal AOSP shell-v2 id + uint32-little-endian-length bytes.
func shellFrame(id byte, payload []byte) []byte {
	n := uint32(len(payload))
	b := []byte{id, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
	return append(b, payload...)
}

type oneByteReader struct{ r io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.r.Read(p)
}

func TestReadShellFragmentedAndZeroFrames(t *testing.T) {
	var wire []byte
	wire = append(wire, shellFrame(1, nil)...)
	wire = append(wire, shellFrame(2, nil)...)
	wire = append(wire, shellFrame(1, []byte("maker\nmodel\n"))...)
	wire = append(wire, shellFrame(1, []byte("device\nfingerprint\n"))...)
	wire = append(wire, []byte{3, 1, 0, 0, 0, 0}...)
	got, err := readShell(oneByteReader{bytes.NewReader(wire)})
	if err != nil || string(got) != "maker\nmodel\ndevice\nfingerprint\n" {
		t.Fatalf("%q, %v", got, err)
	}
}

func TestReadShellRejectsFraming(t *testing.T) {
	validExit := []byte{3, 1, 0, 0, 0, 0}
	tests := map[string][]byte{
		"missing exit":      shellFrame(1, []byte("x")),
		"truncated header":  {1, 1, 0},
		"truncated payload": {1, 2, 0, 0, 0, 'x'},
		"unknown id":        append(shellFrame(4, nil), validExit...),
		"stderr":            append(shellFrame(2, []byte("failure detail")), validExit...),
		"exit empty":        shellFrame(3, nil),
		"exit long":         shellFrame(3, []byte{0, 0}),
		"exit nonzero":      shellFrame(3, []byte{7}),
		"duplicate exit":    append(append([]byte(nil), validExit...), validExit...),
		"after exit":        append(append([]byte(nil), validExit...), shellFrame(1, nil)...),
		"oversized frame":   {1, 9, 32, 0, 0},
	}
	for name, wire := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := readShell(bytes.NewReader(wire))
			if err == nil || got != nil {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestReadShellBounds(t *testing.T) {
	var tooMany []byte
	for range 129 {
		tooMany = append(tooMany, shellFrame(1, nil)...)
	}
	tooMany = append(tooMany, []byte{3, 1, 0, 0, 0, 0}...)
	if got, err := readShell(bytes.NewReader(tooMany)); err == nil || got != nil {
		t.Fatal("accepted too many frames")
	}
	large := bytes.Repeat([]byte{'x'}, 8200)
	wire := append(shellFrame(1, large), shellFrame(1, []byte{'x'})...)
	wire = append(wire, []byte{3, 1, 0, 0, 0, 0}...)
	if got, err := readShell(bytes.NewReader(wire)); err == nil || got != nil {
		t.Fatal("accepted cumulative overflow")
	}
	stderr := append(shellFrame(2, bytes.Repeat([]byte{'x'}, 2049)), []byte{3, 1, 0, 0, 0, 0}...)
	if got, err := readShell(bytes.NewReader(stderr)); err == nil || got != nil {
		t.Fatal("accepted stderr overflow")
	}
}

func TestReadStatusFragmentedAndSecretFreeFailure(t *testing.T) {
	if err := readStatus(oneByteReader{strings.NewReader("OKAY")}, "transport"); err != nil {
		t.Fatal(err)
	}
	secret := "serial-secret-that-must-not-escape"
	fail := "FAIL0021" + secret
	err := readStatus(oneByteReader{strings.NewReader(fail)}, "transport")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("%v", err)
	}
	for name, raw := range map[string]string{"bad status": "NOPE", "bad hex": "FAILzzzz", "too large": "FAIL1001", "truncated": "FAIL0004xx"} {
		t.Run(name, func(t *testing.T) {
			if err := readStatus(strings.NewReader(raw), "shell"); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
