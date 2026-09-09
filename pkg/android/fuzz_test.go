package android

import (
	"bytes"
	"testing"
)

func FuzzProperties(f *testing.F) {
	f.Add([]byte("Example\nDevice 7\nboard7\nbuild/7\n"))
	f.Add([]byte("\n\n\n\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		properties, err := ParseProperties(input)
		if err == nil && (len(input) > 8200 || len(properties.Model) > 2048) {
			t.Fatal("accepted oversized properties")
		}
	})
}

func FuzzShellProtocol(f *testing.F) {
	f.Add(append(shellFrame(1, []byte("Example\nDevice 7\nboard7\nbuild/7\n")), []byte{3, 1, 0, 0, 0, 0}...))
	f.Add([]byte{3, 1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		output, err := readShell(bytes.NewReader(input))
		if err != nil && output != nil {
			t.Fatal("failed frame returned property bytes")
		}
		if len(output) > 8200 {
			t.Fatal("output exceeds bound")
		}
		if err == nil {
			_, _ = ParseProperties(output)
		}
	})
}
