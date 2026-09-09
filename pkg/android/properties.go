// Package android collects bounded model properties through an explicitly
// selected transport on an existing local ADB server.
package android

import (
	"bytes"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const buildPropertyReference = "https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/core/java/android/os/Build.java"

// Properties retains four explicitly requested Android build properties. Device
// and fingerprint strings remain reported identifiers, never catalog guesses.
type Properties struct {
	Manufacturer     string `json:"manufacturer,omitempty"`
	Model            string `json:"model,omitempty"`
	Device           string `json:"device,omitempty"`
	BuildFingerprint string `json:"build_fingerprint,omitempty"`
}

// ParseProperties parses exactly the four newline-terminated getprop results
// produced by the fixed collector command.
func ParseProperties(b []byte) (Properties, error) {
	if len(b) > 8200 || !utf8.Valid(b) {
		return Properties{}, errors.New("invalid or oversized Android properties")
	}
	lines := bytes.Split(b, []byte{'\n'})
	if len(lines) != 5 || len(lines[4]) != 0 {
		return Properties{}, errors.New("expected exactly four newline-terminated Android properties")
	}
	values := make([]string, 4)
	for i, line := range lines[:4] {
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) > 2048 || !utf8.Valid(line) {
			return Properties{}, errors.New("invalid Android property value")
		}
		value := string(line)
		for _, r := range value {
			if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return Properties{}, errors.New("unsafe Android property value")
			}
		}
		values[i] = strings.Trim(value, " ")
	}
	return Properties{Manufacturer: values[0], Model: values[1], Device: values[2], BuildFingerprint: values[3]}, nil
}
