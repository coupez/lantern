package android

import (
	"strings"
	"testing"
)

func TestParseProperties(t *testing.T) {
	got, err := ParseProperties([]byte(" Google \r\nPixel 8 Pro\r\nhusky\r\ngoogle/husky/husky:14/UP1A.1:user/release-keys\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Manufacturer != "Google" || got.Model != "Pixel 8 Pro" || got.Device != "husky" || got.BuildFingerprint != "google/husky/husky:14/UP1A.1:user/release-keys" {
		t.Fatal(got)
	}
}

func TestParsePropertiesKeepsEmptyAndDistinctNamespaces(t *testing.T) {
	got, err := ParseProperties([]byte("\nIndustrial Controller X\nboard-codename\nvendor/board-codename/product:13/build\n"))
	if err != nil || got.Manufacturer != "" || got.Model != "Industrial Controller X" || got.Device != "board-codename" || !strings.Contains(got.BuildFingerprint, "board-codename") {
		t.Fatal(got, err)
	}
}

func TestParsePropertiesRejectsStructureAndUnsafeText(t *testing.T) {
	valid := "maker\nmodel\ndevice\nfingerprint\n"
	for _, raw := range [][]byte{
		[]byte("maker\nmodel\ndevice\nfingerprint"), []byte(valid + "extra\n"), []byte("maker\nmodel\ndevice\nfingerprint\n\n"),
		[]byte("maker\nmodel\nde\x00vice\nfingerprint\n"), []byte("maker\nmodel\ndevice\nfinger\xe2\x80\x8eprint\n"),
		[]byte("maker\nmodel\ndevice\nfinger\xef\xbf\xbdprint\n"), []byte("maker\nmodel\ndevice\nfinger\xffprint\n"),
		[]byte(strings.Repeat("x", 2049) + "\nmodel\ndevice\nfingerprint\n"), []byte(strings.Repeat("x", 8201)),
	} {
		if _, err := ParseProperties(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
