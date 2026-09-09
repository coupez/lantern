package onvif

import (
	"strings"
	"testing"
)

func TestResponseBoundaryLimits(t *testing.T) {
	for _, key := range []string{"Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId"} {
		t.Run(key, func(t *testing.T) {
			makeFields := func(n int) string {
				var b strings.Builder
				for _, name := range []string{"Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId"} {
					b.WriteString("<d:" + name + ">")
					if name == key {
						b.WriteString(strings.Repeat("x", n))
					}
					b.WriteString("</d:" + name + ">")
				}
				return b.String()
			}
			if _, err := ParseResponse(response(makeFields(2048))); err != nil {
				t.Fatal("rejected exact bound", err)
			}
			if _, err := ParseResponse(response(makeFields(2049))); err == nil {
				t.Fatal("accepted field overflow")
			}
		})
	}
	for _, n := range []int{13, 14} {
		extra := strings.Repeat("<x>", n) + strings.Repeat("</x>", n)
		_, err := ParseResponse(response(extra + fields()))
		if (err == nil) != (n == 13) {
			t.Fatal("depth boundary", n, err)
		}
	}
	// Envelope, Header, Body, response and five fields consume nine elements.
	for _, n := range []int{1015, 1016} {
		_, err := ParseResponse(response(strings.Repeat("<x/>", n) + fields()))
		if (err == nil) != (n == 1015) {
			t.Fatal("element boundary", n, err)
		}
	}
}
func TestAllEmptyRequiredStrings(t *testing.T) {
	b := `<d:Manufacturer/><d:Model/><d:FirmwareVersion/><d:SerialNumber/><d:HardwareId/>`
	got, err := ParseResponse(response(b))
	if err != nil || len(got) != 3 {
		t.Fatal(got, err)
	}
	for k, v := range got {
		if v != "" {
			t.Fatal(k, v)
		}
	}
}
