package fingerprints

import (
	"strings"
	"testing"
)

func TestGreetingInputControlsAndNamespaces(t *testing.T) {
	for _, tc := range []struct{ field, input string }{
		{FTPBanner, "SYNOLOGY FTP server ready."},
		{SMTPBanner, "foo.bar ESMTP Postfix (3.1.4)"},
	} {
		good := Lookup(tc.field, tc.input)
		if good == nil {
			t.Fatal(tc)
		}
		for _, suffix := range []string{"\n", "\r", "\r\r\n", "\n\r", "\t", "\x00", "\x1b", "\u202e", "\xff"} {
			if got := Lookup(tc.field, tc.input+suffix); got != nil {
				t.Fatalf("accepted %q: %+v", suffix, got)
			}
		}
		for _, input := range []string{tc.input + "\r\nnotice", "東京 notice\r\n" + tc.input} {
			if Lookup(tc.field, input) == nil {
				t.Fatal("complete CRLF text rejected", input)
			}
		}
		if tc.field == SMTPBanner {
			cross := Lookup(tc.field, "東京\r\n"+tc.input)
			if cross == nil || cross.Fields["host.name"] != "東京\r\nfoo.bar" {
				t.Fatal("cross-line capture lost original CRLF", cross)
			}
			match := Lookup(tc.field, "東京 notice\r\n"+tc.input)
			if match.Input != "東京 notice\r\n"+tc.input || match.Fields["host.name"] != "foo.bar" || match.Fields["service.version"] != "3.1.4" {
				t.Fatal("capture offsets differ after Unicode/CRLF", match)
			}
		}
		if Lookup(tc.field, tc.input+strings.Repeat("x", MaxInputBytes)) != nil {
			t.Fatal("length bound ignored")
		}
		if Lookup(HTTPServer, tc.input+"\r\nApache/2.4.65") != nil {
			t.Fatal("HTTP accepted multiline input")
		}
	}
}
