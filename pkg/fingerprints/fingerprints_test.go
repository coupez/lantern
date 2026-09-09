package fingerprints

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func TestAllCatalogExamplesAndProvenance(t *testing.T) {
	if Count() != 608 {
		t.Fatal(Count())
	}
	var manifest struct {
		Index string `json:"index_sha256"`
		Tests string `json:"testdata_sha256"`
	}
	if err := json.Unmarshal([]byte(Sources), &manifest); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/examples.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != manifest.Index || fmt.Sprintf("%x", sha256.Sum256(fixture)) != manifest.Tests {
		t.Fatal("artifact hashes differ")
	}
	z, err := gzip.NewReader(bytes.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(z)
	z.Close()
	if err != nil {
		t.Fatal(err)
	}
	var tests []struct {
		Field    string
		Examples []struct {
			Rule   int
			Input  string
			Fields map[string]string
		}
	}
	if err := json.Unmarshal(raw, &tests); err != nil {
		t.Fatal(err)
	}
	examples, assertions := 0, 0
	for i, group := range tests {
		c := catalogs[i]
		if group.Field != c.Field {
			t.Fatal("wrong database")
		}
		for _, example := range group.Examples {
			examples++
			r := c.Rules[example.Rule]
			match := Lookup(group.Field, example.Input)
			if match == nil || match.Reference != fmt.Sprintf("%s#L%d", c.Source, r.Line) || match.Name != r.Name || match.Preference != c.Preference || match.Certainty != r.Certainty || match.Fields["service.protocol"] != c.Protocol {
				t.Fatalf("wrong/missing match for %q: %+v", example.Input, match)
			}
			for key, want := range example.Fields {
				assertions++
				if match.Fields[key] != want {
					t.Errorf("%q: %s = %q, want %q", example.Input, key, match.Fields[key], want)
				}
			}
		}
	}
	if examples != 979 || assertions != 1234 {
		t.Fatal(examples, assertions)
	}
}
func TestBoundariesAndOwnership(t *testing.T) {
	for _, input := range []string{"", "Apache/2.4\n", "Apache/2.4\x1b", "Apache/2.4\u202e", "Apache/2.4\xff", strings.Repeat("a", MaxInputBytes+1)} {
		if Lookup(HTTPServer, input) != nil {
			t.Fatal("invalid input matched", input)
		}
	}
	if Lookup("ssh", "OpenSSH_9.9") != nil || Lookup(SSHBanner, "SSH-2.0-OpenSSH_9.9") != nil || Lookup(HTTPServer, "LanternUnknownServer_2026") != nil {
		t.Fatal("input field boundary ignored")
	}
	first := Lookup(HTTPServer, "Apache/2.4.65")
	if first == nil || first.Fields["service.cpe23"] != "cpe:/a:apache:http_server:2.4.65" {
		t.Fatal(first)
	}
	copy := first.Clone()
	copy.Fields["service.version"] = "mutated"
	first.Fields["service.vendor"] = "mutated"
	next := Lookup(HTTPServer, "Apache/2.4.65")
	if next.Fields["service.vendor"] != "Apache" || first.Fields["service.version"] != "2.4.65" {
		t.Fatal("shared result state")
	}
	if m := Lookup(HTTPServer, "Eltex TAU-72"); m == nil || m.Fields["os.product"] != "TAU-72 Firmware" {
		t.Fatal("forward interpolation", m)
	}
	if m := Lookup(SSHBanner, "dropbear"); m == nil || m.Fields["service.cpe23"] != "cpe:/a:dropbear_ssh_project:dropbear_ssh:-" {
		t.Fatal(m)
	}
	if m := Lookup(HTTPServer, "kHTTPd 1.0"); m == nil || m.Certainty != "0.50" {
		t.Fatal("certainty lost", m)
	}
}
func TestOptionalAndUntrustedInterpolation(t *testing.T) {
	r := rule{Params: []parameter{{Name: "service.version", Pos: 1}, {Name: "service.cpe23", Value: "cpe:/a:test:service:{service.version}"}, {Name: "hw.product", Value: "{absent} product"}, {Name: "cycle", Value: "{cycle}"}, {Name: "_tmp.name", Pos: 2}, {Name: "service.product", Value: "{_tmp.name}"}}}
	values := evaluate(r, []int{0, 5, -1, -1, 0, 5}, "{bad}", "ssh")
	if values["service.cpe23"] != "cpe:/a:test:service:-" || values["service.product"] != "{bad}" || values["service.protocol"] != "ssh" {
		t.Fatal(values)
	}
	for _, key := range []string{"hw.product", "cycle", "_tmp.name"} {
		if _, ok := values[key]; ok {
			t.Fatal(values)
		}
	}
}
func BenchmarkLookup(b *testing.B) {
	Count()
	for _, tc := range []struct{ field, input string }{{SSHBanner, "OpenSSH_9.9p1 Ubuntu-3ubuntu1"}, {HTTPServer, "Apache/2.4.65"}, {HTTPServer, strings.Repeat("x", MaxInputBytes)}} {
		b.Run(tc.field+fmt.Sprint(len(tc.input)), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				Lookup(tc.field, tc.input)
			}
		})
	}
}
