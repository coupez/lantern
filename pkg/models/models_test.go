package models

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestKnownAndAmbiguousModels(t *testing.T) {
	rows := Lookup(" Mac16,9 ")
	if len(rows) != 1 || rows[0].Name != "Mac Studio (M4 Max, 2025)" || rows[0].Manufacturer != "Apple" || rows[0].Type != "Mac Studio" || !strings.Contains(rows[0].Source, "/95f799d28e45dc110ee2f25b7e3e6cf8c1124dae/deviceFiles/Mac%20Studio/Mac16%2C9.json") {
		t.Fatal(rows)
	}
	rows[0].Name = "mutated"
	if Lookup("mac16,9")[0].Name == "mutated" {
		t.Fatal("caller changed catalog")
	}
	rows = Lookup("MacBookPro11,3")
	if len(rows) != 2 || !strings.Contains(rows[0].Name, "2013") || !strings.Contains(rows[1].Name, "2014") || rows[0].Source == rows[1].Source {
		t.Fatal(rows)
	}
	rows = Lookup("AppleTV14,1")
	if len(rows) != 2 || rows[0].Name == rows[1].Name {
		t.Fatal("hardware variants collapsed", rows)
	}
	for _, unknown := range []string{"Mac16,9 Pro", "Mac16", "Mac16,99999", "Mac16,9\x00", "Mac16,9\x1b", "unknown", strings.Repeat("X", 257), "AppleTV14,4"} {
		if len(Lookup(unknown)) != 0 {
			t.Fatal("fuzzy or excluded match", unknown)
		}
	}
}
func TestCatalogIntegrityAndProvenance(t *testing.T) {
	load()
	s := Provenance()
	r, err := gzip.NewReader(bytes.NewReader(appleData))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != s.IndexSHA256 || len(index) != s.Identifiers || s.License != "MIT" || s.InputRecords < 1500 {
		t.Fatal(s)
	}
	assignments, ambiguous := 0, 0
	for key, rows := range index {
		names := map[string]bool{}
		for _, r := range rows {
			assignments++
			names[r.Name] = true
			if strings.ToLower(r.Identifier) != key || r.Name == "" || r.Manufacturer == "" || len(r.SHA256) != 64 || !strings.HasPrefix(r.Path, "deviceFiles/") || strings.Contains(r.Path, "..") {
				t.Fatal(key, r)
			}
		}
		if len(names) > 1 {
			ambiguous++
		}
	}
	if assignments != s.Assignments || ambiguous != s.AmbiguousIdentifiers {
		t.Fatal(assignments, ambiguous, s)
	}
}
func BenchmarkLookup(b *testing.B) {
	Lookup("Mac16,9")
	b.ReportAllocs()
	for b.Loop() {
		Lookup("Mac16,9")
	}
}
