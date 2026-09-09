package models

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestShellyCatalogIntegrityAndNamespaces(t *testing.T) {
	sources := Sources()
	if len(sources) != 3 || Count() != 1759 {
		t.Fatal(sources, Count())
	}
	s := sources[1]
	if s.Name != "aioshelly" || s.License != "Apache-2.0" || s.Identifiers != 155 || s.Assignments != 155 || s.IndexSHA256 != fmt.Sprintf("%x", sha256.Sum256(shellyData)) || s.Commit != "8f1b2f9bf2fc154faf6c3d73213d59620a6e301c" || len(s.SourceSHA256) != 64 || len(s.LicenseSHA256) != 64 {
		t.Fatal(s)
	}
	for key, rows := range shellyIndex {
		if len(rows) != 1 || len(LookupApple(key)) != 0 {
			t.Fatal(key, rows)
		}
		for _, row := range rows {
			matches := LookupShelly(key, row.Generation)
			if len(matches) != 1 || matches[0].Identifier != row.Identifier || matches[0].Name != row.Name || matches[0].Manufacturer != "Shelly" || matches[0].Generation != row.Generation || matches[0].SHA256 != s.SourceSHA256 || !strings.Contains(matches[0].Source, "/"+s.Commit+"/aioshelly/const.py") {
				t.Fatal(key, matches)
			}
			if len(LookupShelly(key, 9)) != 0 {
				t.Fatal("wrong generation matched", key)
			}
		}
	}
	rows := Lookup(" snsw-001x16eu ")
	if len(rows) != 1 || rows[0].Name != "Shelly Plus 1" || rows[0].Generation != 2 {
		t.Fatal(rows)
	}
	rows[0].Name = "mutated"
	if Lookup("SNSW-001X16EU")[0].Name != "Shelly Plus 1" {
		t.Fatal("caller mutated index")
	}
	if len(LookupShelly("Mac16,9", 0)) != 0 || len(LookupShelly("SHSW-1", 1)) != 1 {
		t.Fatal("namespace or Gen1 offline lookup")
	}
	for _, unknown := range []string{"SNSW-001X16EU-extra", "SNSW", "SNSW-001X16EU\x00", "SNSW-001X16EU\x1b", strings.Repeat("x", 257)} {
		if len(Lookup(unknown)) != 0 {
			t.Fatal("fuzzy match", unknown)
		}
	}
	sources[1].Name = "mutated"
	if Sources()[1].Name != "aioshelly" {
		t.Fatal("caller mutated provenance")
	}
}
