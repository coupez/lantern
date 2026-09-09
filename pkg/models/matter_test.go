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

func TestMatterProductLookup(t *testing.T) {
	rows := Lookup(" MATTER:4447:8194 ")
	if len(rows) != 1 || rows[0].Name != "Aqara Door and Window Sensor P2" || rows[0].Manufacturer != "" || rows[0].Identifier != "matter:4447:8194" || !strings.Contains(rows[0].Source, "/71bbd3da8178b1c38332a6d9342ea23a3ce5b3dd/drivers/SmartThings/matter-sensor/fingerprints.yml") {
		t.Fatal(rows)
	}
	rows[0].Name = "changed"
	if LookupMatter(4447, 8194)[0].Name == "changed" {
		t.Fatal("caller mutated catalog")
	}
	for _, id := range []string{"4447:8194", "matter:4447", "matter:04447:8194", "matter:+4447:8194", "matter:0x115f:8194", "matter:65521:32769", "matter:65536:1", "matter:4447:8194x", "matter:4447:8194\x00", "matter:1:8194"} {
		if len(Lookup(id)) != 0 {
			t.Fatal("invalid, test, or incomplete key matched", id)
		}
	}
	if len(LookupApple("matter:4447:8194")) != 0 || len(LookupShelly("matter:4447:8194", 0)) != 0 {
		t.Fatal("catalog namespace leaked")
	}
}

func TestMatterProductCatalogIntegrity(t *testing.T) {
	loadMatter()
	r, err := gzip.NewReader(bytes.NewReader(matterData))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	s := Sources()[2]
	if s.IndexSHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) || s.Identifiers != 998 || s.Assignments != 998 || len(matterIndex) != 998 || s.License != "Apache-2.0" || s.AmbiguousIdentifiers != 0 {
		t.Fatal(s)
	}
	for key, rows := range matterIndex {
		for _, r := range rows {
			if key != r.Identifier || r.Name == "" || len(r.SHA256) != 64 || !strings.HasPrefix(r.Path, "drivers/SmartThings/matter-") || !strings.HasSuffix(r.Path, "/fingerprints.yml") || strings.Contains(r.Path, "..") {
				t.Fatal(key, r)
			}
		}
	}
}

func BenchmarkMatterProductLookup(b *testing.B) {
	LookupMatter(4447, 8194)
	b.ReportAllocs()
	for b.Loop() {
		LookupMatter(4447, 8194)
	}
}
