// Package models resolves reported hardware identifiers against offline catalogs.
// A match is a catalog interpretation, not authenticated device identity.
package models

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"sync"
)

//go:embed data/apple-models.json.gz
var appleData []byte

//go:embed data/sources.json
var sourceData []byte

// Source records the exact upstream revision and generated index provenance.
type Source struct {
	Name                 string `json:"name"`
	URL                  string `json:"url"`
	Commit               string `json:"commit"`
	License              string `json:"license"`
	Retrieved            string `json:"retrieved"`
	ArchiveSHA256        string `json:"archive_sha256"`
	LicenseSHA256        string `json:"license_sha256"`
	IndexSHA256          string `json:"index_sha256"`
	SourceSHA256         string `json:"source_sha256,omitempty"`
	InputRecords         int    `json:"input_records"`
	Identifiers          int    `json:"identifiers"`
	Assignments          int    `json:"assignments"`
	AmbiguousIdentifiers int    `json:"ambiguous_identifiers"`
	Selection            string `json:"selection"`
}

// Match is one candidate; several products may share the same identifier.
type Match struct {
	Identifier   string `json:"identifier"`
	Name         string `json:"name"`
	Manufacturer string `json:"manufacturer"`
	Type         string `json:"type"`
	Catalog      string `json:"catalog"`
	Source       string `json:"source"`
	SHA256       string `json:"sha256"`
	Generation   int    `json:"generation,omitempty"`
}
type record struct {
	Identifier   string `json:"identifier"`
	Name         string `json:"name"`
	Manufacturer string `json:"manufacturer"`
	Type         string `json:"type"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
}

var once sync.Once
var index map[string][]record
var source Source

func load() {
	once.Do(func() {
		r, err := gzip.NewReader(bytes.NewReader(appleData))
		if err != nil {
			panic(err)
		}
		defer r.Close()
		data, err := io.ReadAll(r)
		if err != nil {
			panic(err)
		}
		if err = json.Unmarshal(data, &index); err != nil {
			panic(err)
		}
		if err = json.Unmarshal(sourceData, &source); err != nil {
			panic(err)
		}
	})
}

// Lookup uses an exact identifier, ignoring surrounding whitespace and case.
// Unknown values return an empty list. Returned records are independent copies.
func Lookup(identifier string) []Match {
	return append(LookupApple(identifier), LookupShelly(identifier, 0)...)
}

// LookupApple restricts matching to the AppleDB namespace for Apple protocol fields.
func LookupApple(identifier string) []Match {
	if len(identifier) > 256 {
		return []Match{}
	}
	load()
	rows := index[strings.ToLower(strings.TrimSpace(identifier))]
	result := make([]Match, 0, len(rows))
	for _, r := range rows {
		segments := strings.Split(r.Path, "/")
		for i := range segments {
			segments[i] = url.PathEscape(segments[i])
		}
		result = append(result, Match{Identifier: r.Identifier, Name: r.Name, Manufacturer: r.Manufacturer, Type: r.Type, Catalog: source.Name, Source: source.URL + "/blob/" + source.Commit + "/" + strings.Join(segments, "/"), SHA256: r.SHA256})
	}
	return result
}
func Count() int { load(); loadShelly(); return len(index) + len(shellyIndex) }

// Provenance returns the original AppleDB source. Use Sources for all catalogs.
func Provenance() Source { load(); return source }
