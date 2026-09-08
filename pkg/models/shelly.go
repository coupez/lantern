package models

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed data/shelly-models.json
var shellyData []byte

//go:embed data/shelly-sources.json
var shellySourceData []byte

var shellyOnce sync.Once
var shellyIndex map[string][]struct {
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	Generation int    `json:"generation"`
}
var shellySource Source

func loadShelly() {
	shellyOnce.Do(func() {
		if err := json.Unmarshal(shellyData, &shellyIndex); err != nil {
			panic(err)
		}
		if err := json.Unmarshal(shellySourceData, &shellySource); err != nil {
			panic(err)
		}
	})
}

// LookupShelly requires an exact model and generation. Generation zero returns
// all catalog generations for offline lookup, never automatic scan enrichment.
func LookupShelly(identifier string, generation int) []Match {
	result := []Match{}
	if len(identifier) > 256 {
		return result
	}
	loadShelly()
	for _, r := range shellyIndex[strings.ToLower(strings.TrimSpace(identifier))] {
		if generation != 0 && generation != r.Generation {
			continue
		}
		result = append(result, Match{Identifier: r.Identifier, Name: r.Name, Manufacturer: "Shelly", Generation: r.Generation,
			Catalog: shellySource.Name, Source: shellySource.URL + "/blob/" + shellySource.Commit + "/aioshelly/const.py", SHA256: shellySource.SourceSHA256})
	}
	return result
}

// Sources returns independent provenance records for every embedded catalog.
func Sources() []Source {
	load()
	loadShelly()
	loadMatter()
	return []Source{source, shellySource, matterSource}
}
