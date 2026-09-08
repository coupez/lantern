package scanner

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed data/cast-models.json
var castModelData []byte
var castOnce sync.Once
var castCatalog struct {
	Source struct {
		URL string `json:"url"`
	} `json:"source"`
	Models map[string]struct {
		Manufacturer string `json:"manufacturer"`
		CastType     string `json:"cast_type"`
	} `json:"models"`
}

func castManufacturer(model string) (string, string) {
	castOnce.Do(func() {
		if err := json.Unmarshal(castModelData, &castCatalog); err != nil {
			panic(err)
		}
	})
	match, ok := castCatalog.Models[strings.ToLower(strings.TrimSpace(model))]
	if !ok {
		return "", ""
	}
	return match.Manufacturer, castCatalog.Source.URL
}
