package models

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

//go:embed data/matter-models.json.gz
var matterData []byte

//go:embed data/matter-sources.json
var matterSourceData []byte
var matterOnce sync.Once
var matterIndex map[string][]record
var matterSource Source

func loadMatter() {
	matterOnce.Do(func() {
		r, err := gzip.NewReader(bytes.NewReader(matterData))
		if err != nil {
			panic(err)
		}
		defer r.Close()
		data, err := io.ReadAll(r)
		if err != nil {
			panic(err)
		}
		if err := json.Unmarshal(data, &matterIndex); err != nil {
			panic(err)
		}
		if err := json.Unmarshal(matterSourceData, &matterSource); err != nil {
			panic(err)
		}
	})
}

// MatterIdentifier creates a namespace-qualified vendor/product pair. Neither
// ID alone identifies a product; these values are not link-layer MAC prefixes.
func MatterIdentifier(vendorID, productID uint16) string {
	return fmt.Sprintf("matter:%d:%d", vendorID, productID)
}

// LookupMatter returns independent label candidates for an exact Matter pair.
// SmartThings labels can be generic or ambiguous; they are not authentication,
// certification, or device-reported retail model/manufacturer information.
func LookupMatter(vendorID, productID uint16) []Match {
	loadMatter()
	result := []Match{}
	for _, r := range matterIndex[MatterIdentifier(vendorID, productID)] {
		result = append(result, Match{Identifier: r.Identifier, Name: r.Name, Type: "Matter product", Catalog: matterSource.Name,
			Source: matterSource.URL + "/blob/" + matterSource.Commit + "/" + r.Path, SHA256: r.SHA256})
	}
	return result
}

func lookupMatterIdentifier(raw string) []Match {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(raw)), ":")
	if len(parts) != 3 || parts[0] != "matter" {
		return []Match{}
	}
	ids := [2]uint16{}
	for i, part := range parts[1:] {
		value, err := strconv.ParseUint(part, 10, 16)
		if err != nil || strconv.FormatUint(value, 10) != part {
			return []Match{}
		}
		ids[i] = uint16(value)
	}
	return LookupMatter(ids[0], ids[1])
}
