//go:build ignore

// Read-only compatibility experiment, not a runtime matcher or catalog importer.
// Invoked by review-banner-catalogs.py after checking pinned source hashes.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
)

type database struct {
	Patterns []fingerprint `xml:"fingerprint"`
}
type fingerprint struct {
	Pattern  string    `xml:"pattern,attr"`
	Examples []example `xml:"example"`
	Params   []param   `xml:"param"`
}
type example struct {
	Text  string     `xml:",chardata"`
	Attrs []xml.Attr `xml:",any,attr"`
}
type param struct {
	Name  string `xml:"name,attr"`
	Pos   int    `xml:"pos,attr"`
	Value string `xml:"value,attr"`
}
type result struct {
	SHA256            string   `json:"sha256"`
	Patterns          int      `json:"patterns"`
	Examples          int      `json:"examples"`
	CaptureAssertions int      `json:"capture_assertions"`
	OtherAssertions   int      `json:"other_assertions_not_evaluated"`
	MultipleMatches   int      `json:"examples_matching_multiple_patterns"`
	EarlierMatches    int      `json:"examples_matching_an_earlier_pattern"`
	Issues            []string `json:"issues"`
}

func inspect(path string) result {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var db database
	if err = xml.Unmarshal(data, &db); err != nil {
		panic(err)
	}
	out := result{SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Patterns: len(db.Patterns), Issues: []string{}}
	compiled := make([]*regexp.Regexp, len(db.Patterns))
	for i, f := range db.Patterns {
		compiled[i], err = regexp.Compile(f.Pattern)
		if err != nil {
			out.Issues = append(out.Issues, fmt.Sprintf("pattern %d fails Go compilation", i))
		}
	}
	for i, f := range db.Patterns {
		for j, ex := range f.Examples {
			out.Examples++
			if compiled[i] == nil {
				continue
			}
			match := compiled[i].FindStringSubmatch(ex.Text)
			if match == nil {
				out.Issues = append(out.Issues, fmt.Sprintf("pattern %d example %d does not match", i, j))
				continue
			}
			for _, attr := range ex.Attrs {
				checked := false
				for _, p := range f.Params {
					if p.Name != attr.Name.Local || p.Pos <= 0 || p.Value != "" {
						continue
					}
					checked = true
					out.CaptureAssertions++
					if p.Pos >= len(match) || match[p.Pos] != attr.Value {
						out.Issues = append(out.Issues, fmt.Sprintf("pattern %d example %d capture %s differs", i, j, attr.Name.Local))
					}
				}
				if !checked {
					out.OtherAssertions++
				}
			}
			matches, earlier := 0, false
			for k, re := range compiled {
				if re != nil && re.MatchString(ex.Text) {
					matches++
					earlier = earlier || k < i
				}
			}
			if matches > 1 {
				out.MultipleMatches++
			}
			if earlier {
				out.EarlierMatches++
			}
		}
	}
	return out
}
func main() {
	results := []result{}
	for _, path := range os.Args[1:] {
		results = append(results, inspect(path))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		panic(err)
	}
}
