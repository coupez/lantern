// Package fingerprints interprets observed banner fields using a pinned offline
// catalog. Matches are unauthenticated catalog claims, not hardware identities.
package fingerprints

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const SSHBanner = "ssh.banner"
const HTTPServer = "http_header.server"
const MaxInputBytes = 2048

//go:embed data/recog.json.gz
var data []byte

// Sources is JSON provenance for the embedded BSD-2-Clause Recog catalog.
//
//go:embed data/sources.json
var Sources string

// Match and Fields are caller-owned. Namespaced fields retain upstream scopes;
// service.vendor, os.vendor, and hw.vendor must not be conflated.
type Match struct {
	Name      string `json:"name"`
	Field     string `json:"field"`
	Input     string `json:"input"`
	Catalog   string `json:"catalog"`
	Reference string `json:"reference"`
	// Certainty and Preference are catalog metadata, not measured probabilities.
	Certainty  string            `json:"certainty,omitempty"`
	Preference string            `json:"preference,omitempty"`
	Fields     map[string]string `json:"fields"`
}

func (m *Match) Clone() *Match {
	if m == nil {
		return nil
	}
	copy := *m
	copy.Fields = maps.Clone(m.Fields)
	return &copy
}

// Summary returns a service label when available, otherwise the rule description.
func (m *Match) Summary() string {
	if m == nil {
		return ""
	}
	product := m.Fields["service.product"]
	if product == "" {
		return m.Name
	}
	vendor := m.Fields["service.vendor"]
	if vendor != "" && !strings.HasPrefix(strings.ToLower(product), strings.ToLower(vendor)) {
		product = vendor + " " + product
	}
	if version := m.Fields["service.version"]; version != "" {
		product += " " + version
	}
	return product
}

type parameter struct {
	Name  string `json:"name"`
	Pos   int    `json:"pos"`
	Value string `json:"value"`
}
type rule struct {
	Pattern   string      `json:"pattern"`
	Name      string      `json:"name"`
	Line      int         `json:"line"`
	Certainty string      `json:"certainty"`
	Params    []parameter `json:"params"`
	re        *regexp.Regexp
}
type catalog struct {
	Field      string `json:"field"`
	Protocol   string `json:"protocol"`
	Preference string `json:"preference"`
	Source     string `json:"source"`
	Rules      []rule `json:"rules"`
}

var once sync.Once
var catalogs []catalog
var placeholder = regexp.MustCompile(`\{([^\s{}]+)\}`)

func initialize() {
	z, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		panic(err)
	}
	raw, err := io.ReadAll(z)
	z.Close()
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(raw, &catalogs); err != nil {
		panic(err)
	}
	for i := range catalogs {
		for j := range catalogs[i].Rules {
			r := &catalogs[i].Rules[j]
			r.re = regexp.MustCompile(r.Pattern)
			for _, p := range r.Params {
				if p.Pos < 0 || p.Pos > r.re.NumSubexp() {
					panic("invalid embedded fingerprint capture")
				}
			}
		}
	}
}
func Count() int {
	once.Do(initialize)
	n := 0
	for _, c := range catalogs {
		n += len(c.Rules)
	}
	return n
}

// Lookup matches one extracted field, preserving catalog order. SSH input is
// software/comment text after SSH-<version>-, and HTTP input is a Server value.
// Unsupported fields, empty/oversized inputs, invalid UTF-8, and controls fail
// closed. No network requests or upstream executable code are used.
func Lookup(field, input string) *Match {
	if field != SSHBanner && field != HTTPServer || input == "" || len(input) > MaxInputBytes || !utf8.ValidString(input) {
		return nil
	}
	for _, r := range input {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return nil
		}
	}
	once.Do(initialize)
	for _, c := range catalogs {
		if c.Field != field {
			continue
		}
		for _, r := range c.Rules {
			captures := r.re.FindStringSubmatchIndex(input)
			if captures == nil {
				continue
			}
			return &Match{Name: r.Name, Field: field, Input: input, Catalog: "Rapid7 Recog",
				Reference: fmt.Sprintf("%s#L%d", c.Source, r.Line), Certainty: r.Certainty,
				Preference: c.Preference, Fields: evaluate(r, captures, input, c.Protocol)}
		}
	}
	return nil
}

// Expand only catalog templates, never text introduced by captured input. Missing
// optional versions become '-' in CPE fields; unresolved other fields are omitted.
// Compound version keys and certainty qualifiers retain their source names.
func evaluate(r rule, captures []int, input, protocol string) map[string]string {
	values := make(map[string]string, len(r.Params)+1)
	templates := make(map[string]string)
	for _, p := range r.Params {
		if p.Pos == 0 {
			templates[p.Name] = p.Value
			continue
		}
		start, end := captures[p.Pos*2], captures[p.Pos*2+1]
		if start >= 0 {
			values[p.Name] = input[start:end]
		}
	}
	visiting := make(map[string]bool)
	var resolve func(string) (string, bool)
	resolve = func(key string) (string, bool) {
		if value, ok := values[key]; ok {
			return value, true
		}
		template, ok := templates[key]
		if !ok || visiting[key] {
			return "", false
		}
		visiting[key] = true
		valid := true
		value := placeholder.ReplaceAllStringFunc(template, func(token string) string {
			target := token[1 : len(token)-1]
			if replacement, found := resolve(target); found {
				return replacement
			}
			if strings.HasSuffix(key, ".cpe23") && strings.HasSuffix(target, ".version") {
				return "-"
			}
			valid = false
			return ""
		})
		delete(visiting, key)
		if valid {
			values[key] = value
		}
		return value, valid
	}
	for key := range templates {
		resolve(key)
	}
	for key := range values {
		if strings.HasPrefix(key, "_tmp.") {
			delete(values, key)
		}
	}
	if _, ok := values["service.protocol"]; !ok {
		values["service.protocol"] = protocol
	}
	return values
}
