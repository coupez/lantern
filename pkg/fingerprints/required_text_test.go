package fingerprints

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"reflect"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Preserve the previous exhaustive path as an oracle for rule selection,
// captured fields, input eligibility, and source/qualifier metadata.
func unfilteredLookup(field, input string) *Match {
	if field != SSHBanner && field != HTTPServer && field != FTPBanner && field != SMTPBanner && field != IMAPBanner && field != POP3Banner || input == "" || len(input) > MaxInputBytes || !utf8.ValidString(input) {
		return nil
	}
	eligible := input
	if field == IMAPBanner {
		eligible = strings.ReplaceAll(eligible, "\t", "")
	}
	if field == FTPBanner || field == SMTPBanner {
		eligible = strings.ReplaceAll(input, "\r\n", "")
	}
	for _, r := range eligible {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return nil
		}
	}
	logical := input
	if field == FTPBanner || field == SMTPBanner {
		logical = strings.ReplaceAll(input, "\r\n", "\n")
	}
	once.Do(initialize)
	for _, c := range catalogs {
		if c.Field != field {
			continue
		}
		for _, r := range c.Rules {
			captures := r.compiled.get(r.Pattern).FindStringSubmatchIndex(logical)
			if captures == nil {
				continue
			}
			if logical != input {
				for i, index := range captures {
					if index >= 0 {
						captures[i] += strings.Count(logical[:index], "\n")
					}
				}
			}
			return &Match{Name: r.Name, Field: field, Input: input, Catalog: "Rapid7 Recog", Reference: fmt.Sprintf("%s#L%d", c.Source, r.Line), Certainty: r.Certainty, Preference: c.Preference, Fields: evaluate(r, captures, input, c.Protocol)}
		}
	}
	return nil
}
func TestRequiredTextGrammar(t *testing.T) {
	cases := []struct {
		pattern string
		inputs  []string
	}{
		{`^foo(?:LONGOPTIONAL)?$`, []string{"foo", "fooLONGOPTIONAL", "LONGOPTIONAL"}},
		{`^(?:foo|bar)$`, []string{"foo", "bar", "foobar"}},
		{`^(?:foo)*bar$`, []string{"bar", "foobar", "foofoobar"}},
		{`^(?:foo)+bar$`, []string{"foobar", "foofoobar"}},
		{`^(?:foo){2,4}bar$`, []string{"foofoobar", "foofoofoobar"}},
		{`^(?:foo){0,4}bar$`, []string{"bar", "foofoobar"}},
		{`(?i)^Kelvin/Server$`, []string{"Kelvin/Server", "Kelvin/ſerver", "KELVIN/SERVER"}},
		{`(?i)^123-東京abc$`, []string{"123-東京abc", "123-東京ABC"}},
		{`(?s)^foo.*bar$`, []string{"foobar", "foo\nbar"}},
		{`(?m)^foo$`, []string{"foo", "a\nfoo\nb"}},
		{`(?:^|x)foo`, []string{"foo", "xxfoo"}},
		{`foo|`, []string{"", "foo", "bar"}},
		{`^�$`, []string{"�", "\xff"}},
		{`^[[:alpha:]]{1,3}/v[0-9]+$`, []string{"Ab/v1", "XYZ/v42"}},
	}
	for _, tc := range cases {
		tree, err := syntax.Parse(tc.pattern, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		literal := requiredText(tree)
		compiled := regexp.MustCompile(tc.pattern)
		for _, input := range tc.inputs {
			if compiled.MatchString(input) && literal != "" && !strings.Contains(input, literal) {
				t.Fatalf("%q requires %q but matches %q", tc.pattern, literal, input)
			}
		}
	}
}
func TestRequiredTextCatalogDifferential(t *testing.T) {
	fixture, err := os.ReadFile("testdata/examples.json.gz")
	if err != nil {
		t.Fatal(err)
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
	var groups []struct {
		Field    string
		Examples []struct{ Input string }
	}
	if err := json.Unmarshal(raw, &groups); err != nil {
		t.Fatal(err)
	}
	compare := func(field, input string) {
		t.Helper()
		got, want := Lookup(field, input), unfilteredLookup(field, input)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s %q: got %+v; want %+v", field, input, got, want)
		}
	}
	checked := 0
	for _, group := range groups {
		for _, ex := range group.Examples {
			variants := []string{ex.Input, strings.ToLower(ex.Input), strings.ToUpper(ex.Input), "prefix " + ex.Input, ex.Input + " suffix", ex.Input + "\x1b", ex.Input + "\u202e", strings.ReplaceAll(strings.ReplaceAll(ex.Input, "S", "ſ"), "K", "K")}
			if len(ex.Input) > 0 {
				variants = append(variants, ex.Input[1:], ex.Input[:len(ex.Input)-1])
			}
			for _, input := range variants {
				compare(group.Field, input)
				checked++
			}
		}
	}
	for r := rune(0); r < 256; r++ {
		compare(HTTPServer, "Apache/2.4.65"+string(r))
	}
	rng := rand.New(rand.NewSource(314159))
	alphabet := []rune("abcXYZ09 /.-_()Kſ東京\u202e\n")
	for range 1024 {
		runes := make([]rune, rng.Intn(80))
		for i := range runes {
			runes[i] = alphabet[rng.Intn(len(alphabet))]
		}
		input := string(runes)
		compare(HTTPServer, input)
		compare(SSHBanner, input)
	}
	for _, input := range []string{strings.Repeat("x", 2048), strings.Repeat("x", 2000) + "-EmWeb/", strings.Repeat("x", 2049), "\xff"} {
		compare(HTTPServer, input)
		compare(SSHBanner, input)
	}
	t.Logf("checked %d example variants plus Latin-1, seeded mixed-Unicode inputs, and length boundaries", checked)
}

func FuzzRequiredText(f *testing.F) {
	for _, seed := range []struct{ pattern, input string }{{`foo|bar`, "bar"}, {`(?i)Kelvin/Server`, "Kelvin/ſerver"}, {`(?:foo)*bar`, "bar"}, {`^a.*z$`, "abz"}} {
		f.Add(seed.pattern, seed.input)
	}
	f.Fuzz(func(t *testing.T, pattern, input string) {
		if len(pattern) > 128 || len(input) > 256 {
			return
		}
		tree, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			return
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		literal := requiredText(tree)
		if literal != "" && re.MatchString(input) && !strings.Contains(input, literal) {
			t.Fatalf("%q matches %q without required %q", pattern, input, literal)
		}
	})
}
