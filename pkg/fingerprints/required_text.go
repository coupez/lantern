package fingerprints

import (
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// requiredText returns a literal byte sequence contained in every match, or an
// empty string when none is established. It is only a rejection precheck; the
// original regex remains authoritative and retains its captures and ordering.
func requiredText(expression *syntax.Regexp) string {
	switch expression.Op {
	case syntax.OpLiteral:
		// Case-insensitive literals can match Unicode fold equivalents. Only retain
		// runs whose runes have no alternate fold, rather than lowercasing the input.
		// RuneError is excluded because regexes also match malformed bytes with it.
		var run strings.Builder
		best := ""
		finish := func() {
			if run.Len() > len(best) {
				best = run.String()
			}
			run.Reset()
		}
		for _, r := range expression.Rune {
			if r == utf8.RuneError || expression.Flags&syntax.FoldCase != 0 && unicode.SimpleFold(r) != r {
				finish()
				continue
			}
			run.WriteRune(r)
		}
		finish()
		return best
	case syntax.OpCapture, syntax.OpPlus:
		return requiredText(expression.Sub[0])
	case syntax.OpRepeat:
		if expression.Min > 0 {
			return requiredText(expression.Sub[0])
		}
	case syntax.OpConcat:
		best := ""
		for _, child := range expression.Sub {
			if text := requiredText(child); len(text) > len(best) {
				best = text
			}
		}
		return best
	}
	// Alternation, optional/zero repetitions, character classes, and zero-width
	// assertions contribute no proven required text. Their enclosing concat may.
	return ""
}
