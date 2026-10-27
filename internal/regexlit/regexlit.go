// Package regexlit decides cheaply that a regular expression cannot match a
// text, so the expression is not run.
//
// Most catalog patterns (an import statement, an API call) have no literal
// prefix, so Go's regexp runs its automaton over every byte of every file even
// though the match would have to contain a word such as "openai". A Filter
// holds such words, derived from the pattern's syntax tree: every match of the
// pattern contains at least one of them. When a text holds none, the pattern
// cannot match it and is skipped. When nothing can be derived, the filter lets
// every text through. A filter therefore only ever skips work whose answer
// was "no match"; TestFilterNeverHidesAMatch checks that on random texts.
package regexlit

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
)

// minLiteral is the shortest required literal worth testing for: a one- or
// two-byte string is in nearly every file.
const minLiteral = 3

// Filter is the literals one of which every match of a pattern contains.
type Filter struct {
	lits []lit // nil: no prefilter, every text may match
}

type lit struct {
	s string
	// fold: the literal matches ASCII case-insensitively, and s is lower case.
	fold bool
}

// For returns the filter of re, or a filter that passes every text when no
// literal can be derived. The result is cached per expression.
func For(re *regexp.Regexp) *Filter {
	if f, ok := filters.Load(re); ok {
		return f.(*Filter)
	}
	f := build(re.String())
	filters.Store(re, f)
	return f
}

var filters sync.Map // *regexp.Regexp → *Filter

func build(expr string) *Filter {
	tree, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return &Filter{}
	}
	lits, ok := required(tree.Simplify())
	if !ok {
		return &Filter{}
	}
	for _, l := range lits {
		if len(l.s) < minLiteral {
			return &Filter{}
		}
	}
	return &Filter{lits: lits}
}

// required is literals at least one of which every match of re contains, and
// whether any could be derived.
func required(re *syntax.Regexp) ([]lit, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return literal(re)
	case syntax.OpCapture:
		return required(re.Sub[0])
	case syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
		return nil, false
	case syntax.OpConcat:
		// A match contains a match of every part, so any part's literals
		// will do; take the part whose shortest literal is longest.
		var best []lit
		bestLen := -1
		for _, sub := range re.Sub {
			ls, ok := required(sub)
			if !ok {
				continue
			}
			if m := shortest(ls); m > bestLen {
				best, bestLen = ls, m
			}
		}
		return best, best != nil
	case syntax.OpAlternate:
		// A match is a match of one alternative: every alternative must
		// require a literal, and any of those literals may be the one.
		var all []lit
		for _, sub := range re.Sub {
			ls, ok := required(sub)
			if !ok {
				return nil, false
			}
			all = append(all, ls...)
		}
		return all, true
	}
	return nil, false
}

// literal is a literal node's string. A case-insensitive literal is usable
// only when every rune is an ASCII letter or other byte whose case fold stays
// in ASCII: Go folds k to the Kelvin sign and s to the long s, which an ASCII
// lower case of the text would miss.
func literal(re *syntax.Regexp) ([]lit, bool) {
	s := string(re.Rune)
	if re.Flags&syntax.FoldCase == 0 {
		return []lit{{s: s}}, true
	}
	for _, r := range re.Rune {
		if r >= 0x80 {
			return nil, false
		}
		switch r {
		case 'k', 'K', 's', 'S':
			return nil, false
		}
	}
	return []lit{{s: asciiLower(s), fold: true}}, true
}

func shortest(ls []lit) int {
	m := -1
	for _, l := range ls {
		if m < 0 || len(l.s) < m {
			m = len(l.s)
		}
	}
	return m
}

// Text is a text tested against many filters; its ASCII lower case is
// computed once, on first need.
type Text struct {
	s     string
	low   string
	lowed bool
}

// NewText wraps s for filtering.
func NewText(s string) *Text { return &Text{s: s} }

// String is the text itself.
func (t *Text) String() string { return t.s }

// MatchString is re.MatchString(t), skipped when the filter rules a match out.
func MatchString(re *regexp.Regexp, t *Text) bool {
	return For(re).MayMatch(t) && re.MatchString(t.s)
}

func (t *Text) lower() string {
	if !t.lowed {
		t.low, t.lowed = asciiLower(t.s), true
	}
	return t.low
}

// MayMatch reports whether the pattern could match t. False means it cannot.
func (f *Filter) MayMatch(t *Text) bool {
	if f == nil || f.lits == nil {
		return true
	}
	for _, l := range f.lits {
		if l.fold {
			if strings.Contains(t.lower(), l.s) {
				return true
			}
		} else if strings.Contains(t.s, l.s) {
			return true
		}
	}
	return false
}

// MayMatchString is MayMatch for a text tested against one filter only.
func (f *Filter) MayMatchString(s string) bool {
	if f == nil || f.lits == nil {
		return true
	}
	return f.MayMatch(&Text{s: s})
}

// asciiLower maps A-Z to a-z and leaves every other byte alone, so offsets
// and every non-ASCII byte are unchanged.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; 'A' <= c && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if 'A' <= b[j] && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}
