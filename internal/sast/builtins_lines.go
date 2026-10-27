package sast

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"unsafe"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/types"
)

// Line builtins: the secret rules' hot loop, computed in Go.
//
// Every generated secret rule split a file into lines and asked of each line
// whether it holds one of the rule's keywords, or matches its pattern. Over a
// file that passes the rule's file-level gate (an 88 KB workflow that says
// "secret" on many lines) that was some 2,000 interpreted iterations, about
// 180 ms per rule, and there are more than a thousand such rules. These
// builtins answer the same questions in one call and hand back only the lines
// that pass, so a rule iterates the handful of lines it can report on.
//
// Each builtin is defined by the Rego it replaces and must stay exactly that:
//
//	vulnetix.contains_any_fold(s, kws)    some k in kws; contains(lower(s), k)
//	vulnetix.keyword_lines(text, kws)     {i: line | some i, line in split(text, "\n"); contains_any_fold(line, kws)}
//	vulnetix.pattern_lines(text, pattern) {i: line | some i, line in split(text, "\n"); regex.match(pattern, line)}
//
// TestLineBuiltinsMatchRego checks each against that Rego.

func registerLineBuiltins() {
	collection := types.NewAny(types.NewArray(nil, types.A), types.NewSet(types.A), types.NewObject(nil, types.NewDynamicProperty(types.A, types.A)))
	lineObject := types.NewObject(nil, types.NewDynamicProperty(types.N, types.S))

	rego.RegisterBuiltin2(
		&rego.Function{
			Name:        "vulnetix.contains_any_fold",
			Description: "Whether lower(s) contains any string in kws.",
			Decl:        types.NewFunction(types.Args(types.S, collection), types.B),
		},
		func(bctx rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
			s, err := builtins.StringOperand(a.Value, 1)
			if err != nil {
				return nil, err
			}
			kws, err := stringMembers(b.Value)
			if err != nil {
				return nil, err
			}
			return ast.BooleanTerm(containsAnyFold(lowerOf(bctx, string(s)), kws)), nil
		},
	)

	rego.RegisterBuiltin2(
		&rego.Function{
			Name:        "vulnetix.keyword_lines",
			Description: `The lines of split(text, "\n"), keyed by index, whose lower case contains any string in kws.`,
			Decl:        types.NewFunction(types.Args(types.S, collection), lineObject),
		},
		func(_ rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
			text, err := builtins.StringOperand(a.Value, 1)
			if err != nil {
				return nil, err
			}
			kws, err := stringMembers(b.Value)
			if err != nil {
				return nil, err
			}
			return selectLines(string(text), func(line string) bool {
				return containsAnyFold(strings.ToLower(line), kws)
			}), nil
		},
	)

	rego.RegisterBuiltin2(
		&rego.Function{
			Name:        "vulnetix.pattern_lines",
			Description: `The lines of split(text, "\n"), keyed by index, that the regular expression pattern matches.`,
			Decl:        types.NewFunction(types.Args(types.S, types.S), lineObject),
		},
		func(_ rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
			text, err := builtins.StringOperand(a.Value, 1)
			if err != nil {
				return nil, err
			}
			pat, err := builtins.StringOperand(b.Value, 2)
			if err != nil {
				return nil, err
			}
			re, err := compiledPattern(string(pat))
			if err != nil {
				return nil, err
			}
			return selectLines(string(text), re.MatchString), nil
		},
	)
}

// stringMembers is the string members of a collection, in the order `some k
// in c` visits them. A member that is not a string is left out: contains()
// on it is a type error, which leaves that iteration undefined.
func stringMembers(v ast.Value) ([]string, error) {
	var out []string
	add := func(t *ast.Term) {
		if s, ok := t.Value.(ast.String); ok {
			out = append(out, string(s))
		}
	}
	switch c := v.(type) {
	case *ast.Array:
		c.Foreach(add)
	case ast.Set:
		c.Foreach(add)
	case ast.Object:
		c.Foreach(func(_, v *ast.Term) { add(v) })
	default:
		return nil, errors.New("operand 2 must be one of {array, set, object}")
	}
	return out, nil
}

func containsAnyFold(low string, kws []string) bool {
	for _, k := range kws {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}

// selectLines splits text as OPA's split(text, "\n") does and keeps the lines
// keep accepts, keyed by their index in that split.
func selectLines(text string, keep func(string) bool) *ast.Term {
	obj := ast.NewObject()
	i := 0
	for line := range strings.SplitSeq(text, "\n") {
		if keep(line) {
			obj.Insert(ast.InternedTerm(i), ast.StringTerm(line))
		}
		i++
	}
	return ast.NewTerm(obj)
}

// lowerMemoMin is the shortest string whose lower case is kept for the rest of
// one evaluation. A file's text is lowered by every rule that gates on its
// keywords; a line is cheaper to lower again than to look up.
const lowerMemoMin = 4 << 10

// lowerKey identifies a string by where its bytes are. The memo entry holds
// the string itself, so those bytes cannot be freed and reused by a different
// string while the entry exists.
type lowerKey struct {
	p *byte
	n int
}

type lowerEntry struct {
	src, low string
}

// lowerOf is strings.ToLower(s), computed once per evaluation for a long s.
func lowerOf(bctx rego.BuiltinContext, s string) string {
	if len(s) < lowerMemoMin || bctx.Cache == nil {
		return strings.ToLower(s)
	}
	k := lowerKey{unsafe.StringData(s), len(s)}
	if v, ok := bctx.Cache.Get(k); ok {
		return v.(lowerEntry).low
	}
	low := strings.ToLower(s)
	bctx.Cache.Put(k, lowerEntry{src: s, low: low})
	return low
}

var patternCache sync.Map // pattern → *regexp.Regexp or error

// compiledPattern compiles pat as OPA's regex builtins do (regexp.Compile),
// once per process.
func compiledPattern(pat string) (*regexp.Regexp, error) {
	if v, ok := patternCache.Load(pat); ok {
		if re, ok := v.(*regexp.Regexp); ok {
			return re, nil
		}
		return nil, v.(error)
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		patternCache.Store(pat, err)
		return nil, err
	}
	patternCache.Store(pat, re)
	return re, nil
}
