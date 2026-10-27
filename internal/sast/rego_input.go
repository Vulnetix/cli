package sast

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/util"
)

// regoInput is a ScanInput converted to Rego terms once and shared by every
// job that evaluates it.
//
// rego.Input(*ScanInput) converts on every Eval: OPA marshals the struct to
// JSON, unmarshals it into a map and builds AST terms from that, three copies
// of every file's text per job. A sast run has one job per scope group and
// shard, more than a hundred with the external packs, up to 16 at once, and
// that was most of a 7 GB peak on vdb-manager. Here each file's text becomes
// one string term, and each job's input is an object of pointers to the
// shared terms.
type regoInput struct {
	// base holds file_set, dirs_by_language and scan_root, converted through
	// the same JSON path rego.Input uses, so those fields are identical.
	base     ast.Object
	contents map[string]*ast.Term
}

var fileContentsKey = ast.StringTerm("file_contents")

func newRegoInput(in *ScanInput) (*regoInput, error) {
	var raw any = &ScanInput{FileSet: in.FileSet, DirsByLanguage: in.DirsByLanguage, ScanRoot: in.ScanRoot}
	if err := util.RoundTrip(&raw); err != nil {
		return nil, fmt.Errorf("convert scan input: %w", err)
	}
	v, err := ast.InterfaceToValue(raw)
	if err != nil {
		return nil, fmt.Errorf("convert scan input: %w", err)
	}
	base, ok := v.(ast.Object)
	if !ok {
		return nil, fmt.Errorf("convert scan input: got %T, want an object", v)
	}
	contents := make(map[string]*ast.Term, len(in.FileContents))
	for p, c := range in.FileContents {
		contents[p] = ast.StringTerm(jsonText(c))
	}
	return &regoInput{base: base, contents: contents}, nil
}

// value is the input document for a job that may read the files of `in`,
// which is the ScanInput the terms were made from or a scopedInput of it.
func (r *regoInput) value(in *ScanInput) ast.Value {
	// A new object over the shared terms: Object.Copy would deep-copy file_set.
	obj := ast.NewObject()
	r.base.Foreach(func(k, v *ast.Term) { obj.Insert(k, v) })
	if len(in.FileContents) == 0 {
		return obj // file_contents is omitempty in ScanInput's JSON
	}
	files := ast.NewObject()
	for p := range in.FileContents {
		files.Insert(ast.StringTerm(p), r.contents[p])
	}
	obj.Insert(fileContentsKey, ast.NewTerm(files))
	return obj
}

// jsonText is s as it reads after a JSON round trip, which is what rules saw
// when the input went through rego.Input: each byte of an invalid UTF-8
// sequence becomes U+FFFD. Valid text, nearly every file, is returned as is.
func jsonText(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune(utf8.RuneError)
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}
