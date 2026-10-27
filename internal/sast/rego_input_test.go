package sast

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

// What a rule sees through regoInput must be exactly what it saw through
// rego.Input, including text that is not valid UTF-8 and empty fields.
func TestRegoInputMatchesRegoInput(t *testing.T) {
	inputs := map[string]*ScanInput{
		"full": {
			FileSet:        map[string]bool{"a.py": true, "b.go": true, "latin1.txt": true},
			DirsByLanguage: map[string][]string{"go": {"."}, "python": {"svc", "."}},
			FileContents: map[string]string{
				"a.py":       "import os\nos.system(x)\n",
				"b.go":       "package main // <&>   tags",
				"latin1.txt": "caf\xe9 \xff\xfe end",
			},
			ScanRoot: "/repo",
		},
		"no contents":  {FileSet: map[string]bool{"x": true}, ScanRoot: "/r"},
		"empty fields": {},
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			terms, err := newRegoInput(in)
			require.NoError(t, err)
			require.Equal(t, 0, viaRegoInput(t, in).Compare(terms.value(in)))

			if len(in.FileContents) > 0 {
				scoped := scopedInput(in, scopeOf(`metadata := {"kind": "sast", "languages": ["python"]}`))
				require.Equal(t, 0, viaRegoInput(t, scoped).Compare(terms.value(scoped)),
					"a scoped job's input must match the scoped ScanInput")
			}
		})
	}
}

// viaRegoInput is the input document OPA builds from rego.Input.
func viaRegoInput(t *testing.T, in *ScanInput) ast.Value {
	t.Helper()
	rs, err := rego.New(rego.Query("x := input"), rego.Input(in)).Eval(context.Background())
	require.NoError(t, err)
	v, err := ast.InterfaceToValue(rs[0].Bindings["x"])
	require.NoError(t, err)
	return v
}

func TestJSONText(t *testing.T) {
	require.Equal(t, "plain", jsonText("plain"))
	require.Equal(t, "caf�", jsonText("caf\xe9"))
	require.Equal(t, "�� ok", jsonText("\xff\xfe ok"), "one replacement per invalid byte, as encoding/json does")
}
