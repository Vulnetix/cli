package sast

import (
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want float64 // -1 means "just assert >= threshold via min"
		min  float64
	}{
		{name: "empty", in: "", want: 0},
		{name: "single repeated char", in: "aaaaaa", want: 0},
		{name: "all zeros", in: "0000000000", want: 0},
		{name: "two symbols equal", in: "abab", want: 1.0},
		{name: "four symbols equal", in: "abcd", want: 2.0},
		{name: "example placeholder low-ish", in: "AKIAIOSFODNN7EXAMPLE", min: 2.5},
		{name: "real-looking base64 high", in: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", min: 4.0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := shannonEntropy(c.in)
			if c.min > 0 {
				if got < c.min {
					t.Fatalf("shannonEntropy(%q) = %f, want >= %f", c.in, got, c.min)
				}
				return
			}
			if math.Abs(got-c.want) > 1e-9 {
				t.Fatalf("shannonEntropy(%q) = %f, want %f", c.in, got, c.want)
			}
		})
	}
}

// TestEntropyBuiltinThroughEngine proves the custom builtin resolves through
// the split compile (ast.NewCompiler) + eval (rego.New) path used by Engine.
func TestEntropyBuiltinThroughEngine(t *testing.T) {
	rule := `package vulnetix.rules.test_entropy

import rego.v1

metadata := {"id": "TEST-ENTROPY", "kind": "secrets", "severity": "high"}

findings contains finding if {
	some path in object.keys(input.file_contents)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	token := line
	vulnetix.shannon_entropy(token) >= 4.0
	finding := {
		"rule_id": metadata.id,
		"message": "high entropy",
		"artifact_uri": path,
		"start_line": i + 1,
		"snippet": line,
	}
}
`
	eng := NewEngine(map[string]string{"test_entropy.rego": rule}, t.TempDir())
	compiler, err := eng.compile()
	if err != nil {
		t.Fatalf("compile with custom builtin failed: %v", err)
	}
	if compiler.Failed() {
		t.Fatalf("compiler reported failure: %v", compiler.Errors)
	}

	rules, err := eng.ListRules()
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.ID == "TEST-ENTROPY" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected TEST-ENTROPY rule to load; got %d rules", len(rules))
	}
}
