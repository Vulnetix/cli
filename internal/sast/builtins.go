package sast

import (
	"math"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/types"
)

// init registers Vulnetix-specific OPA builtins so that every Rego rule —
// embedded or external — can call them. Registration is global (it mutates
// the OPA builtin registry consulted both by ast.NewCompiler's type checker
// and by the topdown evaluator), so it must happen before any Engine.compile
// runs. Doing it in init() guarantees that ordering and makes it idempotent.
//
// We keep the custom-builtin surface minimal: the only thing pure Rego cannot
// express is Shannon entropy, so that is the only computation exported here.
// Allowlist/stopword/path logic stays in Rego (see rules/_lib/lib_secrets.rego)
// where it is auditable and extensible per rule without a binary rebuild.
func init() {
	registerEntropyBuiltin()
}

// registerEntropyBuiltin exposes vulnetix.shannon_entropy(string) -> number,
// returning the Shannon entropy (in bits per character) of the input's byte
// distribution. High-fidelity secret rules use it to suppress low-entropy
// false positives (e.g. "password", "0000000000") while keeping real
// high-entropy credentials.
func registerEntropyBuiltin() {
	rego.RegisterBuiltin1(
		&rego.Function{
			Name:             "vulnetix.shannon_entropy",
			Description:      "Shannon entropy (bits per character) of a string's byte distribution.",
			Decl:             types.NewFunction(types.Args(types.S), types.N),
			Nondeterministic: false, // pure function of its input → safe to memoize
		},
		func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
			s, err := builtins.StringOperand(a.Value, 1)
			if err != nil {
				return nil, err
			}
			return ast.FloatNumberTerm(shannonEntropy(string(s))), nil
		},
	)
}

// shannonEntropy computes the Shannon entropy in bits per character over the
// byte distribution of s. Empty strings have zero entropy.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
