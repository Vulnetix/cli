package sast

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	libModule     = "package vulnetix.lib\n\nimport rego.v1\n\nneedle := \"NEEDLE\"\n"
	sastModule    = `package vulnetix.rules.a` + "\n" + `metadata := {"id": "VNX-0001", "kind": "sast"}` + "\n"
	secretsModule = `package vulnetix.rules.b` + "\n" + `metadata := {"id": "VNX-0002", "kind": "secrets"}` + "\n"
	ociModule     = `package vulnetix.rules.c` + "\n" + `metadata := {"id": "VNX-0003", "kind": "oci"}` + "\n"
	iacModule     = `package vulnetix.rules.d` + "\n" + `metadata := {"id": "VNX-0004", "kind": "iac"}` + "\n"
	noKindModule  = `package vulnetix.rules.e` + "\n" + `metadata := {"id": "VNX-0005"}` + "\n"
)

func sampleModules() map[string]string {
	return map[string]string{
		"rules/lib.rego":     libModule,
		"rules/a.rego":       sastModule,
		"rules/b.rego":       secretsModule,
		"rules/c.rego":       ociModule,
		"rules/d.rego":       iacModule,
		"rules/e.rego":       noKindModule,
		"external/pack.rego": secretsModule,
	}
}

func TestExtractRegoKind(t *testing.T) {
	require.Equal(t, KindSAST, ExtractRegoKind(sastModule))
	require.Equal(t, KindSecrets, ExtractRegoKind(secretsModule))
	require.Equal(t, KindOCI, ExtractRegoKind(ociModule))
	require.Equal(t, KindIAC, ExtractRegoKind(iacModule))
}

func TestModulesWithoutAKindDefaultToSast(t *testing.T) {
	// Every rule was written against this default; changing it would silently
	// reclassify rules that never declared a kind.
	require.Equal(t, KindSAST, ExtractRegoKind(noKindModule))
	require.Equal(t, KindSAST, ExtractRegoKind(libModule))
	require.Equal(t, KindSAST, ExtractRegoKind(""))
}

func TestExtractRegoID(t *testing.T) {
	require.Equal(t, "VNX-0001", ExtractRegoID(sastModule))
	require.Empty(t, ExtractRegoID(libModule), "a library declares no id")
	require.Empty(t, ExtractRegoID(""))
}

func TestIsRuleModule(t *testing.T) {
	require.True(t, IsRuleModule(sastModule))
	require.False(t, IsRuleModule(libModule))
}

func TestFilterModulesToKindsKeepsLibraries(t *testing.T) {
	// OPA compiles every module together, so dropping a library that a kept
	// rule imports fails the whole evaluation rather than just losing a rule.
	got := FilterModulesToKinds(sampleModules(), []string{KindOCI})
	require.Contains(t, got, "rules/lib.rego", "libraries must survive any kind filter")
	require.Contains(t, got, "rules/c.rego")
	require.NotContains(t, got, "rules/a.rego")
	require.NotContains(t, got, "rules/b.rego")
}

func TestFilterModulesToKindsAppliesToExternalPacks(t *testing.T) {
	// A locked specialized subcommand scopes every rule regardless of origin,
	// so `containers --rule <pack>` never bleeds into that pack's secrets
	// rules. This is the documented difference from FilterModulesByKind.
	got := FilterModulesToKinds(sampleModules(), []string{KindOCI})
	require.NotContains(t, got, "external/pack.rego")
}

func TestFilterModulesToKindsEmptyMeansNoLock(t *testing.T) {
	in := sampleModules()
	require.Len(t, FilterModulesToKinds(in, nil), len(in))
	require.Len(t, FilterModulesToKinds(in, []string{}), len(in))
}

func TestFilterModulesByKindExemptsExternalPacks(t *testing.T) {
	// The user asked for these explicitly by passing --rule, so a feature
	// toggle does not silently discard them.
	got := FilterModulesByKind(sampleModules(), false, true, false, false)
	require.Contains(t, got, "external/pack.rego", "external packs bypass the feature filter")
	require.NotContains(t, got, "rules/b.rego", "embedded secrets rules are filtered")
}

func TestFilterModulesByKindNoFlagsIsIdentity(t *testing.T) {
	in := sampleModules()
	require.Len(t, FilterModulesByKind(in, false, false, false, false), len(in))
}

func TestFilterModulesByKindFiltersEachKind(t *testing.T) {
	all := sampleModules()
	require.NotContains(t, FilterModulesByKind(all, true, false, false, false), "rules/a.rego")
	require.NotContains(t, FilterModulesByKind(all, false, true, false, false), "rules/b.rego")
	require.NotContains(t, FilterModulesByKind(all, false, false, true, false), "rules/c.rego")
	require.NotContains(t, FilterModulesByKind(all, false, false, false, true), "rules/d.rego")

	// A module with no declared kind is filtered as sast.
	require.NotContains(t, FilterModulesByKind(all, true, false, false, false), "rules/e.rego")
}

func TestFilterModulesByID(t *testing.T) {
	got := FilterModulesByID(sampleModules(), "vnx-0003")
	require.Len(t, got, 1, "single-rule mode keeps exactly one module")
	require.Contains(t, got, "rules/c.rego")

	in := sampleModules()
	require.Len(t, FilterModulesByID(in, ""), len(in), "an empty id means no filter")
	require.Empty(t, FilterModulesByID(in, "VNX-9999"))
}

// TestEmbeddedCorpusKindDistribution pins the shape the language server's
// scheduling depends on. The keystroke path skips secrets because they are the
// overwhelming majority and cost roughly 20x the rest combined; if that ratio
// ever inverts, the kind split stops being the right lever and this fails.
func TestEmbeddedCorpusKindDistribution(t *testing.T) {
	modules, err := LoadAllModules(DefaultRulesFS, false, nil, "", io.Discard)
	require.NoError(t, err)

	counts := CountByKind(modules)
	t.Logf("embedded rules by kind: %v (total modules %d)", counts, len(modules))

	require.Greater(t, counts[KindSecrets], 500, "secrets should dominate the corpus")
	require.Greater(t, counts[KindSAST], 200)
	require.Greater(t, counts[KindOCI], 0)
	require.Greater(t, counts[KindIAC], 0)

	rules := 0
	for _, n := range counts {
		rules += n
	}
	require.Greater(t, float64(counts[KindSecrets])/float64(rules), 0.5,
		"the keystroke path skips secrets precisely because they are most of the corpus")
}

// TestInteractiveKindsExcludeSecrets is the one-line statement of the hot-path
// design, so a well-meaning "make the editor find secrets as you type" change
// has to come past a test that explains the cost.
func TestInteractiveKindsExcludeSecrets(t *testing.T) {
	for _, k := range InteractiveKinds {
		require.NotEqual(t, KindSecrets, k,
			"secrets cost ~213ms of the 231ms it takes to evaluate one file; "+
				"they belong on save, not on keystroke (see session_bench_test.go)")
	}
	require.ElementsMatch(t, []string{KindSAST, KindIAC, KindOCI}, InteractiveKinds)
}

func TestCountByKindIgnoresLibraries(t *testing.T) {
	counts := CountByKind(map[string]string{
		"lib.rego": libModule,
		"a.rego":   sastModule,
	})
	require.Equal(t, map[string]int{KindSAST: 1}, counts)
}
