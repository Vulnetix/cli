package sast

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFixtureAppRecall is the other half of the efficacy suite. The precision
// cases in rules_fp_test.go prove a rule stays quiet on code that is fine; this
// proves the whole embedded ruleset still reports, with the right rule, the
// defects that testdata/vulnetix-fixture-app contains on purpose. A rule that
// is made quiet by being made blind fails here.
//
// Each entry is a defect the fixture file's own comment describes.
func TestFixtureAppRecall(t *testing.T) {
	if testing.Short() {
		t.Skip("evaluates the full embedded ruleset")
	}
	if _, err := os.Stat("../../testdata/vulnetix-fixture-app/src/vuln.go"); err != nil {
		t.Skip("the fixture app is a private submodule and is not checked out")
	}
	all, err := LoadAllModules(DefaultRulesFS, false, nil, "", io.Discard)
	require.NoError(t, err)

	rep, err := NewEngine(all, "../../testdata/vulnetix-fixture-app").Evaluate(EvalOptions{MaxDepth: 5})
	require.NoError(t, err)

	type hit struct {
		file string
		line int
		rule string
	}
	got := map[hit]bool{}
	for _, f := range rep.Findings {
		got[hit{f.ArtifactURI, f.StartLine, f.RuleID}] = true
	}

	want := []struct {
		hit
		why string
	}{
		{hit{"src/vuln.go", 15, "VNX-GO-002"}, "sh -c with a concatenated host is command injection"},
		{hit{"src/vuln.go", 22, "VNX-GO-023"}, "SQL built by concatenation is SQL injection"},
		{hit{"src/vuln.go", 30, "VNX-GO-039"}, "a login handler with no rate limiting"},
		{hit{"src/vuln.go", 32, "VNX-GO-030"}, "cookie without Secure"},
		{hit{"src/vuln.go", 32, "VNX-GO-035"}, "cookie without HttpOnly"},
		{hit{"src/vuln.go", 37, "VNX-CRYPTO-001"}, "md5 used as a fingerprint"},
		{hit{"src/vuln.js", 9, "VNX-NODE-002"}, "eval of a request value"},
		{hit{"src/vuln.js", 15, "VNX-NODE-003"}, "execSync with a concatenated request value"},
		{hit{"src/vuln.py", 13, "VNX-PY-007"}, "shell=True with interpolated input"},
		{hit{"src/vuln.py", 24, "VNX-PY-003"}, "pickle.loads of attacker data"},
		{hit{"src/vuln.py", 29, "VNX-327"}, "hashlib.md5 is a broken hash call"},
	}
	for _, w := range want {
		require.Truef(t, got[w.hit], "missed %s at %s:%d (%s)", w.rule, w.file, w.line, w.why)
	}

	// The same files must not be reported by a rule that has no business there:
	// the command injection at src/vuln.go:15 is not SQL injection.
	require.False(t, got[hit{"src/vuln.go", 15, "VNX-GO-023"}], "command injection mislabelled as SQL injection")
}
