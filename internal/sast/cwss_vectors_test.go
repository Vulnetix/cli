package sast

import (
	"io"
	"testing"

	"github.com/Vulnetix/vdb-sca-match/cwss"
	"github.com/stretchr/testify/require"
)

// The ruleset used to ship CWSS vectors that were not CWSS. There were 1208 of
// them and only 11 distinct strings, and nine of the sixteen metrics carried
// values the spec does not define — AS:L, IN:L and SC:N in every single one,
// plus CONF and T, which are not CWSS metrics at all. Parsed as CWSS they all
// scored between 0.47 and 0.74, so a rule declaring critical and one declaring
// low both came out "low", and every SAST/secrets/IaC/container finding in the
// product displayed as unknown or trivial severity.
//
// internal/sast/cwssgen regenerates them from severity, kind, CWE and tags.
// These tests are what stops a hand edit putting the old shape back.

func embeddedRules(t *testing.T) []RuleMetadata {
	t.Helper()
	modules, err := LoadAllModules(DefaultRulesFS, false, nil, "", io.Discard)
	require.NoError(t, err)

	rules, err := NewEngine(modules, ".").ListRules()
	require.NoError(t, err)
	require.Greater(t, len(rules), 1500, "the embedded corpus should be the full ruleset")

	return rules
}

func TestEveryRuleCarriesAValidCWSSVector(t *testing.T) {
	for _, r := range embeddedRules(t) {
		if r.CWSS == "" {
			t.Errorf("%s (%s): no CWSS vector; run `just gen-cwss`", r.ID, r.Severity)
			continue
		}
		if _, err := cwss.Parse(r.CWSS); err != nil {
			t.Errorf("%s: %v\n  vector: %s", r.ID, err, r.CWSS)
		}
	}
}

func TestRuleCWSSVectorsMatchTheDerivation(t *testing.T) {
	// The vectors are generated, not authored, so any drift means someone edited
	// a rule's severity/CWE/tags without regenerating — which would leave the
	// score describing the rule it used to be.
	for _, r := range embeddedRules(t) {
		want := cwss.Derive(cwss.Input{
			Severity: r.Severity,
			Kind:     r.Kind,
			CWEs:     r.CWE,
			Tags:     r.Tags,
		}).Vector()
		if r.CWSS != want {
			t.Errorf("%s: stale CWSS vector; run `just gen-cwss`\n  have %s\n  want %s", r.ID, r.CWSS, want)
		}
	}
}

func TestRuleCWSSScoresTrackDeclaredSeverity(t *testing.T) {
	// A score is only useful if it agrees with the rule's own claim, or is one
	// band below it because reach demotes it. Anything else means the derivation
	// and the severity labels have diverged.
	rank := map[string]int{"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

	demoted := 0
	for _, r := range embeddedRules(t) {
		m, err := cwss.Parse(r.CWSS)
		if err != nil {
			continue // reported by TestEveryRuleCarriesAValidCWSSVector
		}
		declared, ok := rank[normaliseRuleSeverity(r.Severity)]
		if !ok {
			continue
		}
		got := rank[m.Severity()]
		switch {
		case got == declared:
		case got == declared-1:
			demoted++
		default:
			t.Errorf("%s: declared %s but scores %.2f (%s) — more than one band away",
				r.ID, r.Severity, m.Score(), m.Severity())
		}
	}
	// Local-reach rules are meant to demote; a corpus where nothing demotes means
	// reach inference has stopped doing anything.
	require.Greater(t, demoted, 0, "no rule demoted: reach inference is inert")
	t.Logf("%d rules score one band below their declared severity (local reach)", demoted)
}

func normaliseRuleSeverity(s string) string {
	switch s {
	case "crit":
		return "critical"
	case "info", "none":
		return "informational"
	default:
		return s
	}
}

func TestBuildSARIFCarriesTheCWSSVectorToTheServer(t *testing.T) {
	// The vector has to survive into the SARIF the CLI posts, otherwise vdb-api
	// falls back to deriving from the severity word and loses the reach the rule
	// already worked out.
	rule := RuleMetadata{
		ID: "VNX-TEST-001", Name: "test", Severity: "critical", Kind: "sast",
		CWE:  []int{89},
		CWSS: cwss.Derive(cwss.Input{Severity: "critical", CWEs: []int{89}}).Vector(),
	}
	log := BuildSARIF(
		[]Finding{{RuleID: rule.ID, Message: "m", ArtifactURI: "a.go", Severity: rule.Severity, StartLine: 1}},
		[]RuleMetadata{rule}, "test",
	)
	require.Len(t, log.Runs, 1)
	require.Len(t, log.Runs[0].Tool.Driver.Rules, 1)

	got, ok := log.Runs[0].Tool.Driver.Rules[0].Properties["cwss"].(string)
	require.True(t, ok, "rule descriptor carries no cwss property")
	require.Equal(t, rule.CWSS, got)

	parsed, err := cwss.Parse(got)
	require.NoError(t, err)
	require.Equal(t, "critical", parsed.Severity())
}
