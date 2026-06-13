package cmd

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// jsMemberCallQuery matches `_.template(x)`-style member calls.
const jsMemberCallQuery = `(call_expression function: (member_expression) @callee)`

// TestRunReachabilityForFindings_OnlyExecutedQueriesAssessed verifies the core
// fix: a CVE is only marked unreachable/assessed when its tree-sitter query
// actually ran against a matching-language file. A CVE whose query language has
// no files in the project must stay unassessed (so it is never posted as
// UNREACHABLE → never auto-resolved to not_affected server-side).
func TestRunReachabilityForFindings_OnlyExecutedQueriesAssessed(t *testing.T) {
	// Project has only a .js file. A JS query will run; a Python query has no
	// matching files and must not be treated as evidence.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("const a = 1;\nconst b = a + 2;\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	enriched := []scan.EnrichedVuln{
		{VulnFinding: scan.VulnFinding{CveID: "CVE-JS-NOMATCH", PackageName: "lodash", PackageVer: "4.17.20", Ecosystem: "npm"}},
		{VulnFinding: scan.VulnFinding{CveID: "CVE-PY-NOFILE", PackageName: "requests", PackageVer: "2.0.0", Ecosystem: "pypi"}},
	}
	hits := []vdb.CliReachabilityHit{
		{VulnID: "CVE-JS-NOMATCH", Language: "javascript", Name: "js-q", QueryText: jsMemberCallQuery, QueryHash: "h-js"},
		{VulnID: "CVE-PY-NOFILE", Language: "python", Name: "py-q", QueryText: `(call (identifier) @c)`, QueryHash: "h-py"},
	}

	runReachabilityForFindings(hits, enriched, root, io.Discard)

	byCVE := map[string]scan.EnrichedVuln{}
	for _, ev := range enriched {
		byCVE[ev.CveID] = ev
	}

	// JS query ran against app.js but matched nothing → unreachable + assessed.
	js := byCVE["CVE-JS-NOMATCH"]
	assert.True(t, js.ReachabilityAssessed, "JS query ran, so the CVE should be assessed")
	assert.Equal(t, "unreachable", js.Reachability)

	// Python query had no .py files → never executed → must stay unassessed so
	// it is not posted as UNREACHABLE.
	py := byCVE["CVE-PY-NOFILE"]
	assert.False(t, py.ReachabilityAssessed, "Python query never executed; CVE must not be assessed")
	assert.Equal(t, "", py.Reachability)

	// And confirm the unassessed CVE produces no UNREACHABLE payload.
	payloads := buildReachabilityPayloads(enriched, nil, nil)
	for _, p := range payloads {
		assert.NotEqual(t, "CVE-PY-NOFILE", p.CveID, "unassessed CVE must not be posted")
	}
}

func TestBuildReachabilityPayloads_EmptyReachabilityEmitsNoRow(t *testing.T) {
	enriched := []scan.EnrichedVuln{
		{VulnFinding: scan.VulnFinding{CveID: "CVE-2024-0001", PackageName: "lodash", PackageVer: "4.17.20"}, Reachability: ""},
	}
	payloads := buildReachabilityPayloads(enriched, nil, nil)
	assert.Empty(t, payloads, "empty reachability should emit no row")
}

func TestBuildReachabilityPayloads_UnreachableAssessedEmitsRowWithQueryHash(t *testing.T) {
	enriched := []scan.EnrichedVuln{
		{
			VulnFinding:  scan.VulnFinding{CveID: "CVE-2024-0001", PackageName: "lodash", PackageVer: "4.17.20"},
			Reachability: "unreachable", ReachabilityAssessed: true,
			ReachabilityQueryHashes: []string{"abc123"},
		},
	}
	payloads := buildReachabilityPayloads(enriched, nil, nil)
	assert.Len(t, payloads, 1)
	assert.Equal(t, "UNREACHABLE", payloads[0].Verdict)
	assert.Equal(t, "TREE_SITTER", payloads[0].Source)
	assert.Equal(t, "abc123", payloads[0].QueryHash)
}

func TestBuildReachabilityPayloads_UnreachableNotAssessedEmitsNoRow(t *testing.T) {
	enriched := []scan.EnrichedVuln{
		{
			VulnFinding:  scan.VulnFinding{CveID: "CVE-2024-0001", PackageName: "lodash", PackageVer: "4.17.20"},
			Reachability: "unreachable", ReachabilityAssessed: false,
		},
	}
	payloads := buildReachabilityPayloads(enriched, nil, nil)
	assert.Empty(t, payloads, "unreachable without assessed flag should emit no row")
}

func TestBuildReachabilityPayloads_MemoryVexWithEmptyReachabilityEmitsNoRow(t *testing.T) {
	enriched := []scan.EnrichedVuln{
		{
			VulnFinding:  scan.VulnFinding{CveID: "CVE-2024-0001", PackageName: "lodash", PackageVer: "4.17.20"},
			Reachability: "",
		},
	}
	memRecords := map[string]memory.FindingRecord{
		"CVE-2024-0001": {Status: "not_affected", Justification: "vulnerable_code_not_present", Package: "lodash"},
	}
	payloads := buildReachabilityPayloads(enriched, nil, memRecords)
	assert.Empty(t, payloads, "memory VEX + empty reachability should not manufacture UNREACHABLE row")
}

func TestBuildReachabilityPayloads_SemanticWithMatchesEmitsRows(t *testing.T) {
	enriched := []scan.EnrichedVuln{
		{
			VulnFinding:  scan.VulnFinding{CveID: "CVE-2024-0001", PackageName: "lodash", PackageVer: "4.17.20"},
			Reachability: "semantic",
			SemanticMatches: []scan.SemanticMatch{
				{File: "src/app.js", Line: 42, Symbol: "merge", Kind: "routine"},
			},
		},
	}
	payloads := buildReachabilityPayloads(enriched, nil, nil)
	assert.Len(t, payloads, 1)
	assert.Equal(t, "SEMANTIC", payloads[0].Verdict)
	assert.Equal(t, "SEMANTIC_GREP", payloads[0].Source)
	assert.Equal(t, "src/app.js", payloads[0].MatchedFile)
	assert.Equal(t, "merge", payloads[0].MatchedRoutine)
	assert.Equal(t, 42, payloads[0].MatchStartLine)
}

func TestBuildReachabilityPayloads_SemanticEmptyMatchesEmitsNoRow(t *testing.T) {
	enriched := []scan.EnrichedVuln{
		{
			VulnFinding:     scan.VulnFinding{CveID: "CVE-2024-0001", PackageName: "lodash", PackageVer: "4.17.20"},
			Reachability:    "semantic",
			SemanticMatches: []scan.SemanticMatch{},
		},
	}
	payloads := buildReachabilityPayloads(enriched, nil, nil)
	assert.Empty(t, payloads, "semantic with no matches should emit no row")
}

func TestBuildReachabilityPayloads_DirectEmitsRow(t *testing.T) {
	enriched := []scan.EnrichedVuln{
		{
			VulnFinding:             scan.VulnFinding{CveID: "CVE-2024-0001", PackageName: "lodash", PackageVer: "4.17.20"},
			Reachability:            "direct",
			ReachabilityAssessed:    true,
			ReachabilityQueryHashes: []string{"hash1"},
			AffectedSymbols: &scan.AffectedSymbols{
				Routines: []string{"merge"},
			},
		},
	}
	payloads := buildReachabilityPayloads(enriched, nil, nil)
	assert.Len(t, payloads, 1)
	assert.Equal(t, "DIRECT", payloads[0].Verdict)
	assert.Equal(t, "TREE_SITTER", payloads[0].Source)
	assert.Equal(t, "hash1", payloads[0].QueryHash)
	assert.Equal(t, "merge", payloads[0].MatchedRoutine)
}

func TestBuildReachabilityPayloads_FindingUuidLookup(t *testing.T) {
	enriched := []scan.EnrichedVuln{
		{VulnFinding: scan.VulnFinding{CveID: "CVE-2024-0001", PackageName: "lodash", PackageVer: "4.17.20"}, Reachability: "transitive", ReachabilityAssessed: true},
	}
	findingByKey := map[string]vdb.CliFindingResult{
		"CVE-2024-0001|lodash|4.17.20": {FindingUuid: "find-uuid-1", Purl: "pkg:npm/lodash@4.17.20"},
	}
	payloads := buildReachabilityPayloads(enriched, findingByKey, nil)
	assert.Len(t, payloads, 1)
	assert.Equal(t, "find-uuid-1", payloads[0].FindingUuid)
	assert.Equal(t, "pkg:npm/lodash@4.17.20", payloads[0].Purl)
}

func TestBuildReachabilityPayloads_MemoryVexForwardedOnRow(t *testing.T) {
	enriched := []scan.EnrichedVuln{
		{
			VulnFinding:  scan.VulnFinding{CveID: "CVE-2024-0001", PackageName: "lodash", PackageVer: "4.17.20"},
			Reachability: "transitive", ReachabilityAssessed: true,
		},
	}
	memRecords := map[string]memory.FindingRecord{
		"CVE-2024-0001": {Status: "not_affected", Justification: "vulnerable_code_not_present", ActionResponse: "upgrade", Package: "lodash"},
	}
	payloads := buildReachabilityPayloads(enriched, nil, memRecords)
	assert.Len(t, payloads, 1)
	assert.Equal(t, "not_affected", payloads[0].MemoryVexStatus)
	assert.Equal(t, "vulnerable_code_not_present", payloads[0].MemoryVexJustification)
	assert.Equal(t, "upgrade", payloads[0].MemoryVexAction)
}
