package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

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
