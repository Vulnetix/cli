package sast

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// shardModules must be lossless: every rule lands in exactly one shard, none
// duplicated or dropped, for any shard count.
func TestShardModulesLossless(t *testing.T) {
	rules := map[string]string{}
	for i := range 200 {
		rules[fmt.Sprintf("rules/r%03d.rego", i)] = fmt.Sprintf("package vulnetix.rules.r%03d", i)
	}
	for _, n := range []int{1, 2, 3, 7, 16, 199, 200} {
		shards := shardModules(rules, n)
		require.Len(t, shards, n)
		seen := map[string]int{}
		for _, sh := range shards {
			for k, v := range sh {
				require.Equal(t, rules[k], v)
				seen[k]++
			}
		}
		require.Len(t, seen, len(rules), "n=%d: every rule present exactly once", n)
		for k, c := range seen {
			require.Equal(t, 1, c, "rule %s duplicated across shards", k)
		}
	}
}

func TestPartitionModules(t *testing.T) {
	mods := map[string]string{
		"rules/helpers.rego": "package vulnetix.helpers\n",
		"rules/r1.rego":      "package vulnetix.rules.r1\n",
		"rules/r2.rego":      "package vulnetix.rules.r2\n",
		"lib/util.rego":      "package vulnetix.lib.util\n",
	}
	shared, rules := partitionModules(mods)
	require.Len(t, rules, 2)
	require.Contains(t, rules, "rules/r1.rego")
	require.Contains(t, rules, "rules/r2.rego")
	// helpers and any non-rule package are shared (included in every shard).
	require.Len(t, shared, 2)
	require.Contains(t, shared, "rules/helpers.rego")
	require.Contains(t, shared, "lib/util.rego")
}

func TestShardCount(t *testing.T) {
	// Small rule sets stay single-compile.
	require.Equal(t, 1, shardCount(0))
	require.Equal(t, 1, shardCount(shardMinRules))
	// Large sets shard, bounded by the ceiling and cores.
	require.LessOrEqual(t, shardCount(10000), shardMaxCount)
	require.GreaterOrEqual(t, shardCount(10000), 1)

	// Env override wins (1 forces the single-compile parity baseline).
	t.Setenv("VULNETIX_SAST_SHARDS", "1")
	require.Equal(t, 1, shardCount(10000))
	t.Setenv("VULNETIX_SAST_SHARDS", "5")
	require.Equal(t, 5, shardCount(10000))
	// Override is clamped to the rule count.
	require.Equal(t, 3, shardCount(3))
}

// TestEngineShardingParity proves the sharded compile+eval+merge yields the
// identical (non-empty) finding set and rule set as the single-compile path.
// It uses synthetic always-firing rules so the merge across shards is actually
// exercised; real embedded-rule finding parity is covered end-to-end elsewhere.
func TestEngineShardingParity(t *testing.T) {
	const nRules = 120 // > shardMinRules so default sharding also engages
	modules := map[string]string{
		// minimal shared module to prove shared modules land in every shard
		"lib.rego": "package vulnetix.lib\n\nimport rego.v1\n\nneedle := \"NEEDLE\"\n",
	}
	for i := range nRules {
		id := fmt.Sprintf("SYN-%03d", i)
		pkg := fmt.Sprintf("syn_%03d", i)
		marker := fmt.Sprintf("MARK_%03d", i)
		modules[fmt.Sprintf("rules/syn_%03d.rego", i)] = fmt.Sprintf(`package vulnetix.rules.%s

import rego.v1
import data.vulnetix.lib

metadata := {"id": "%s", "name": "synthetic", "languages": [], "severity": "low", "level": "note", "kind": "sast"}

findings contains f if {
	some path, content in input.file_contents
	contains(content, "%s")
	contains(content, lib.needle)
	f := {"rule_id": "%s", "message": "hit", "artifact_uri": path, "start_line": 1}
}
`, pkg, id, marker, id)
	}

	dir := t.TempDir()
	// Plant content matching every synthetic rule's marker (+ the shared needle).
	var body strings.Builder
	body.WriteString("NEEDLE\n")
	for i := range nRules {
		fmt.Fprintf(&body, "MARK_%03d\n", i)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "code.txt"), []byte(body.String()), 0o644))

	run := func(shards string) *SASTReport {
		t.Setenv("VULNETIX_SAST_SHARDS", shards)
		rep, err := NewEngine(modules, dir).Evaluate(EvalOptions{MaxDepth: 5})
		require.NoError(t, err)
		return rep
	}

	single := run("1")  // parity baseline (single compile)
	sharded := run("6") // forces multi-shard compile+eval+merge

	t.Logf("rules=%d single findings=%d sharded findings=%d", len(single.Rules), len(single.Findings), len(sharded.Findings))
	require.Equal(t, nRules, len(single.Findings), "every synthetic rule should fire once")
	require.Equal(t, len(single.Rules), len(sharded.Rules), "rule count parity")
	require.Equal(t, fingerprintSet(single.Findings), fingerprintSet(sharded.Findings),
		"sharded findings must be the identical set to single-compile")
}

func fingerprintSet(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%s|%s|%d|%s", f.RuleID, f.ArtifactURI, f.StartLine, f.Message))
	}
	sort.Strings(out)
	return out
}
