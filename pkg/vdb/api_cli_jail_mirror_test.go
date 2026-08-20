package vdb

// The jail wire types in api_cli_jail.go are a typed MIRROR of vdb-api's
// internal/handler/v2_cli_jail.go. A mirror is only safe if it cannot silently
// drift, so this test reads the sibling checkout when one is present and asserts
// every struct's JSON tags match field for field.
//
// It skips when the sibling is absent so CI stays standalone — the same
// skip-if-absent arrangement the vdb-api side uses for its SQL drift guard.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// siblingJailHandlerPaths are the places a vdb-api checkout usually sits
// relative to this repo.
var siblingJailHandlerPaths = []string{
	"../../../vdb-api/internal/handler/v2_cli_jail.go",
	"../../../../vdb-api/internal/handler/v2_cli_jail.go",
}

// jailMirroredStructs are the types that must stay identical across the wire.
//
// CliJailRequest and CliJailResponse are the envelope; everything else is
// reachable from them, and a drift in a nested type is just as breaking as one
// in the top level — a renamed tag three levels down silently decodes to a zero
// value, which for a gate means a threshold of 0 or a verdict of "".
var jailMirroredStructs = []string{
	"CliJailRequest",
	"CliJailResponse",
	"CliJailPolicyRef",
	"CliJailScope",
	"CliJailFreshness",
	"CliJailCategoryFreshness",
	"CliJailToolCover",
	"CliJailRuleVerdict",
	"CliJailExemptionApplied",
	"CliJailVexPayload",
	"CliJailVexStatement",
	"CliJailSarifPayload",
	"CliJailSarifRule",
	"CliJailSarifResult",
	"CliJailSummary",
	"CliJailExemptRequest",
	"CliJailExemptResponse",
}

func TestJailWireTypesMirrorVdbApi(t *testing.T) {
	var sibling string
	for _, p := range siblingJailHandlerPaths {
		if b, err := os.ReadFile(filepath.Clean(p)); err == nil {
			sibling = string(b)
			break
		}
	}
	if sibling == "" {
		t.Skip("vdb-api checkout not present; skipping the wire-mirror check")
	}

	local, err := os.ReadFile("api_cli_jail.go")
	if err != nil {
		t.Fatalf("read local mirror: %v", err)
	}

	for _, name := range jailMirroredStructs {
		t.Run(name, func(t *testing.T) {
			want := jsonTagsOf(sibling, name)
			if len(want) == 0 {
				t.Skipf("could not locate struct %s in the sibling checkout", name)
			}
			got := jsonTagsOf(string(local), name)
			if len(got) == 0 {
				t.Fatalf("struct %s is missing from the CLI mirror", name)
			}
			if !equalStringSlices(want, got) {
				t.Fatalf("%s has drifted from vdb-api.\n\nvdb-api: %v\n    cli: %v", name, want, got)
			}
		})
	}
}

// jsonTagsOf extracts the sorted set of json tag names declared on a struct.
//
// Tag names rather than field names: the Go identifier is free to differ (and
// does — vdb-api spells the fields the same way, but nothing enforces that),
// while the tag is the actual contract crossing the wire.
func jsonTagsOf(source, structName string) []string {
	re := regexp.MustCompile(`(?s)type\s+` + regexp.QuoteMeta(structName) + `\s+struct\s*\{(.*?)\n\}`)
	m := re.FindStringSubmatch(source)
	if len(m) < 2 {
		return nil
	}
	tagRe := regexp.MustCompile("`json:\"([^\"]+)\"`")
	out := []string{}
	for _, hit := range tagRe.FindAllStringSubmatch(m[1], -1) {
		name := strings.Split(hit[1], ",")[0]
		if name == "" || name == "-" {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
