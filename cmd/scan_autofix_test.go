package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	autofix "github.com/vulnetix/cli/v3/internal/fix"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/triage"
)

func TestRecordAutofixMemoryEventsCreatesFixedRecord(t *testing.T) {
	mem := &memory.Memory{Version: "1"}

	recordAutofixMemoryEvents(mem, []*triage.TriageFinding{{
		CVEID:        "CVE-2024-0001",
		Package:      "lodash",
		Ecosystem:    "npm",
		InstalledVer: "4.17.20",
		FixedVer:     "4.17.21",
	}})

	rec := mem.Findings["CVE-2024-0001"]
	assert.Equal(t, "fixed", rec.Status)
	assert.Equal(t, "lodash", rec.Package)
	assert.Equal(t, "npm", rec.Ecosystem)
	assert.Equal(t, memory.ToolSCA, rec.Tool)
	assert.Equal(t, "vulnetix-sca", rec.Source)
	assert.Equal(t, "4.17.20", rec.Versions.Current)
	assert.Equal(t, "4.17.21", rec.Versions.FixedIn)
	assert.Equal(t, "sca-autofix", rec.Versions.FixSource)
	assert.Equal(t, "autofix-applied", rec.History[len(rec.History)-1].Event)
	assert.Contains(t, rec.History[len(rec.History)-1].Detail, "lodash 4.17.20 -> 4.17.21")
}

func TestRecordAutofixMemoryEventsDoesNotDuplicateHistory(t *testing.T) {
	mem := &memory.Memory{Version: "1"}
	finding := &triage.TriageFinding{
		CVEID:        "CVE-2024-0001",
		Package:      "lodash",
		Ecosystem:    "npm",
		InstalledVer: "4.17.20",
		FixedVer:     "4.17.21",
	}

	recordAutofixMemoryEvents(mem, []*triage.TriageFinding{finding})
	recordAutofixMemoryEvents(mem, []*triage.TriageFinding{finding})

	rec := mem.Findings["CVE-2024-0001"]
	var autofixEvents int
	for _, h := range rec.History {
		if h.Event == "autofix-applied" {
			autofixEvents++
		}
	}
	assert.Equal(t, 1, autofixEvents)
}

func TestRewriteAutofixCommandsUsesYarnClassicLockfile(t *testing.T) {
	dir := t.TempDir()
	requireNoErr(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"packageManager":"yarn@1.22.22"}`), 0o644))
	requireNoErr(t, os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte("# yarn lockfile v1\n"), 0o644))
	plans := []autofix.FixCandidate{{
		PackageName: "vulnerable-child",
		Ecosystem:   "npm",
		SourceFile:  "web/package.json",
		ParentName:  "parent",
		TargetVer:   "2.0.0",
		Method:      autofix.MethodParentUpdate,
		Command:     "npm update parent",
	}}
	files := []scan.DetectedFile{
		{Path: filepath.Join(dir, "package.json"), RelPath: "web/package.json"},
		{Path: filepath.Join(dir, "yarn.lock"), RelPath: "web/yarn.lock"},
	}

	out := rewriteAutofixCommandsForPackageManagers(plans, files)

	assert.Equal(t, "yarn upgrade parent", out[0].Command)
}

func TestRewriteAutofixCommandsUsesYarnBerryUp(t *testing.T) {
	dir := t.TempDir()
	requireNoErr(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"packageManager":"yarn@4.5.0"}`), 0o644))
	requireNoErr(t, os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte("__metadata:\n  version: 8\n"), 0o644))
	plans := []autofix.FixCandidate{{
		PackageName: "vulnerable-child",
		Ecosystem:   "npm",
		SourceFile:  "web/package.json",
		ParentName:  "parent",
		TargetVer:   "2.0.0",
		Method:      autofix.MethodParentUpdate,
		Command:     "npm update parent",
	}}
	files := []scan.DetectedFile{
		{Path: filepath.Join(dir, "package.json"), RelPath: "web/package.json"},
		{Path: filepath.Join(dir, "yarn.lock"), RelPath: "web/yarn.lock"},
	}

	out := rewriteAutofixCommandsForPackageManagers(plans, files)

	assert.Equal(t, "yarn up parent", out[0].Command)
}

func TestRewriteAutofixCommandsRewritesSkippedManualCommands(t *testing.T) {
	dir := t.TempDir()
	requireNoErr(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"packageManager":"yarn@1.22.22"}`), 0o644))
	requireNoErr(t, os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte("# yarn lockfile v1\n"), 0o644))
	plans := []autofix.FixCandidate{{
		PackageName: "lodash",
		Ecosystem:   "npm",
		SourceFile:  "web/package.json",
		Method:      autofix.MethodDirectBump,
		Command:     "npm install",
		Skipped:     true,
		SkipReason:  "no Safe-Harbour fix version available",
	}}
	files := []scan.DetectedFile{
		{Path: filepath.Join(dir, "package.json"), RelPath: "web/package.json"},
		{Path: filepath.Join(dir, "yarn.lock"), RelPath: "web/yarn.lock"},
	}

	out := rewriteAutofixCommandsForPackageManagers(plans, files)

	assert.True(t, out[0].Skipped)
	assert.Equal(t, "yarn install", out[0].Command)
}

func TestRewriteAutofixCommandsUsesAuthoritativePythonLockfile(t *testing.T) {
	plans := []autofix.FixCandidate{{
		PackageName: "requests",
		Ecosystem:   "pypi",
		SourceFile:  "api/pyproject.toml",
		Method:      autofix.MethodDirectBump,
		Command:     "pip install -r api/pyproject.toml",
	}}
	files := []scan.DetectedFile{
		{RelPath: "api/pyproject.toml"},
		{RelPath: "api/uv.lock"},
	}

	out := rewriteAutofixCommandsForPackageManagers(plans, files)

	assert.Equal(t, "uv sync", out[0].Command)
}

func TestAutofixEvidencePayloadIncludesProofOfWork(t *testing.T) {
	payload := autofixEvidencePayload(&triage.TriageFinding{
		Package:      "lodash",
		Ecosystem:    "npm",
		InstalledVer: "4.17.20",
		FixedVer:     "4.17.21",
	}, autofix.FixCandidate{
		PackageName: "lodash",
		Ecosystem:   "npm",
		SourceFile:  "package.json",
		TargetVer:   "4.17.21",
		Method:      autofix.MethodDirectBump,
		Command:     "yarn up lodash",
		Reason:      "safe harbour target selected",
	}, autofix.ProofCounts{Direct: 1, TransitiveParentUpdate: 2})

	assert.Equal(t, "vulnetix-cli sca-autofix", payload["source"])
	assert.Equal(t, "direct-bump", payload["method"])
	assert.Equal(t, "yarn up lodash", payload["command"])
	proof, ok := payload["proof_of_work"].(map[string]int)
	assert.True(t, ok)
	assert.Equal(t, 1, proof["direct"])
	assert.Equal(t, 2, proof["transitive_parent_update"])
}

func TestHasActionableAutofixPlan(t *testing.T) {
	assert.False(t, hasActionableAutofixPlan([]autofix.FixCandidate{{Skipped: true}}))
	assert.True(t, hasActionableAutofixPlan([]autofix.FixCandidate{{Skipped: true}, {PackageName: "lodash"}}))
}

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	assert.NoError(t, err)
}
