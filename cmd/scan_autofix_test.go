package cmd

import (
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

func TestRewriteAutofixCommandsUsesAuthoritativeNpmLockfile(t *testing.T) {
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
		{RelPath: "web/package.json"},
		{RelPath: "web/yarn.lock"},
	}

	out := rewriteAutofixCommandsForPackageManagers(plans, files)

	assert.Equal(t, "yarn upgrade parent", out[0].Command)
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
