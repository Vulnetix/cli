package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	autofix "github.com/vulnetix/cli/v4/internal/fix"
	"github.com/vulnetix/cli/v4/internal/memory"
	"github.com/vulnetix/cli/v4/internal/scan"
	"github.com/vulnetix/cli/v4/internal/triage"
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
	withFakePackageManagers(t, "yarn")
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
	withFakePackageManagers(t, "yarn")
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
	withFakePackageManagers(t, "yarn")
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
	withFakePackageManagers(t, "uv")
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
	withFakePackageManagers(t, "yarn")
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

// withFakePackageManagers puts executables with the given names first on PATH.
//
// rewriteAutofixCommandsForPackageManagers only emits a manager's command when that manager is
// installed, and falls back to another one otherwise. A test that expects `uv sync` or `yarn up`
// therefore passes on a machine with uv and yarn and fails on a runner without them. The tests
// say which managers exist rather than inheriting whatever the host happens to have.
func withFakePackageManagers(t *testing.T, names ...string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake package managers are shell scripts")
	}
	dir := t.TempDir()
	for _, name := range names {
		requireNoErr(t, os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\necho 1.0.0\n"), 0o755))
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// withOnlyPackageManagers is withFakePackageManagers with nothing else on PATH, so
// a real pip or uv on the host cannot change which fallback a test reaches.
func withOnlyPackageManagers(t *testing.T, names ...string) {
	t.Helper()
	withFakePackageManagers(t, names...)
	t.Setenv("PATH", strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))[0])
}

// With no lockfile naming a manager and pip missing, the plan must use a command
// that can read the manifest: `uv sync` beside a requirements file stops with
// "No `pyproject.toml` found", which is how `fix` was found failing.
func TestRewriteAutofixCommandsPythonFallback(t *testing.T) {
	cases := []struct {
		name     string
		bins     []string
		source   string
		wantCmd  string
		wantSkip bool
	}{
		{"pip3 for requirements", []string{"pip3", "uv"}, "sub/requirements.txt", "pip3 install -r requirements.txt", false},
		{"pip3 for pyproject", []string{"pip3"}, "pyproject.toml", "pip3 install .", false},
		{"uv for requirements", []string{"uv"}, "sub/requirements.txt", "uv pip install -r requirements.txt", false},
		{"uv for pyproject", []string{"uv"}, "pyproject.toml", "uv sync", false},
		{"uv for setup.py", []string{"uv"}, "setup.py", "uv pip install .", false},
		{"pipenv for pyproject", []string{"pipenv"}, "pyproject.toml", "pipenv update requests", false},
		{"pipenv for requirements", []string{"pipenv"}, "requirements.txt", "pipenv install -r requirements.txt", false},
		{"poetry for pyproject", []string{"poetry"}, "pyproject.toml", "poetry update requests", false},
		{"pipenv for Pipfile", []string{"pipenv"}, "Pipfile", "pipenv update requests", false},
		{"pip3 never takes a Pipfile", []string{"pip3"}, "Pipfile", "", true},
		{"nothing installed", nil, "requirements.txt", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withOnlyPackageManagers(t, tc.bins...)
			files := []scan.DetectedFile{{RelPath: tc.source}, {RelPath: "pyproject.toml"}, {RelPath: "Pipfile"}}
			plans := []autofix.FixCandidate{{
				PackageName: "requests",
				Ecosystem:   "pypi",
				SourceFile:  tc.source,
				Method:      autofix.MethodDirectBump,
				Command:     autofix.PipCommand(tc.source),
			}}

			out := rewriteAutofixCommandsForPackageManagers(plans, files)

			assert.Equal(t, tc.wantSkip, out[0].Skipped, out[0].SkipReason)
			if !tc.wantSkip {
				assert.Equal(t, tc.wantCmd, out[0].Command)
			}
		})
	}
}

// poetry and pdm cannot read a requirements file, so a host that has only those
// lists the fix as manual rather than plan a command that fails.
func TestRewriteAutofixCommandsPythonFallbackManagerCannotReadManifest(t *testing.T) {
	withOnlyPackageManagers(t, "poetry")
	files := []scan.DetectedFile{{RelPath: "requirements.txt"}, {RelPath: "pyproject.toml"}}
	plans := []autofix.FixCandidate{{
		PackageName: "requests",
		Ecosystem:   "pypi",
		SourceFile:  "requirements.txt",
		Method:      autofix.MethodDirectBump,
		Command:     autofix.PipCommand("requirements.txt"),
	}}

	out := rewriteAutofixCommandsForPackageManagers(plans, files)

	assert.True(t, out[0].Skipped)
	assert.Contains(t, out[0].SkipReason, "poetry cannot install requirements.txt")
}

// A lockfile still decides: only the no-lockfile fallback changed.
func TestRewriteAutofixCommandsLockfileManagerBeatsPythonFallback(t *testing.T) {
	withOnlyPackageManagers(t, "uv", "pip3")
	files := []scan.DetectedFile{{RelPath: "api/pyproject.toml"}, {RelPath: "api/uv.lock"}, {RelPath: "api/requirements.txt"}}
	plans := []autofix.FixCandidate{{
		PackageName: "requests",
		Ecosystem:   "pypi",
		SourceFile:  "api/requirements.txt",
		Method:      autofix.MethodDirectBump,
		Command:     autofix.PipCommand("api/requirements.txt"),
	}}

	out := rewriteAutofixCommandsForPackageManagers(plans, files)

	assert.Equal(t, "uv sync", out[0].Command)
}

// A lockfile's manager that is not installed falls back to plain pip, whose
// command stands as planned.
func TestRewriteAutofixCommandsMissingLockfileManagerFallsBackToPip(t *testing.T) {
	withOnlyPackageManagers(t, "pip")
	files := []scan.DetectedFile{{RelPath: "pyproject.toml"}, {RelPath: "uv.lock"}}
	plans := []autofix.FixCandidate{{
		PackageName: "requests",
		Ecosystem:   "pypi",
		SourceFile:  "pyproject.toml",
		Method:      autofix.MethodDirectBump,
		Command:     autofix.PipCommand("pyproject.toml"),
	}}

	out := rewriteAutofixCommandsForPackageManagers(plans, files)

	assert.False(t, out[0].Skipped, out[0].SkipReason)
	assert.Equal(t, "pip install .", out[0].Command)
}
