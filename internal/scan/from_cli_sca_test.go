package scan

import "testing"

func TestSynthesiseFromCDX_BasicMapping(t *testing.T) {
	packages := []ScopedPackage{
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", Scope: "production", SourceFile: "package.json"},
	}
	purls := []string{"pkg:npm/lodash@4.17.20"}
	cdxDoc := map[string]any{
		"components": []any{
			map[string]any{
				"bom-ref": "pkg:npm/lodash@4.17.20",
				"purl":    "pkg:npm/lodash@4.17.20",
				"name":    "lodash",
				"version": "4.17.20",
			},
		},
		"vulnerabilities": []any{
			map[string]any{
				"id":      "CVE-2021-23337",
				"source":  map[string]any{"name": "nvd"},
				"affects": []any{map[string]any{"ref": "pkg:npm/lodash@4.17.20"}},
				"ratings": []any{
					map[string]any{
						"source":   map[string]any{"name": "cvss"},
						"score":    7.2,
						"severity": "high",
						"method":   "CVSSv3",
						"vector":   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
					},
					map[string]any{
						"source": map[string]any{"name": "epss"},
						"score":  0.61,
						"method": "other",
					},
				},
				"properties": []any{
					map[string]any{"name": "vulnetix:inCisaKev", "value": "true"},
					map[string]any{"name": "vulnetix:exploitCount", "value": "3"},
					map[string]any{"name": "vulnetix:confirmed", "value": "true"},
				},
			},
		},
	}

	findings, enriched, stats := SynthesiseFromCDX(cdxDoc, packages, purls)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	f := findings[0]
	if f.CveID != "CVE-2021-23337" || f.PackageName != "lodash" || f.PackageVer != "4.17.20" {
		t.Errorf("finding fields wrong: %+v", f)
	}
	if f.Severity != "high" || f.Score != 7.2 {
		t.Errorf("severity/score not lifted from CVSS rating: %+v", f)
	}
	if !f.InCisaKev || f.ExploitCount != 3 {
		t.Errorf("vulnetix:* properties not lifted: kev=%v count=%d", f.InCisaKev, f.ExploitCount)
	}
	if f.Source != "nvd" {
		t.Errorf("source not lifted from source.name: %q", f.Source)
	}

	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched; got %d", len(enriched))
	}
	e := enriched[0]
	if e.CVSSScore != 7.2 || e.EPSSScore != 0.61 || !e.Confirmed || e.MatchMethod != "name+version" {
		t.Errorf("enriched mapping wrong: %+v", e)
	}

	if stats == nil || stats.Total != 1 || stats.Succeeded != 1 {
		t.Errorf("stats wrong: %+v", stats)
	}
}

func TestSynthesiseFromCDX_FansOutAcrossManifestPaths(t *testing.T) {
	// Same purl introduced by two manifests — synthesiser should emit two
	// findings (one per ScopedPackage) so PathCount maths downstream still works.
	packages := []ScopedPackage{
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", SourceFile: "app/package.json"},
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", SourceFile: "tools/package.json"},
	}
	purls := []string{"pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.20"}
	cdxDoc := map[string]any{
		"components": []any{
			map[string]any{"bom-ref": "x", "purl": "pkg:npm/lodash@4.17.20", "name": "lodash", "version": "4.17.20"},
		},
		"vulnerabilities": []any{
			map[string]any{
				"id":      "CVE-2021-23337",
				"affects": []any{map[string]any{"ref": "x"}},
			},
		},
	}
	findings, _, _ := SynthesiseFromCDX(cdxDoc, packages, purls)
	if len(findings) != 2 {
		t.Fatalf("expected fan-out across both source files; got %d findings: %+v", len(findings), findings)
	}
	if findings[0].SourceFile == findings[1].SourceFile {
		t.Errorf("source files should differ: %s vs %s", findings[0].SourceFile, findings[1].SourceFile)
	}
}

func TestSynthesiseFromCDX_NilOnEmptyDoc(t *testing.T) {
	f, e, s := SynthesiseFromCDX(nil, nil, nil)
	if f != nil || e != nil || s != nil {
		t.Errorf("nil doc should produce nil result; got f=%v e=%v s=%v", f, e, s)
	}
}

func TestSynthesiseFromCDX_EmptyVulnsReturnsEmptySlices(t *testing.T) {
	cdxDoc := map[string]any{
		"components":      []any{},
		"vulnerabilities": []any{},
	}
	f, e, s := SynthesiseFromCDX(cdxDoc, []ScopedPackage{{Name: "x"}}, []string{"pkg:npm/x"})
	if f == nil || e == nil {
		t.Fatalf("empty-but-present vulns should return non-nil slices; f=%v e=%v", f, e)
	}
	if len(f) != 0 || len(e) != 0 {
		t.Errorf("expected zero findings; got f=%d e=%d", len(f), len(e))
	}
	if s == nil || s.Total != 1 {
		t.Errorf("stats wrong: %+v", s)
	}
}
