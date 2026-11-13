package lsp

import (
	"reflect"
	"testing"

	"github.com/vulnetix/cli/v4/internal/lsp/protocol"
	"github.com/vulnetix/cli/v4/internal/sast"
	"github.com/vulnetix/cli/v4/internal/scan"
)

func TestEngineManifestLookups(t *testing.T) {
	e := seedEngine(t)
	e.typeByFile["web/package-lock.json"] = "package-lock.json"

	pkgs, typ, ok := e.PackagesFor("package.json")
	if !ok || typ != "package.json" || len(pkgs) != 3 {
		t.Errorf("PackagesFor(package.json) = %d packages, %q, %v", len(pkgs), typ, ok)
	}
	if pkgs, typ, ok := e.PackagesFor("missing.json"); ok || typ != "" || pkgs != nil {
		t.Errorf("PackagesFor(unknown) = %v, %q, %v", pkgs, typ, ok)
	}

	if !e.IsManifest("package.json") || e.IsManifest("main.go") {
		t.Error("IsManifest is true only for parsed manifests")
	}
	if got := e.ManifestPaths(); !reflect.DeepEqual(got, []string{"package.json", "web/package-lock.json"}) {
		t.Errorf("ManifestPaths = %v", got)
	}
}

func TestEngineVerdictFor(t *testing.T) {
	e := seedEngine(t)
	v, ok := e.VerdictFor("lodash", "4.17.20", "npm")
	if !ok || v == nil || !v.Vulnerable() {
		t.Fatalf("VerdictFor(lodash) = %+v, %v", v, ok)
	}
	if v, ok := e.VerdictFor("express", "4.16.0", "npm"); !ok || v.Vulnerable() {
		t.Errorf("a clean package still has a verdict: %+v, %v", v, ok)
	}
	if _, ok := e.VerdictFor("lodash", "9.9.9", "npm"); ok {
		t.Error("an unknown version has no verdict")
	}
	if _, ok := e.VerdictFor("", "", ""); ok {
		t.Error("no coordinate, no purl, no verdict")
	}
}

func TestEngineIntroducedBy(t *testing.T) {
	e := seedEngine(t)
	pkg := func(name string) scan.ScopedPackage { return scan.ScopedPackage{Name: name} }
	e.groups = []scan.ManifestGroup{
		{
			Dir: "web",
			Graph: &scan.DepGraph{
				DirectDeps: map[string]scan.ScopedPackage{"express": pkg("express"), "mocha": pkg("mocha")},
				Edges: map[string][]string{
					"express": {"qs", "debug"},
					"mocha":   {"debug", "minimist"},
					"debug":   {"ms"}, // debug is transitive: not a parent to report
				},
			},
		},
		{Dir: "other", Graph: &scan.DepGraph{
			DirectDeps: map[string]scan.ScopedPackage{"koa": pkg("koa")},
			Edges:      map[string][]string{"koa": {"debug"}},
		}},
		{Dir: "nograph"},
	}

	if got := e.IntroducedBy("web/package.json", "debug"); !reflect.DeepEqual(got, []string{"express", "mocha"}) {
		t.Errorf("IntroducedBy(debug) = %v, want the direct parents in this directory, sorted", got)
	}
	if got := e.IntroducedBy("web/package.json", "ms"); got != nil {
		t.Errorf("IntroducedBy(ms) = %v, want none: its parent is itself transitive", got)
	}
	if got := e.IntroducedBy("web/package.json", "express"); got != nil {
		t.Errorf("a direct package is introduced by nobody: %v", got)
	}
	if got := e.IntroducedBy("nograph/package.json", "debug"); got != nil {
		t.Errorf("no graph, no claim: %v", got)
	}
	if got := e.IntroducedBy("elsewhere/package.json", "debug"); got != nil {
		t.Errorf("an unknown directory: %v", got)
	}
}

func TestEngineAnchorFor(t *testing.T) {
	e := seedEngine(t)
	text := "{\n  \"dependencies\": {\n    \"lodash\": \"4.17.20\"\n  }\n}\n"
	res, ok := e.AnchorFor("package.json", text, "lodash")
	if !ok || res.Line != 3 {
		t.Errorf("AnchorFor(lodash) = %+v, %v; want line 3 (1-based)", res, ok)
	}
	if _, ok := e.AnchorFor("never-parsed.json", text, "lodash"); ok {
		t.Error("a path the engine never parsed has no anchor")
	}
}

func TestDiagnosticMappingFallbacks(t *testing.T) {
	if got := SourceForKind(sast.KindSecrets); got != "vulnetix-secrets" {
		t.Errorf("SourceForKind(secrets) = %q", got)
	}
	if got := SourceForKind("brand-new-kind"); got != "vulnetix-sast" {
		t.Errorf("an unmapped kind falls back to the sast source: %q", got)
	}

	for _, tt := range []struct {
		sev  string
		hint bool
		want int
	}{
		{"critical", false, protocol.SeverityError},
		{" HIGH ", false, protocol.SeverityError},
		{"Medium", false, protocol.SeverityWarning},
		{"low", false, protocol.SeverityInformation},
		{"low", true, protocol.SeverityHint},
		{"info", true, protocol.SeverityHint},
		{"", false, protocol.SeverityInformation},
		{"bogus", true, protocol.SeverityHint},
	} {
		if got := severityToLSP(tt.sev, SeverityMapping{LowAsHint: tt.hint}); got != tt.want {
			t.Errorf("severityToLSP(%q, hint=%v) = %d, want %d", tt.sev, tt.hint, got, tt.want)
		}
	}

	for kind, want := range map[string]string{
		sast.KindOCI:     "container",
		"":               sast.KindSAST,
		sast.KindSecrets: sast.KindSecrets,
		"custom":         "custom",
	} {
		if got := kindToTool(kind); got != want {
			t.Errorf("kindToTool(%q) = %q, want %q", kind, got, want)
		}
	}
}
