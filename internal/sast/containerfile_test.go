package sast

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// evalDockerRulesOn loads the embedded default rules and evaluates them over a
// temp dir containing a single file named fileName with the given content.
// Returns the set of rule IDs that fired.
func evalDockerRulesOn(t *testing.T, fileName, content string) map[string]bool {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", fileName, err)
	}
	modules, err := LoadAllModules(DefaultRulesFS, false, nil, "", io.Discard)
	if err != nil {
		t.Fatalf("LoadAllModules: %v", err)
	}
	report, err := NewEngine(modules, dir).Evaluate(EvalOptions{MaxDepth: 5})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	fired := map[string]bool{}
	for _, f := range report.Findings {
		fired[f.RuleID] = true
	}
	return fired
}

// A Dockerfile with FROM but no USER directive must trigger VNX-DOCKER-001.
// This is the baseline that already worked before the Containerfile fix.
func TestDockerRules_FireOnDockerfile(t *testing.T) {
	fired := evalDockerRulesOn(t, "Dockerfile", "FROM alpine:3.21\nRUN echo hi\n")
	if !fired["VNX-DOCKER-001"] {
		t.Fatalf("expected VNX-DOCKER-001 to fire on Dockerfile; fired=%v", fired)
	}
}

// The same content in a file literally named "Containerfile" must also trigger
// VNX-DOCKER-001 — this is the regression the _is_dockerfile fix addresses.
func TestDockerRules_FireOnContainerfile(t *testing.T) {
	fired := evalDockerRulesOn(t, "Containerfile", "FROM alpine:3.21\nRUN echo hi\n")
	if !fired["VNX-DOCKER-001"] {
		t.Fatalf("expected VNX-DOCKER-001 to fire on Containerfile; fired=%v", fired)
	}
}

// A lowercase-extension variant must match too.
func TestDockerRules_FireOnDotContainerfile(t *testing.T) {
	fired := evalDockerRulesOn(t, "service.containerfile", "FROM alpine:3.21\nRUN echo hi\n")
	if !fired["VNX-DOCKER-001"] {
		t.Fatalf("expected VNX-DOCKER-001 to fire on *.containerfile; fired=%v", fired)
	}
}

// Suffix-style names (Containerfile.postgres, Dockerfile.prod) are detected by
// detector.go via basename-contains; the rego matcher must agree, otherwise a
// repo whose compose.yml builds from Containerfile.<svc> gets SCA but no
// misconfiguration findings.
func TestDockerRules_FireOnSuffixVariants(t *testing.T) {
	for _, name := range []string{"Containerfile.postgres", "Dockerfile.prod", "go-processors.Containerfile"} {
		fired := evalDockerRulesOn(t, name, "FROM alpine:3.21\nRUN echo hi\n")
		if !fired["VNX-DOCKER-001"] {
			t.Fatalf("expected VNX-DOCKER-001 to fire on %q; fired=%v", name, fired)
		}
	}
}
