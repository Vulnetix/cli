package sast

import (
	"strings"
	"testing"
)

func TestSanitizeIdent_Normal(t *testing.T) {
	got := sanitizeIdent("community-rules")
	if got != "community_rules" {
		t.Errorf("expected 'community_rules', got %q", got)
	}
}

func TestSanitizeIdent_StartsWithDigit(t *testing.T) {
	got := sanitizeIdent("123abc")
	if got != "r_123abc" {
		t.Errorf("expected 'r_123abc', got %q", got)
	}
}

func TestSanitizeIdent_Empty(t *testing.T) {
	got := sanitizeIdent("")
	if got != "r_" {
		t.Errorf("expected 'r_', got %q", got)
	}
}

func TestNamespacePath_VulnetixRules(t *testing.T) {
	got := namespacePath("vulnetix.rules.myrule.subrule", "ns")
	if got != "vulnetix.rules.ns_myrule.subrule" {
		t.Errorf("expected 'vulnetix.rules.ns_myrule.subrule', got %q", got)
	}
}

func TestNamespacePath_VulnetixNonRules(t *testing.T) {
	got := namespacePath("vulnetix.helpers.func", "ns")
	if got != "vulnetix.ns_helpers.func" {
		t.Errorf("expected 'vulnetix.ns_helpers.func', got %q", got)
	}
}

func TestNamespacePath_NonVulnetix(t *testing.T) {
	got := namespacePath("data.test.thing", "ns")
	if got != "data.test.thing" {
		t.Errorf("expected unchanged, got %q", got)
	}
}

func TestNamespacePath_ShortPrefix(t *testing.T) {
	got := namespacePath("vulnetix", "ns")
	if got != "vulnetix" {
		t.Errorf("expected unchanged short path, got %q", got)
	}
}

func TestNamespacePath_RulesShort(t *testing.T) {
	// "vulnetix.rules" with no further parts should stay unchanged
	got := namespacePath("vulnetix.rules", "ns")
	if got != "vulnetix.rules" {
		t.Errorf("expected unchanged, got %q", got)
	}
}

func TestNamespaceRego_RewritesPackageAndImport(t *testing.T) {
	src := "package vulnetix.rules.myrule\n\nimport data.vulnetix.helpers.func\n\ndeny[msg] { true }"
	result := namespaceRego(src, "ns")

	if !strings.Contains(result, "package vulnetix.rules.ns_myrule") {
		t.Errorf("expected package rewrite in: %s", result)
	}
	if !strings.Contains(result, "import data.vulnetix.ns_helpers.func") {
		t.Errorf("expected import rewrite in: %s", result)
	}
}
