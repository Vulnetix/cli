package sast

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRuleRef_Valid(t *testing.T) {
	ref, err := ParseRuleRef("Vulnetix/community-rules")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Org != "Vulnetix" || ref.Repo != "community-rules" {
		t.Fatalf("got Org=%q Repo=%q", ref.Org, ref.Repo)
	}
}

func TestParseRuleRef_NoSlash(t *testing.T) {
	_, err := ParseRuleRef("norules")
	if err == nil {
		t.Fatal("expected error for missing slash")
	}
}

func TestParseRuleRef_EmptyOrg(t *testing.T) {
	_, err := ParseRuleRef("/repo")
	if err == nil {
		t.Fatal("expected error for empty org")
	}
}

func TestParseRuleRef_EmptyRepo(t *testing.T) {
	_, err := ParseRuleRef("org/")
	if err == nil {
		t.Fatal("expected error for empty repo")
	}
}

func TestParseRuleRef_EmptyString(t *testing.T) {
	_, err := ParseRuleRef("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}

func TestParseRuleRef_TrimSpaces(t *testing.T) {
	ref, err := ParseRuleRef("  org/repo  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Org != "org" || ref.Repo != "repo" {
		t.Fatalf("got Org=%q Repo=%q", ref.Org, ref.Repo)
	}
}

func TestResolveURL_TrailingSlash(t *testing.T) {
	url := ResolveURL("https://github.com/", RuleRef{Org: "a", Repo: "b"})
	if url != "https://github.com/a/b" {
		t.Fatalf("got %q", url)
	}
}

func TestResolveURL_NoTrailingSlash(t *testing.T) {
	url := ResolveURL("https://github.com", RuleRef{Org: "a", Repo: "b"})
	if url != "https://github.com/a/b" {
		t.Fatalf("got %q", url)
	}
}

func TestResolveURL_CustomRegistry(t *testing.T) {
	url := ResolveURL("https://gitlab.example.com/api/v4", RuleRef{Org: "my", Repo: "rules"})
	if url != "https://gitlab.example.com/api/v4/my/rules" {
		t.Fatalf("got %q", url)
	}
}

func TestCacheDir(t *testing.T) {
	dir, err := CacheDir(RuleRef{Org: "vulnetix", Repo: "rules"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dir == "" {
		t.Fatal("expected non-empty cache dir")
	}
	// Should follow the documented pattern
	base, _ := os.UserCacheDir()
	expected := filepath.Join(base, "vulnetix", "rules", "vulnetix", "rules")
	if dir != expected {
		t.Fatalf("expected %q, got %q", expected, dir)
	}
}
