package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The layout `npx skills` leaves behind: real directories in ~/.agents/skills,
// symlinks into them from each host's skills folder, and a lock beside the
// store. The fixture mixes a skill upstream still ships, one it removed, one
// from a different source, a lock ghost with no files, and a user's own real
// directory that must survive no matter what.
func pruneFixture(t *testing.T) (home, host string) {
	t.Helper()
	home = t.TempDir()
	store := filepath.Join(home, ".agents", "skills")
	host = filepath.Join(home, ".claude", "skills")

	for _, name := range []string{"current", "orphan", "other-orphan"} {
		if err := os.MkdirAll(filepath.Join(store, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(store, name, "SKILL.md"), []byte("# "+name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(host, "keep-me"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"current", "orphan", "other-orphan"} {
		// Relative, exactly as the installer writes them.
		if err := os.Symlink(filepath.Join("..", "..", ".agents", "skills", name), filepath.Join(host, name)); err != nil {
			t.Fatal(err)
		}
	}
	// A symlink named like an orphan that points somewhere else entirely.
	if err := os.Symlink(filepath.Join(home, "elsewhere"), filepath.Join(host, "ghost")); err != nil {
		t.Fatal(err)
	}

	lock := map[string]any{
		"version": 3,
		"skills": map[string]any{
			"current":      map[string]any{"source": "Vulnetix/pix-ai-coding-assistant", "skillPath": "skills/current/SKILL.md"},
			"orphan":       map[string]any{"source": "Vulnetix/pix-ai-coding-assistant", "skillPath": "vulnetix/skills/orphan/SKILL.md"},
			"other-orphan": map[string]any{"source": "someone/else", "skillPath": "skills/other-orphan/SKILL.md"},
			"ghost":        map[string]any{"source": "Vulnetix/pix-ai-coding-assistant", "skillPath": "skills/ghost/SKILL.md"},
		},
		"unrelated": "must survive",
	}
	b, _ := json.MarshalIndent(lock, "", "  ")
	if err := os.WriteFile(filepath.Join(home, ".agents", ".skill-lock.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return home, host
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func TestPlanPruneTargetsOnlyVulnetixOrphans(t *testing.T) {
	home, host := pruneFixture(t)
	store := filepath.Join(home, ".agents", "skills")

	plan, _, err := planPrune(home, []string{host, store}, skillSet([]string{"current", "missing-upstream"}), nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(plan.Targets) != 2 || plan.Targets[0].Name != "ghost" || plan.Targets[1].Name != "orphan" {
		t.Fatalf("targets = %+v, want ghost and orphan", plan.Targets)
	}
	orphan := plan.Targets[1]
	if orphan.Store != filepath.Join(store, "orphan") || len(orphan.Links) != 1 || orphan.Links[0] != filepath.Join(host, "orphan") {
		t.Errorf("orphan target wrong: %+v", orphan)
	}
	ghost := plan.Targets[0]
	if ghost.Store != "" || len(ghost.Links) != 0 || ghost.Reason != "lock entry without files" {
		t.Errorf("ghost target wrong: %+v", ghost)
	}
	if len(plan.Missing) != 1 || plan.Missing[0] != "missing-upstream" {
		t.Errorf("missing = %v, want [missing-upstream]", plan.Missing)
	}

	// Planning is read-only.
	for _, p := range []string{filepath.Join(store, "orphan"), filepath.Join(host, "orphan"), filepath.Join(host, "ghost")} {
		if !exists(p) {
			t.Errorf("planning removed %s", p)
		}
	}
}

func TestApplyPruneRemovesLinksStoreAndLockEntry(t *testing.T) {
	home, host := pruneFixture(t)
	store := filepath.Join(home, ".agents", "skills")

	plan, lock, err := planPrune(home, []string{host, store}, skillSet([]string{"current"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyPrune(plan, lock); err != nil {
		t.Fatal(err)
	}

	for _, gone := range []string{filepath.Join(store, "orphan"), filepath.Join(host, "orphan")} {
		if exists(gone) {
			t.Errorf("%s should have been removed", gone)
		}
	}
	for _, kept := range []string{
		filepath.Join(store, "current"), filepath.Join(host, "current"),
		filepath.Join(store, "other-orphan"), filepath.Join(host, "other-orphan"),
		filepath.Join(host, "keep-me"), filepath.Join(host, "ghost"),
	} {
		if !exists(kept) {
			t.Errorf("%s must survive a prune", kept)
		}
	}

	b, err := os.ReadFile(filepath.Join(home, ".agents", ".skill-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	skills := doc["skills"].(map[string]any)
	if _, ok := skills["orphan"]; ok {
		t.Error("orphan still in lock")
	}
	if _, ok := skills["ghost"]; ok {
		t.Error("ghost still in lock")
	}
	if _, ok := skills["current"]; !ok {
		t.Error("current dropped from lock")
	}
	if _, ok := skills["other-orphan"]; !ok {
		t.Error("a non-Vulnetix entry was dropped from the lock")
	}
	if doc["unrelated"] != "must survive" {
		t.Error("unknown top-level lock fields were not preserved")
	}
}

func TestPlanPruneExplicitNamesIgnoreUpstream(t *testing.T) {
	home, host := pruneFixture(t)
	store := filepath.Join(home, ".agents", "skills")

	plan, _, err := planPrune(home, []string{host, store}, skillSet([]string{"current"}), []string{"current", "other-orphan"})
	if err != nil {
		t.Fatal(err)
	}
	// "current" is Vulnetix-sourced and explicitly named, so it is removed even
	// though upstream ships it; "other-orphan" is not ours and stays out.
	if len(plan.Targets) != 1 || plan.Targets[0].Name != "current" || plan.Targets[0].Reason != "requested" {
		t.Errorf("targets = %+v, want just current (requested)", plan.Targets)
	}
	if len(plan.Missing) != 0 {
		t.Errorf("explicit prune must not report missing skills, got %v", plan.Missing)
	}
}

func TestLinksIntoMatchesOnlyLinksIntoTheStoreEntry(t *testing.T) {
	home, host := pruneFixture(t)
	store := filepath.Join(home, ".agents", "skills")

	if got := linksInto([]string{host, store}, store, "orphan"); len(got) != 1 {
		t.Errorf("want the host symlink, got %v", got)
	}
	if got := linksInto([]string{host}, store, "ghost"); len(got) != 0 {
		t.Errorf("a symlink pointing elsewhere must not match, got %v", got)
	}
	if got := linksInto([]string{host}, store, "keep-me"); len(got) != 0 {
		t.Errorf("a real directory must never match, got %v", got)
	}
}

func TestLoadSkillLockMissingFileIsEmpty(t *testing.T) {
	l, err := loadSkillLock(filepath.Join(t.TempDir(), "nope", ".skill-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.skills) != 0 {
		t.Errorf("want empty lock, got %v", l.skills)
	}
}
