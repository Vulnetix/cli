package managedfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var pkgMarkers = Markers{Start: "# Vulnetix Package Firewall", End: "# End Vulnetix Package Firewall"}
var aiMarkers = Markers{Start: "# Vulnetix AI Firewall", End: "# End Vulnetix AI Firewall"}

func TestUpsertAppendsAndReplaces(t *testing.T) {
	existing := "export PATH=/usr/bin\n"
	block := Block(pkgMarkers, "export GOPROXY=\"https://packages.vulnetix.com\"")

	got := Upsert(existing, block, pkgMarkers)
	if !strings.Contains(got, "export PATH=/usr/bin") {
		t.Fatalf("user content lost: %q", got)
	}
	if !strings.Contains(got, "export GOPROXY=") {
		t.Fatalf("block not written: %q", got)
	}

	// Re-running with the same block is a no-op.
	if again := Upsert(got, block, pkgMarkers); again != got {
		t.Fatalf("upsert not idempotent:\n%q\n%q", got, again)
	}

	// A new block replaces the old one rather than stacking.
	next := Block(pkgMarkers, "export GOPROXY=\"https://other\"")
	replaced := Upsert(got, next, pkgMarkers)
	if strings.Count(replaced, pkgMarkers.Start) != 1 {
		t.Fatalf("block duplicated: %q", replaced)
	}
	if strings.Contains(replaced, "packages.vulnetix.com") {
		t.Fatalf("old block content survived: %q", replaced)
	}
}

func TestRemoveKeepsSurroundingContent(t *testing.T) {
	existing := "before\n\n" + Block(pkgMarkers, "export GOPROXY=x") + "after\n"
	got, changed := Remove(existing, pkgMarkers)
	if !changed {
		t.Fatal("expected a block to be found")
	}
	if strings.Contains(got, "GOPROXY") || strings.Contains(got, pkgMarkers.Start) {
		t.Fatalf("block survived removal: %q", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Fatalf("user content lost: %q", got)
	}

	if _, changed := Remove("nothing here\n", pkgMarkers); changed {
		t.Fatal("expected no block to be found")
	}
}

// The whole reason Markers is a parameter: both firewalls write the same
// ~/.zshrc, and uninstalling one must not strip the other's block.
func TestTwoMarkerSetsCoexist(t *testing.T) {
	rc := "export PATH=/usr/bin\n"
	rc = Upsert(rc, Block(pkgMarkers, "export GOPROXY=\"https://packages.vulnetix.com\""), pkgMarkers)
	rc = Upsert(rc, EnvBlock("sh", aiMarkers, []KV{
		{Key: "OPENAI_BASE_URL", Value: "https://guardrails.vulnetix.com/openai/ORG/v1"},
	}), aiMarkers)

	if !strings.Contains(rc, "GOPROXY") || !strings.Contains(rc, "OPENAI_BASE_URL") {
		t.Fatalf("both blocks should be present: %q", rc)
	}

	afterPkgUninstall, changed := Remove(rc, pkgMarkers)
	if !changed {
		t.Fatal("package firewall block should have been found")
	}
	if strings.Contains(afterPkgUninstall, "GOPROXY") {
		t.Fatalf("package firewall block survived: %q", afterPkgUninstall)
	}
	if !strings.Contains(afterPkgUninstall, "OPENAI_BASE_URL") || !strings.Contains(afterPkgUninstall, aiMarkers.Start) {
		t.Fatalf("AI firewall block was collateral damage: %q", afterPkgUninstall)
	}
	if !strings.Contains(afterPkgUninstall, "export PATH=/usr/bin") {
		t.Fatalf("user content lost: %q", afterPkgUninstall)
	}
}

func TestEnvBlockDialects(t *testing.T) {
	vars := []KV{
		{Key: "OPENAI_BASE_URL", Value: "https://guardrails.vulnetix.com/openai/ORG/v1"},
		{Key: "OPENAI_API_KEY", Value: "$VULNETIX_API_KEY"},
	}
	for kind, want := range map[string]string{
		"fish": "set -gx OPENAI_API_KEY $VULNETIX_API_KEY",
		"csh":  "setenv OPENAI_API_KEY $VULNETIX_API_KEY",
		"sh":   "export OPENAI_API_KEY=\"$VULNETIX_API_KEY\"",
	} {
		got := EnvBlock(kind, aiMarkers, vars)
		if !strings.Contains(got, want) {
			t.Errorf("%s block missing %q:\n%s", kind, want, got)
		}
		// The key is referenced, never expanded: no literal secret in an rc file.
		if !strings.Contains(got, "$VULNETIX_API_KEY") {
			t.Errorf("%s block should reference the key variable, not inline it:\n%s", kind, got)
		}
	}
}

// R1: a whole-file write over a real user config must be recoverable. This is
// the bug the Package Firewall shipped with — ~/.m2/settings.xml was replaced
// with no backup, and uninstall then deleted it.
func TestStructuredWriteBacksUpAndRestores(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.xml")
	original := "<settings><!-- hand tuned --></settings>\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	file := File{Path: path, Content: "<settings>firewall</settings>\n", Structured: true}
	out, err := UpsertFile(file, pkgMarkers, false)
	if err != nil {
		t.Fatal(err)
	}
	if !out.BackedUp {
		t.Fatal("a structured write over an existing file must back it up")
	}
	if data, err := os.ReadFile(path + BackupSuffix); err != nil || string(data) != original {
		t.Fatalf("backup missing or wrong: %v %q", err, data)
	}

	rem, err := RemoveFile(file, pkgMarkers, "vulnetix.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if !rem.Restored {
		t.Fatal("uninstall should restore the backup, not delete the user's file")
	}
	if data, _ := os.ReadFile(path); string(data) != original {
		t.Fatalf("file not restored: %q", data)
	}
	if _, err := os.Stat(path + BackupSuffix); !os.IsNotExist(err) {
		t.Fatal("backup should be consumed on restore")
	}
}

// A structured file we created ourselves (no pre-existing user content, so no
// backup) is still ours to delete on uninstall.
func TestStructuredWriteWeCreatedIsDeleted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "remotes.json")
	file := File{Path: path, Content: `{"url":"https://packages.vulnetix.com/conan"}` + "\n", Structured: true}

	out, err := UpsertFile(file, pkgMarkers, false)
	if err != nil {
		t.Fatal(err)
	}
	if out.BackedUp {
		t.Fatal("nothing to back up for a file we created")
	}
	rem, err := RemoveFile(file, pkgMarkers, "packages.vulnetix.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if !rem.Deleted {
		t.Fatal("expected the file to be deleted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file should be gone")
	}
}

// A structured file the user has since replaced with their own content is left
// alone: it no longer points at us, so it is not ours to delete.
func TestStructuredWriteNotOursIsLeftAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "remotes.json")
	if err := os.WriteFile(path, []byte(`{"url":"https://center.conan.io"}`), 0600); err != nil {
		t.Fatal(err)
	}
	file := File{Path: path, Structured: true}
	rem, err := RemoveFile(file, pkgMarkers, "packages.vulnetix.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if rem.Configured || rem.Deleted {
		t.Fatalf("a file that does not point at us must not be touched: %+v", rem)
	}
	if !rem.Existed {
		t.Fatal("Existed should report the file was there")
	}
}

// A managed block gets no backup: removal is surgical, and restoring a stale
// backup would discard edits the user made after install.
func TestBlockWriteDoesNotBackUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".npmrc")
	if err := os.WriteFile(path, []byte("registry=https://registry.npmjs.org\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file := File{Path: path, Content: "//packages.vulnetix.com/npm/:_auth=abc"}

	out, err := UpsertFile(file, pkgMarkers, false)
	if err != nil {
		t.Fatal(err)
	}
	if out.BackedUp {
		t.Fatal("a managed block write must not create a backup")
	}
	if _, err := os.Stat(path + BackupSuffix); !os.IsNotExist(err) {
		t.Fatal("no backup file should exist")
	}

	rem, err := RemoveFile(file, pkgMarkers, "packages.vulnetix.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if !rem.Stripped {
		t.Fatalf("expected the block to be stripped: %+v", rem)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "registry=https://registry.npmjs.org\n" {
		t.Fatalf("user config not preserved byte-for-byte: %q", data)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	original := "[registries]\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	file := File{Path: path, Content: "token = \"abc\"", Structured: true}

	out, err := UpsertFile(file, pkgMarkers, true)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Changed {
		t.Fatal("dry run should still report that a change is pending")
	}
	if data, _ := os.ReadFile(path); string(data) != original {
		t.Fatalf("dry run wrote to the file: %q", data)
	}
	if _, err := os.Stat(path + BackupSuffix); !os.IsNotExist(err) {
		t.Fatal("dry run wrote a backup")
	}
}

func TestUpsertFileUnchangedIsNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf")
	file := File{Path: path, Content: "key=value", Structured: true}
	if _, err := UpsertFile(file, pkgMarkers, false); err != nil {
		t.Fatal(err)
	}
	out, err := UpsertFile(file, pkgMarkers, false)
	if err != nil {
		t.Fatal(err)
	}
	if out.Changed {
		t.Fatal("rewriting identical content should report no change")
	}
	if out.BackedUp {
		t.Fatal("an unchanged write must not churn a backup")
	}
}

func TestMergeBacksUpAndStripsWhenNoBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paru.conf")
	original := "[options]\nBottomUp\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	file := File{
		Path: path,
		Merge: func(existing string) (string, error) {
			return existing + "AurUrl = https://packages.vulnetix.com/aur\n", nil
		},
		Strip: func(_, existing string) (string, bool) {
			var kept []string
			changed := false
			for _, line := range strings.Split(existing, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "AurUrl") {
					changed = true
					continue
				}
				kept = append(kept, line)
			}
			return strings.Join(kept, "\n"), changed
		},
	}

	out, err := UpsertFile(file, pkgMarkers, false)
	if err != nil {
		t.Fatal(err)
	}
	if !out.BackedUp {
		t.Fatal("a merge over an existing file must back it up")
	}

	// With the backup deleted, removal falls back to stripping our keys.
	if err := os.Remove(path + BackupSuffix); err != nil {
		t.Fatal(err)
	}
	rem, err := RemoveFile(file, pkgMarkers, "packages.vulnetix.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if !rem.Stripped || rem.Restored {
		t.Fatalf("expected a strip, got %+v", rem)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "AurUrl") {
		t.Fatalf("our key survived: %q", data)
	}
	if !strings.Contains(string(data), "BottomUp") {
		t.Fatalf("user setting lost: %q", data)
	}
}

func TestEnvValuesUpsertAndRemove(t *testing.T) {
	keys := []string{"OPENAI_BASE_URL", "OPENAI_API_KEY"}
	existing := "DATABASE_URL=postgres://localhost\nOPENAI_BASE_URL=https://api.openai.com/v1\n"
	body := "OPENAI_BASE_URL=https://guardrails.vulnetix.com/openai/ORG/v1\nOPENAI_API_KEY=${VULNETIX_API_KEY}\n"

	got := UpsertEnvValues(existing, body, keys)
	if strings.Contains(got, "api.openai.com") {
		t.Fatalf("the old assignment should be replaced, not duplicated: %q", got)
	}
	if !strings.Contains(got, "DATABASE_URL=postgres://localhost") {
		t.Fatalf("unrelated variable lost: %q", got)
	}
	if strings.Count(got, "OPENAI_BASE_URL=") != 1 {
		t.Fatalf("duplicate assignment: %q", got)
	}

	back, changed := RemoveEnvValues(got, keys)
	if !changed {
		t.Fatal("expected assignments to be removed")
	}
	if strings.Contains(back, "OPENAI_") {
		t.Fatalf("our variables survived: %q", back)
	}
	if !strings.Contains(back, "DATABASE_URL=postgres://localhost") {
		t.Fatalf("unrelated variable lost: %q", back)
	}

	if _, changed := RemoveEnvValues("DATABASE_URL=x\n", keys); changed {
		t.Fatal("nothing of ours to remove")
	}
}

func TestIsEnvLineForms(t *testing.T) {
	for _, line := range []string{
		"GOPROXY=https://x",
		"export GOPROXY=\"https://x\"",
		"setenv GOPROXY https://x",
		"set -gx GOPROXY https://x",
	} {
		if !IsEnvLine(line, "GOPROXY") {
			t.Errorf("should match: %q", line)
		}
	}
	for _, line := range []string{
		"GOPROXYX=1",
		"# GOPROXY=https://x",
		"echo $GOPROXY",
	} {
		if IsEnvLine(line, "GOPROXY") {
			t.Errorf("should not match: %q", line)
		}
	}
}

func TestMaskSecret(t *testing.T) {
	if got := MaskSecret("short"); got != "****" {
		t.Errorf("short secret should be fully masked, got %q", got)
	}
	got := MaskSecret("abcdefghijklmnop")
	if strings.Contains(got, "efghijkl") {
		t.Errorf("secret body leaked: %q", got)
	}
	if got != "abcd...mnop" {
		t.Errorf("unexpected mask: %q", got)
	}
}
