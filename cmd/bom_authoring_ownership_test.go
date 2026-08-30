package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// bom_authoring_ownership_test.go — invariant locks, in the style of
// scan_flag_ownership_test.go.
//
// These are source-walking tests rather than behaviour tests, and they exist
// because the defect they prevent is not one a behaviour test would catch. Every
// individual emitting path here was correct in isolation; what went wrong was
// that there were six of them, each assembling its own answer to "who produced
// this document", and they disagreed. One emitted a tool entry with no version
// at all, four defaulted the version to the literal string "cli", and all of
// them claimed the same lifecycle phase regardless of what they had read.
//
// A test that a given command emits a sensible document would have passed
// throughout. What is worth asserting is that there is exactly one place the
// answer comes from.
// ─────────────────────────────────────────────────────────────────────────────

// repoGoFiles walks the repository's non-test Go sources.
func repoGoFiles(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range []string{".", "../internal", "../pkg"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			out[filepath.ToSlash(filepath.Clean(path))] = string(data)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	if len(out) == 0 {
		t.Fatal("found no Go sources; the walk roots are wrong")
	}
	return out
}

// The tool entry is this product's identity on every document it touches. It is
// built in one place so that it cannot be built two ways — which is what
// produced six tool names, two of them versionless, for one program.
func TestOnlyOneFileBuildsTheVulnetixToolEntry(t *testing.T) {
	const owner = "../internal/cdx/authorship.go"
	for path, src := range repoGoFiles(t) {
		if path == owner {
			continue
		}
		if strings.Contains(src, "cyclonedx.VulnetixTool(") {
			t.Errorf("%s builds a tool entry directly; call cdx.Authoring or cdx.Participating, which live in %s", path, owner)
		}
	}
}

// The version a tool entry reports must come from the build, not from a literal.
// Four builders defaulted it to "cli", which is not a version: every consumer
// that tried to compare it got a parse failure rather than an answer.
func TestNoToolEntryClaimsALiteralVersion(t *testing.T) {
	for path, src := range repoGoFiles(t) {
		for _, bad := range []string{`ToolVersion: "cli"`, `ToolVersion:    "cli"`, `Version: "cli"`} {
			if strings.Contains(src, bad) {
				t.Errorf(`%s sets a tool version to the literal "cli"`, path)
			}
		}
	}
}

// metadata.manufacturer says who created the BOM. Resolving it in more than one
// place is how it would come to mean the running organization in one document
// and the tool vendor in the next, with nothing in either to say which.
func TestOnlyOneFileResolvesTheManufacturer(t *testing.T) {
	const owner = "../internal/cdx/authorship.go"
	for path, src := range repoGoFiles(t) {
		if path == owner {
			continue
		}
		if strings.Contains(src, "Manufacturer:") && strings.Contains(src, "OrganizationalEntity{") {
			t.Errorf("%s builds a manufacturer directly; use cdx.ResolveManufacturer in %s", path, owner)
		}
	}
}

// The lifecycle phase is a claim about what the pass observed. Deriving it in
// several places is how every builder came to hardcode `build` — including for
// a manifest read, where nothing has been built yet.
func TestOnlyOneFileDerivesLifecyclePhases(t *testing.T) {
	const owner = "../internal/cdx/authorship.go"
	for path, src := range repoGoFiles(t) {
		if path == owner {
			continue
		}
		if strings.Contains(src, `Lifecycle{Phase:`) || strings.Contains(src, `Lifecycles: []`) {
			t.Errorf("%s builds lifecycle entries directly; use cdx.DerivePhases in %s", path, owner)
		}
	}
}

// A property name appears once in a CycloneDX properties array. Five copies of
// this upsert existed, and one of them was a plain append — so re-running that
// pass left the document asserting the same property twice with different
// values, which a consumer resolves by picking one arbitrarily.
func TestNothingReimplementsThePropertyUpsert(t *testing.T) {
	for path, src := range repoGoFiles(t) {
		if strings.Contains(src, "Properties[i].Name == name") {
			t.Errorf("%s reimplements the property upsert; use SetProperty", path)
		}
	}
}
