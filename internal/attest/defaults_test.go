package attest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// defaults_test.go covers the choices made so a beginner does not have to.
//
// Each one has to hold two properties at once: it must be the right answer
// without configuration, and it must stay overridable. A default that cannot be
// overridden is a decision taken away from the user; one that is wrong out of
// the box is a flag they are forced to learn.

// TestIdentityIsExactNotAPattern pins the footgun. Every keyless subject is a
// URL, so a subject pasted into a pattern-matching flag has unescaped dots in
// it — and "." matches any character. Treating --identity as a regex means
// pasting the printed identity back silently accepts more than it names.
func TestIdentityIsExactNotAPattern(t *testing.T) {
	subject := "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
	f := newSigningFixture(t, subject, "https://token.actions.githubusercontent.com")
	envelope := f.writeDSSE(t, "exact.intoto.jsonl", []byte(`{}`))

	// The exact subject matches.
	res, err := Verify(Options{
		ArtifactPath: "exact", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
		Identity: subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified() {
		t.Fatalf("the exact subject did not match itself: %+v", res.Checks)
	}

	// A near-miss that a regex would have accepted must not match. Under regex
	// semantics every "." here is a wildcard, so this string matches the real
	// subject; under exact comparison it cannot.
	nearMiss := strings.ReplaceAll(subject, ".", "X")
	res, err = Verify(Options{
		ArtifactPath: "exact", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
		Identity: nearMiss,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified() {
		t.Error("--identity accepted a subject differing at every dot; it is matching as a pattern")
	}
}

// TestSuggestedIdentityPastesBack is the loop that has to close: the identity
// the command prints must be accepted verbatim by the flag it prints it for.
func TestSuggestedIdentityPastesBack(t *testing.T) {
	subject := "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
	f := newSigningFixture(t, subject, "https://token.actions.githubusercontent.com")
	envelope := f.writeDSSE(t, "paste.intoto.jsonl", []byte(`{}`))

	res, err := Verify(Options{
		ArtifactPath: "paste", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	var suggested string
	for _, s := range res.Suggestions {
		if after, ok := strings.CutPrefix(s.Flags, "--identity "); ok {
			suggested = strings.Trim(after, "'")
		}
	}
	if suggested == "" {
		t.Fatal("no --identity suggestion offered")
	}
	// No backslashes: the value is compared exactly, so escaping it would be
	// both unnecessary and wrong.
	if strings.Contains(suggested, `\`) {
		t.Errorf("the suggested identity is regex-escaped: %q", suggested)
	}

	res, err = Verify(Options{
		ArtifactPath: "paste", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
		Identity: suggested,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified() {
		t.Errorf("the suggested --identity value does not verify when pasted back: %+v", res.Checks)
	}
}

func TestIssuerShortcuts(t *testing.T) {
	if got := ExpandIssuer("github"); got != "https://token.actions.githubusercontent.com" {
		t.Errorf("ExpandIssuer(github) = %q", got)
	}
	if got := ExpandIssuer("GitHub"); got != "https://token.actions.githubusercontent.com" {
		t.Errorf("shortcuts must be case-insensitive, got %q", got)
	}
	// A full URL passes through unchanged, so the shortcut is an addition
	// rather than a replacement.
	const url = "https://auth.internal.example.com"
	if got := ExpandIssuer(url); got != url {
		t.Errorf("ExpandIssuer(%q) = %q, want it unchanged", url, got)
	}
	if names := IssuerShortcutNames(); len(names) == 0 {
		t.Error("no shortcut names offered for help text")
	}
}

// TestProjectTrustRootIsDiscovered covers the middle link of the chain: a team
// on a private Sigstore commits its root once, and nobody types the flag again.
func TestProjectTrustRootIsDiscovered(t *testing.T) {
	f := newSigningFixture(t, "https://example.com/signer", "https://issuer.example.com")
	envelope := f.writeDSSE(t, "project.intoto.jsonl", []byte(`{}`))

	projectRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectRoot, ".vulnetix"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(projectRoot, ProjectTrustRootPath), []byte(f.rootPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(Options{
		ArtifactPath: "project", EnvelopePath: envelope, ProjectRoot: projectRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified() {
		t.Fatalf("the project's own trust root was not discovered: %+v", res.Checks)
	}
	// And the output names which anchor answered, so "trusted" is never
	// ambiguous.
	if !strings.Contains(res.TrustAnchor, ProjectTrustRootPath) {
		t.Errorf("TrustAnchor = %q, want it to name the project root file", res.TrustAnchor)
	}

	// An explicit flag still wins over the project file.
	other := newSigningFixture(t, "https://example.com/other", "https://issuer.example.com")
	res, err = Verify(Options{
		ArtifactPath: "project", EnvelopePath: envelope, ProjectRoot: projectRoot,
		TrustedRootPath: other.rootPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified() {
		t.Error("--trusted-root did not override the project's file")
	}
}

// TestStrictNamesTheFlagsToAdd is the whole point of --strict for a beginner:
// it must not merely refuse, it must say what would satisfy it.
func TestStrictNamesTheFlagsToAdd(t *testing.T) {
	subject := "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
	f := newSigningFixture(t, subject, "https://token.actions.githubusercontent.com")
	envelope := f.writeDSSE(t, "strict.intoto.jsonl", []byte(`{}`))

	res, err := Verify(Options{
		ArtifactPath: "strict", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
		Strict: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified() {
		t.Fatal("--strict passed with nothing pinned")
	}
	c := checkNamed(res, "strict")
	if c == nil || c.Status != CheckFailed {
		t.Fatalf("strict check = %+v, want failed", c)
	}
	for _, want := range []string{"--identity", subject, "--issuer"} {
		if !strings.Contains(c.Detail, want) {
			t.Errorf("the --strict failure does not name %q: %s", want, c.Detail)
		}
	}

	// Pinned, it passes.
	res, err = Verify(Options{
		ArtifactPath: "strict", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
		Strict: true, Identity: subject, Issuer: "github",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified() {
		t.Errorf("--strict failed with everything pinned: %+v", res.Checks)
	}
}

// TestSignerRepositoryIsNoted covers the zero-config signal. "Signed by
// github.com/acme/repo" is not an answer until the reader knows whether that is
// their repository.
func TestSignerRepositoryIsNoted(t *testing.T) {
	f := newSigningFixture(t,
		"https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main",
		"https://token.actions.githubusercontent.com")
	envelope := f.writeDSSE(t, "repo.intoto.jsonl", []byte(`{}`))

	same, err := Verify(Options{
		ArtifactPath: "repo", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
		RepoFullName: "acme/repo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !same.SignerIsThisRepo {
		t.Error("a signature from the scanned repository was not recognised as such")
	}

	other, err := Verify(Options{
		ArtifactPath: "repo", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
		RepoFullName: "someone-else/thing",
	})
	if err != nil {
		t.Fatal(err)
	}
	if other.SignerIsThisRepo {
		t.Error("a signature from a different repository was reported as this one")
	}
	if other.SignerRepo != "acme/repo" {
		t.Errorf("SignerRepo = %q, want the signer's repository", other.SignerRepo)
	}

	// It is a note, not a check: a third-party artefact legitimately comes from
	// a third party, and failing on that by default would break the case this
	// is most needed for.
	if !other.Verified() {
		t.Error("a signature from another repository failed verification; it should only be noted")
	}
}

func TestGithubRepoFromSubject(t *testing.T) {
	tests := map[string]string{
		"https://github.com/acme/repo/.github/workflows/x.yml@refs/heads/main": "acme/repo",
		"https://github.com/acme/repo":                                         "acme/repo",
		// Anything not shaped like a GitHub workflow identity yields nothing,
		// rather than a confident and wrong "not your repository".
		"https://gitlab.com/acme/repo//.gitlab-ci.yml@refs/heads/main": "",
		"mailto:person@example.com":                                    "",
		"https://github.com/acme":                                      "",
		"":                                                             "",
	}
	for subject, want := range tests {
		if got := githubRepoFromSubject(subject); got != want {
			t.Errorf("githubRepoFromSubject(%q) = %q, want %q", subject, got, want)
		}
	}
}
