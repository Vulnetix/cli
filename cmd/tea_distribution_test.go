package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTeaTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The checksums file is what a user verifies a download against. Publishing
// distributions from it — rather than recomputing digests — is what makes the
// checksum a consumer reads through TEA the same string the project published.
func TestDistributionsFromChecksums(t *testing.T) {
	const digestA = "b9f62ff7cb04a2ff7418f11d7777e060b09820ad3ee5b60ed45439d433d70a7e"
	const digestB = "8aad93860379845fd8a8138a96f3585554924270b476408dac61b9baebaa57f9"
	path := writeTeaTemp(t, "checksums.txt",
		digestA+"  vulnetix-linux-amd64\n"+
			digestB+" *vulnetix-windows-amd64.exe\n"+
			"\n"+
			digestA+"  install.sh\n"+
			digestB+"  checksums.txt\n")

	got, err := distributionsFromChecksums(path,
		"https://github.com/Vulnetix/cli/releases/download/v3.81.0/", []string{"install.sh"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d distributions, want 2 — --exclude and the manifest itself should both be dropped: %+v", len(got), got)
	}
	if got[0].URL != "https://github.com/Vulnetix/cli/releases/download/v3.81.0/vulnetix-linux-amd64" {
		t.Errorf("url: %s", got[0].URL)
	}
	if len(got[0].Checksums) != 1 || got[0].Checksums[0].AlgValue != digestA {
		t.Errorf("checksum was not carried through verbatim: %+v", got[0].Checksums)
	}
	if got[0].Checksums[0].AlgType != "SHA-256" {
		t.Errorf("algType %q is not the spelling the TEA checksum enum uses", got[0].Checksums[0].AlgType)
	}
	// GNU coreutils marks binary mode with a leading `*`, which is not part of
	// the file name and must not end up in the URL.
	if got[1].URL != "https://github.com/Vulnetix/cli/releases/download/v3.81.0/vulnetix-windows-amd64.exe" {
		t.Errorf("binary-mode marker leaked into the URL: %s", got[1].URL)
	}
}

// A manifest we only half understand would publish a partial set of links while
// looking complete, so anything unparseable stops the whole thing.
func TestDistributionsFromChecksumsRefusesGarbage(t *testing.T) {
	cases := map[string]string{
		"truncated digest": "abc123  vulnetix-linux-amd64\n",
		"no file name":     "b9f62ff7cb04a2ff7418f11d7777e060b09820ad3ee5b60ed45439d433d70a7e\n",
		"not hex":          "zzzzzzzzcb04a2ff7418f11d7777e060b09820ad3ee5b60ed45439d433d70a7e  x\n",
	}
	for name, content := range cases {
		path := writeTeaTemp(t, "checksums.txt", content)
		if _, err := distributionsFromChecksums(path, "https://example.com/v1", nil); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	// A relative base would resolve against whatever origin the consumer is on.
	good := writeTeaTemp(t, "checksums.txt",
		"b9f62ff7cb04a2ff7418f11d7777e060b09820ad3ee5b60ed45439d433d70a7e  x\n")
	if _, err := distributionsFromChecksums(good, "/releases/download", nil); err == nil {
		t.Error("a relative --base-url was accepted")
	}
}

// A typo that silently drops a URL publishes a channel with no way to reach it,
// so unknown keys are refused rather than ignored.
func TestParseChannelSpec(t *testing.T) {
	d, err := parseChannelSpec("name=Homebrew tap,url=https://github.com/Vulnetix/homebrew-tap")
	if err != nil {
		t.Fatal(err)
	}
	if d.Description != "Homebrew tap" || d.URL != "https://github.com/Vulnetix/homebrew-tap" {
		t.Errorf("parsed as %+v", d)
	}

	// Homebrew and Scoop have no accepted purl type, so most channels carry
	// none — but one may be given where it genuinely resolves.
	withPurl, err := parseChannelSpec("name=npm,purl=pkg:npm/vulnetix@3.81.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(withPurl.Identifiers) != 1 || withPurl.Identifiers[0].IDType != "PURL" {
		t.Errorf("identifiers: %+v", withPurl.Identifiers)
	}

	for _, bad := range []string{
		"url=https://example.com",  // no name
		"name=Scoop,uri=https://x", // typo for url
		"Homebrew tap",             // not key=value
	} {
		if _, err := parseChannelSpec(bad); err == nil {
			t.Errorf("--channel %q was accepted", bad)
		}
	}
}

// Guessing github.com inside a GitHub Enterprise run would publish download
// links pointing at an instance the release does not exist on.
func TestGitHubDownloadBase(t *testing.T) {
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	if got := teaGitHubDownloadBase("Vulnetix/cli", "v3.81.0"); got !=
		"https://github.com/Vulnetix/cli/releases/download/v3.81.0" {
		t.Errorf("got %q", got)
	}
	t.Setenv("GITHUB_SERVER_URL", "https://ghe.example.com/")
	if got := teaGitHubDownloadBase("Vulnetix/cli", "v3.81.0"); got !=
		"https://ghe.example.com/Vulnetix/cli/releases/download/v3.81.0" {
		t.Errorf("enterprise host was not honoured: %q", got)
	}

	t.Setenv("GITHUB_SERVER_URL", "")
	if got := teaGitHubDownloadBase("Vulnetix/cli", "v3.81.0"); got != "" {
		t.Errorf("a base was invented outside GitHub Actions: %q", got)
	}
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	if got := teaGitHubDownloadBase("not-a-repo", "v1"); got != "" {
		t.Errorf("a base was built from something that is not owner/repo: %q", got)
	}
}
