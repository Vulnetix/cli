package license

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// ghAPIDirect must answer every request the licence lookups make exactly as
// `gh api ... --jq` does: the same bytes on success, an error where gh fails,
// and "HTTP 404" in the error exactly where gh's says so (that decides whether
// a miss is stored). It talks to the live API, so it runs only when
// VULNETIX_GH_PARITY is set and gh is signed in.
func TestGHAPIDirectMatchesGH(t *testing.T) {
	if os.Getenv("VULNETIX_GH_PARITY") == "" {
		t.Skip("set VULNETIX_GH_PARITY=1 to compare against the live GitHub API")
	}
	if ghAuthToken() == "" {
		t.Skip("gh is not signed in")
	}
	repos := []string{
		// The repositories a scan of this repository looks up.
		"actions/checkout", "actions/deploy-pages", "actions/download-artifact", "actions/setup-go",
		"actions/setup-node", "actions/upload-artifact", "actions/upload-pages-artifact",
		"alecthomas/chroma", "anchore/sbom-action", "anchore/scan-action", "aquasecurity/tfsec-sarif-action",
		"aquasecurity/trivy-action", "astral-sh/setup-uv", "aws-actions/configure-aws-credentials",
		"cloudflare/circl", "cloudflare/cloudflare", "cloudflare/terraform-provider-cloudflare",
		"cyphar/filepath-securejoin", "davecgh/go-spew", "decred/dcrd", "dustin/go-humanize",
		"emirpasic/gods", "glaslos/ssdeep", "godbus/dbus", "go-git/gcfg", "golangci/golangci-lint-action",
		"google/osv-scanner-action", "gorilla/websocket", "hadolint/hadolint-action", "kevinburke/ssh_config",
		"klauspost/compress", "munnerz/goautoneg", "peaceiris/actions-hugo", "pmezard/go-difflib",
		"rcrowley/go-metrics", "segmentio/asm", "sigstore/cosign-installer", "xeipuuv/gojsonpointer",
		"xeipuuv/gojsonreference",
		// A missing repository, and one GitHub serves through a redirect.
		"vulnetix/no-such-repository-for-parity", "golang/lint",
	}
	type req struct{ path, expr string }
	for _, r := range repos {
		for _, q := range []req{
			{"repos/" + r, jqSPDX},
			{"repos/" + r + "/license", jqSPDX},
			{"repos/" + r + "/license", jqContent},
			{"repos/" + r + "/contents/", jqLicDir},
			{"repos/" + r + "/contents/LICENSE", jqContent},
			{"repos/" + r + "/contents/COPYING.md", jqContent},
		} {
			cmd := exec.Command("gh", "api", q.path, "--jq", q.expr)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			want, wantErr := cmd.Output()
			got, ok, gotErr := ghAPIDirect(q.path, q.expr)
			if !ok {
				t.Fatalf("%s %s: not answered in process", q.path, q.expr)
			}
			if (wantErr != nil) != (gotErr != nil) {
				t.Fatalf("%s %s: gh error %v (%s), direct error %v", q.path, q.expr, wantErr, stderr.String(), gotErr)
			}
			if wantErr != nil {
				want404 := strings.Contains(stderr.String(), "HTTP 404")
				got404 := strings.Contains(gotErr.Error(), "HTTP 404")
				if want404 != got404 {
					t.Fatalf("%s %s: gh says %q, direct says %q", q.path, q.expr, stderr.String(), gotErr)
				}
				continue
			}
			if !bytes.Equal(want, got) {
				t.Fatalf("%s %s: gh printed %q, direct %q", q.path, q.expr, want, got)
			}
		}
	}
}

func TestRenderGHJQ(t *testing.T) {
	cases := []struct{ body, expr, want string }{
		{`{"license":{"spdx_id":"MIT"}}`, jqSPDX, "MIT\n"},
		{`{"license":null}`, jqSPDX, "\n"},
		{`{"name":"x"}`, jqSPDX, "\n"},
		{`{"content":"TUlU\nTGlj\n"}`, jqContent, "TUlU\nTGlj\n\n"},
		{`{"content":null}`, jqContent, "\n"},
		{`[{"name":"LICENSE"},{"name":"main.go"},{"name":"Copying.txt"},{"name":"licence-notes"}]`, jqLicDir, "LICENSE\nCopying.txt\nlicence-notes\n"},
		{`[]`, jqLicDir, ""},
	}
	for _, c := range cases {
		got, err := renderGHJQ([]byte(c.body), c.expr)
		if err != nil || string(got) != c.want {
			t.Fatalf("%s over %s: got %q, %v; want %q", c.expr, c.body, got, err, c.want)
		}
	}
	if _, err := renderGHJQ([]byte(`{"name":"x"}`), jqLicDir); err == nil {
		t.Fatal("iterating an object is an error, as in jq")
	}
}
