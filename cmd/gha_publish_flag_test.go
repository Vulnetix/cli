package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/pipeline"
)

// Every scan-family command a generated action wraps takes --github-publish.
// sca did not, so the sca action failed with "unknown flag" as soon as
// github-code-scanning or dependency-graph was true.
func TestScanCommandsAcceptGitHubPublish(t *testing.T) {
	for _, name := range []string{"scan", "sca", "sast", "secrets", "iac", "containers"} {
		for _, flag := range []string{"github-publish", "github-publish-dry-run"} {
			ok, err := CommandAcceptsFlag([]string{name}, flag)
			if err != nil || !ok {
				t.Errorf("vulnetix %s does not accept --%s (err %v)", name, flag, err)
			}
		}
	}
}

func TestGitHubPublishDryRunSubmitsNothing(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".vulnetix"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	opts := pipeline.Options{GitHubPublish: []string{"code-scanning"}, GitHubPublishDryRun: true}
	publishScanToGitHub(context.Background(), opts, root, nil, []string{"sca"}, &out)
	if strings.Contains(out.String(), "warning") || !strings.Contains(out.String(), "dry run") {
		t.Fatalf("a dry run needs no token and uploads nothing:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".vulnetix", "code-scanning", "sca.sarif")); err != nil {
		t.Fatalf("the per-kind file should be written: %v", err)
	}
}
