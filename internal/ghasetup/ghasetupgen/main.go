// Command ghasetupgen renders the third-party scanner documentation from the
// single source of truth: the embedded catalog (internal/ghasetup/catalog).
//
// It writes:
//   - website/content/docs/ci-cd/third-party-scanners.md
//
// Every workflow example on that page is produced by the same Render() that
// `vulnetix gha setup` writes to a repository, so a reader is looking at the
// exact job that will run. Run via:
//
//	just gen-gha-setup    # go run ./internal/ghasetup/ghasetupgen
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/ghasetup"
)

func main() {
	c, err := ghasetup.Load()
	if err != nil {
		fail(err)
	}
	if err := os.MkdirAll(filepath.Join("website", "content", "docs", "ci-cd"), 0o755); err != nil {
		fail(err)
	}
	out := filepath.Join("website", "content", "docs", "ci-cd", "third-party-scanners.md")
	if err := os.WriteFile(out, []byte(render(c)), 0o644); err != nil {
		fail(err)
	}
	fmt.Println("wrote", out)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ghasetupgen:", err)
	os.Exit(1)
}

func render(c *ghasetup.Catalog) string {
	var b strings.Builder

	b.WriteString("---\n")
	b.WriteString("title: \"Third-Party Scanners\"\n")
	b.WriteString("weight: 2\n")
	b.WriteString("description: \"Publish gosec, Semgrep, Trivy, Grype, Checkov, KICS and other scanner reports to Vulnetix from GitHub Actions, attributed to the tool that produced them.\"\n")
	b.WriteString("---\n\n")

	b.WriteString("{{< callout type=\"info\" >}}\n")
	b.WriteString("This page is generated from the same catalog `vulnetix gha setup` writes from, so every\n")
	b.WriteString("example here is the exact job the command produces. Regenerate with `just gen-gha-setup`.\n")
	b.WriteString("{{< /callout >}}\n\n")

	b.WriteString("Vulnetix ingests reports from the scanners you already run. Each one is recorded\n")
	b.WriteString("under its own name and version, in its own scan category, alongside your\n")
	b.WriteString("first-party Vulnetix scans.\n\n")

	b.WriteString("## The quickest way\n\n")
	b.WriteString("From inside the repository:\n\n")
	b.WriteString("```sh\n")
	b.WriteString("vulnetix gha setup --list        # what is available\n")
	b.WriteString("vulnetix gha setup gosec         # write the workflow\n")
	b.WriteString("vulnetix gha setup trivy-fs      # add another; the first is kept\n")
	b.WriteString("```\n\n")
	b.WriteString("That writes `.github/workflows/vulnetix-scanners.yml`. Set two repository\n")
	b.WriteString("secrets and push:\n\n")
	b.WriteString("| Secret | Value |\n|---|---|\n")
	b.WriteString("| `VULNETIX_ORG_ID` | your organisation uuid |\n")
	b.WriteString("| `VULNETIX_API_KEY` | an API key for that organisation |\n\n")
	b.WriteString("After the run, `vulnetix gha status` reports what landed.\n\n")

	b.WriteString("## How it fits together\n\n")
	b.WriteString("Each scanner runs as its own job and uploads its report as a workflow artifact.\n")
	b.WriteString("A single `publish` job then hands every artifact to Vulnetix at once.\n\n")
	b.WriteString("Three details in that workflow are load-bearing, and all three fail silently\n")
	b.WriteString("when they are wrong:\n\n")
	b.WriteString("- **`publish` must depend on every scanner.** A job missing from `needs` still\n")
	b.WriteString("  runs and still uploads its artifact, but the publish job may start before it\n")
	b.WriteString("  finishes, and its report is never sent. Nothing in the log says so.\n")
	b.WriteString("- **`publish` must set `if: always()`.** Without it, one failing scanner\n")
	b.WriteString("  suppresses the publication of every other scanner's results.\n")
	b.WriteString("- **`publish` needs `permissions: actions: read`.** That is what lets the CLI\n")
	b.WriteString("  list the run's artifacts. Without it there is nothing to publish.\n\n")

	b.WriteString("### Writing SARIF through a shell redirect\n\n")
	b.WriteString("Several tools print SARIF to stdout, and the obvious `tool > out.sarif || true`\n")
	b.WriteString("is wrong in three ways at once: stdout also carries the tool's own log lines,\n")
	b.WriteString("`|| true` hides the exit code, and a failed run leaves a zero-byte or\n")
	b.WriteString("half-written file. `if-no-files-found` cannot catch that last one, because the\n")
	b.WriteString("file exists, so a broken scan gets uploaded as a report.\n\n")
	b.WriteString("The generated jobs separate stderr, handle the exit codes that mean success\n")
	b.WriteString("(terrascan exits `3` on violations and `5` when it finds no IaC; zizmor exits\n")
	b.WriteString("`14` when it has findings), and validate the result with `jq`, deleting it if it\n")
	b.WriteString("is not a SARIF document. A scanner that fails then produces no artifact rather\n")
	b.WriteString("than a corrupt one.\n\n")

	b.WriteString("## Versions\n\n")
	b.WriteString("The Vulnetix CLI is installed **unpinned**: `install.sh` resolves the latest\n")
	b.WriteString("release, so a workflow written today keeps working without anyone coming back\n")
	b.WriteString("to bump a version.\n\n")
	b.WriteString("The third-party scanners are **pinned**, because there a reproducible scan\n")
	b.WriteString("matters more than being current: an unpinned scanner can change its output\n")
	b.WriteString("shape without any change to your repository.\n\n")

	// Per-tool sections.
	tools := append([]ghasetup.Tool(nil), c.Tools...)
	sort.Slice(tools, func(i, j int) bool {
		if tools[i].Category != tools[j].Category {
			return tools[i].Category < tools[j].Category
		}
		return tools[i].ID < tools[j].ID
	})

	b.WriteString("## Supported scanners\n\n")
	b.WriteString("| Tool | Category | Report |\n|---|---|---|\n")
	for _, t := range tools {
		fmt.Fprintf(&b, "| [%s](#%s) | %s | `%s` |\n", t.Name, t.ID, t.Category, strings.Join(t.Paths, "`, `"))
	}
	b.WriteString("\n")

	for _, t := range tools {
		fmt.Fprintf(&b, "### %s {#%s}\n\n", t.Name, t.ID)
		fmt.Fprintf(&b, "%s\n\n", t.Description)
		if t.Note != "" {
			fmt.Fprintf(&b, "{{< callout type=\"warning\" >}}\n%s\n{{< /callout >}}\n\n", t.Note)
		}
		fmt.Fprintf(&b, "```sh\nvulnetix gha setup %s\n```\n\n", t.ID)

		job, err := renderSingleJob(c, t.ID)
		if err != nil {
			fail(err)
		}
		fmt.Fprintf(&b, "The job it adds:\n\n```yaml\n%s```\n\n", job)
	}

	b.WriteString("## A complete workflow\n\n")
	b.WriteString("Setting up several tools produces one file. This is `gosec`, `semgrep` and\n")
	b.WriteString("`trivy-fs` together, verbatim:\n\n")
	full, err := ghasetup.Render(c, []string{"gosec", "semgrep", "trivy-fs"}, ghasetup.Options{})
	if err != nil {
		fail(err)
	}
	fmt.Fprintf(&b, "```yaml\n%s```\n\n", full)

	b.WriteString("## Self-hosted runners\n\n")
	b.WriteString("```sh\nvulnetix gha setup gosec --runs-on self-hosted,Linux,X64\n```\n\n")

	b.WriteString("## Checking what landed\n\n")
	b.WriteString("A green check is not proof that anything was published. `gha upload` exits\n")
	b.WriteString("non-zero when a report fails to publish, and `gha status` reports what the run\n")
	b.WriteString("actually recorded:\n\n")
	b.WriteString("```sh\n")
	b.WriteString("vulnetix gha status                    # the current run, inside a workflow\n")
	b.WriteString("vulnetix gha status --run-id 30178087483\n")
	b.WriteString("vulnetix gha status --json\n")
	b.WriteString("```\n\n")
	b.WriteString("Each tool appears with its own name, version, category and finding counts. A\n")
	b.WriteString("tool you set up that is missing from that list did not publish.\n\n")

	b.WriteString("## A tool that is not listed\n\n")
	b.WriteString("Any scanner that writes SARIF, CycloneDX or SPDX can be published. Upload its\n")
	b.WriteString("report as an artifact and the publish job picks it up. The catalog exists to\n")
	b.WriteString("save you writing the job, not to restrict what Vulnetix accepts.\n\n")
	b.WriteString("The category and the tool's identity are read from the report itself, so a\n")
	b.WriteString("scanner Vulnetix has never seen is still attributed correctly.\n")

	return b.String()
}

// renderSingleJob renders one tool's job on its own, by rendering a workflow for
// just that tool and slicing out the job block. Doing it this way rather than
// exporting the job renderer keeps a single code path: what the page shows is
// literally what the command writes.
func renderSingleJob(c *ghasetup.Catalog, id string) (string, error) {
	full, err := ghasetup.Render(c, []string{id}, ghasetup.Options{})
	if err != nil {
		return "", err
	}
	start := strings.Index(full, "\n  "+id+":\n")
	if start < 0 {
		return "", fmt.Errorf("job %q not found in rendered workflow", id)
	}
	rest := full[start+1:]
	end := strings.Index(rest, "\n  publish:\n")
	if end < 0 {
		return "", fmt.Errorf("publish job not found after %q", id)
	}
	return rest[:end+1], nil
}
