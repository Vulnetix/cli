package ghasetup

import (
	"fmt"
	"sort"
	"strings"
)

// WorkflowPath is the file `gha setup` manages, relative to the repository root.
//
// It is deliberately separate from any hand-written workflow: the file is
// regenerated in full on every `gha setup`, so it must not be somewhere a user
// keeps their own jobs.
const WorkflowPath = ".github/workflows/vulnetix-scanners.yml"

// managedHeader marks the file as generated. `gha setup` refuses to overwrite a
// file that does not carry it, so a hand-written workflow that happens to sit at
// WorkflowPath is never silently destroyed.
const managedHeader = "# Managed by `vulnetix gha setup`."

// Options controls how the workflow is rendered.
type Options struct {
	// SelfHostedLabels, when set, replaces `ubuntu-latest` on every job.
	SelfHostedLabels []string
	// OrgID is written into the publish job's env as a literal only when the
	// caller explicitly asks; otherwise the secret reference is used, which is
	// what almost every repository wants.
	OrgIDLiteral string
}

// Render produces the complete workflow for the given tool ids.
//
// The Vulnetix CLI is installed unpinned on purpose. install.sh resolves the
// latest release, so a workflow written today keeps working without anyone
// coming back to bump a version — which is exactly how a fleet ends up spread
// across three different CLI versions. Third-party scanners are pinned, because
// there the reproducibility of the scan matters more than being current.
func Render(c *Catalog, ids []string, opt Options) (string, error) {
	tools := make([]*Tool, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		t, ok := c.Find(id)
		if !ok {
			return "", fmt.Errorf("unknown tool %q", id)
		}
		if seen[t.ID] {
			continue
		}
		seen[t.ID] = true
		tools = append(tools, t)
	}
	if len(tools) == 0 {
		return "", fmt.Errorf("no tools selected")
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].ID < tools[j].ID })

	runsOn := "ubuntu-latest"
	if len(opt.SelfHostedLabels) > 0 {
		runsOn = "[" + strings.Join(opt.SelfHostedLabels, ", ") + "]"
	}

	var b strings.Builder
	b.WriteString(managedHeader + "\n")
	b.WriteString("# Re-run `vulnetix gha setup <tool>` to add a scanner; edits here are overwritten.\n")
	b.WriteString("#\n")
	b.WriteString("# Each scanner runs independently and uploads its report as a workflow\n")
	b.WriteString("# artifact. The publish job then hands every artifact to Vulnetix in one go,\n")
	b.WriteString("# attributed to the tool that produced it.\n")
	b.WriteString("\nname: Third-Party Scanners\n\n")
	b.WriteString("on:\n  push:\n  workflow_dispatch:\n\n")
	b.WriteString("permissions:\n  contents: read\n\n")
	b.WriteString("jobs:\n")

	for _, t := range tools {
		b.WriteString(renderJob(t, runsOn))
	}

	b.WriteString(renderPublish(tools, runsOn, opt))
	return b.String(), nil
}

func renderJob(t *Tool, runsOn string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %s:\n", t.ID)
	fmt.Fprintf(&b, "    name: %s\n", yamlScalar(t.JobName))
	fmt.Fprintf(&b, "    runs-on: %s\n", runsOn)
	b.WriteString("    steps:\n")
	b.WriteString("      - uses: actions/checkout@v5\n")

	for _, s := range t.Steps {
		b.WriteString(renderStep(s))
	}

	// if-no-files-found: warn, not error. A scanner that legitimately found
	// nothing to scan should not fail the run; a scanner that broke is caught by
	// the SARIF validation in its own step.
	fmt.Fprintf(&b, "      - uses: actions/upload-artifact@v6\n")
	b.WriteString("        with:\n")
	fmt.Fprintf(&b, "          name: %s\n", t.Artifact)
	if len(t.Paths) == 1 {
		fmt.Fprintf(&b, "          path: %s\n", t.Paths[0])
	} else {
		b.WriteString("          path: |\n")
		for _, p := range t.Paths {
			fmt.Fprintf(&b, "            %s\n", p)
		}
	}
	b.WriteString("          if-no-files-found: warn\n")
	b.WriteString("          include-hidden-files: true\n")
	b.WriteString("          retention-days: 7\n\n")
	return b.String()
}

func renderStep(s Step) string {
	var b strings.Builder
	if s.Name != "" {
		fmt.Fprintf(&b, "      - name: %s\n", yamlScalar(s.Name))
	} else {
		b.WriteString("      -\n")
	}
	if s.ID != "" {
		fmt.Fprintf(&b, "        id: %s\n", s.ID)
	}
	// Every scanner step tolerates failure: one broken scanner must not stop the
	// others from publishing.
	b.WriteString("        continue-on-error: true\n")

	if len(s.Env) > 0 {
		b.WriteString("        env:\n")
		for _, k := range sortedKeys(s.Env) {
			fmt.Fprintf(&b, "          %s: %s\n", k, yamlScalar(s.Env[k]))
		}
	}
	if s.Uses != "" {
		fmt.Fprintf(&b, "        uses: %s\n", s.Uses)
		if len(s.With) > 0 {
			b.WriteString("        with:\n")
			for _, k := range sortedAnyKeys(s.With) {
				b.WriteString(renderWith(k, s.With[k]))
			}
		}
	}
	if s.Run != "" {
		b.WriteString("        run: |\n")
		for _, line := range strings.Split(strings.TrimRight(s.Run, "\n"), "\n") {
			if line == "" {
				b.WriteString("\n")
				continue
			}
			fmt.Fprintf(&b, "          %s\n", line)
		}
	}
	return b.String()
}

// renderWith emits one `with:` entry, using a block scalar for multi-line
// values (osv-scanner's scan-args is newline separated).
func renderWith(k string, v any) string {
	switch val := v.(type) {
	case string:
		if strings.Contains(val, "\n") {
			var b strings.Builder
			fmt.Fprintf(&b, "          %s: |-\n", k)
			for _, line := range strings.Split(strings.TrimRight(val, "\n"), "\n") {
				fmt.Fprintf(&b, "            %s\n", line)
			}
			return b.String()
		}
		return fmt.Sprintf("          %s: %s\n", k, yamlScalar(val))
	case bool:
		return fmt.Sprintf("          %s: %t\n", k, val)
	default:
		return fmt.Sprintf("          %s: %v\n", k, val)
	}
}

func renderPublish(tools []*Tool, runsOn string, opt Options) string {
	needs := make([]string, 0, len(tools))
	for _, t := range tools {
		needs = append(needs, t.ID)
	}

	orgID := "${{ secrets.VULNETIX_ORG_ID }}"
	if opt.OrgIDLiteral != "" {
		orgID = opt.OrgIDLiteral
	}

	var b strings.Builder
	b.WriteString("  publish:\n")
	b.WriteString("    name: Publish to Vulnetix\n")
	fmt.Fprintf(&b, "    runs-on: %s\n", runsOn)
	fmt.Fprintf(&b, "    needs: [%s]\n", strings.Join(needs, ", "))
	// always(): a scanner that failed must not stop the others being published.
	b.WriteString("    if: always()\n")
	b.WriteString("    permissions:\n")
	b.WriteString("      contents: read\n")
	// actions: read is what lets the CLI list this run's artifacts.
	b.WriteString("      actions: read\n")
	b.WriteString("    env:\n")
	fmt.Fprintf(&b, "      VULNETIX_ORG_ID: %s\n", orgID)
	b.WriteString("      VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}\n")
	b.WriteString("    steps:\n")
	b.WriteString("      - uses: actions/checkout@v5\n")
	b.WriteString("      - name: Install Vulnetix CLI\n")
	// No --version: install.sh resolves the latest release, so this workflow
	// does not go stale and never needs a version bump commit.
	b.WriteString("        run: |\n")
	b.WriteString("          curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir \"$HOME/.local/bin\"\n")
	b.WriteString("          echo \"$HOME/.local/bin\" >> \"$GITHUB_PATH\"\n")
	b.WriteString("      - name: Publish scanner reports\n")
	b.WriteString("        env:\n")
	b.WriteString("          GITHUB_TOKEN: ${{ github.token }}\n")
	b.WriteString("        run: vulnetix gha upload --org-id \"$VULNETIX_ORG_ID\" --json --no-banner --no-progress\n")
	return b.String()
}

// yamlScalar quotes a scalar when YAML would otherwise misread it.
func yamlScalar(s string) string {
	if s == "" {
		return `""`
	}
	needsQuote := strings.ContainsAny(s, ":#{}[]&*!|>%@`\"'") ||
		strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ")
	if !needsQuote {
		return s
	}
	// Single quotes are literal in YAML apart from the doubled quote, which
	// keeps ${{ ... }} expressions intact.
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedAnyKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ToolsInWorkflow returns the catalog tool ids already wired into an existing
// managed workflow, so `gha setup` adds to the set rather than replacing it.
func ToolsInWorkflow(c *Catalog, content string) []string {
	var out []string
	for _, t := range c.Tools {
		if strings.Contains(content, "\n  "+t.ID+":\n") {
			out = append(out, t.ID)
		}
	}
	sort.Strings(out)
	return out
}

// IsManaged reports whether this file was written by `gha setup`.
func IsManaged(content string) bool {
	return strings.Contains(content, managedHeader)
}
