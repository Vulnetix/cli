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

	// Triggers are the workflow's `on:` events. Empty means push +
	// workflow_dispatch, which is what this command has always written.
	//
	// It is worth choosing deliberately once a repository runs more than a
	// handful of scanners: a full detected set is twenty-odd jobs, and on a
	// small runner pool "on every push" turns a two-minute build into an hour
	// of queue for everyone else.
	Triggers []string

	// ScheduleCron is the five-field expression used when Triggers includes
	// "schedule". Leave it empty and the expression is derived from RepoSlug,
	// which is what staggers the fleet; set it only to pin one repository to a
	// time somebody actually cares about.
	ScheduleCron string

	// RepoSlug is "owner/repo", used to derive the schedule when ScheduleCron
	// is empty. Empty falls back to DefaultScheduleCron.
	RepoSlug string
}

// DefaultScheduleCron is the schedule used when one is asked for and the
// repository has no slug to derive a slot from. It is a fallback, not a fleet
// default: every repository that knows its own name gets its own slot from
// ScheduleCronFor instead.
const DefaultScheduleCron = "17 3 * * 1"

// DefaultJobTimeoutMinutes caps every scanner job.
//
// Measured over 1,645 jobs on the self-hosted pool: p50 39 seconds, 95.2% under
// five minutes, p99 29 minutes. Sixty minutes is a little over twice the p99, so
// it never touches a scan that is merely slow, and it turns a hang from six
// hours of a held runner — GitHub's own job ceiling, which is what four of these
// actually hit — into an hour.
const DefaultJobTimeoutMinutes = 60

// publishTimeoutMinutes caps the publish job. It downloads this run's artifacts
// and uploads them; time spent waiting on `needs` does not count against it.
const publishTimeoutMinutes = 30

// scheduleSlotMinutes is the spacing between two repositories' scheduled starts.
//
// The pool tops out at 24 concurrent runners and drains a full 24-job backlog in
// about seven minutes. A repository's workflow is around forty jobs, so one
// repository alone occupies the pool for roughly two drains. Twenty minutes
// clears that with room to spare, and is the smallest round number that does.
const scheduleSlotMinutes = 20

// scheduleMinuteOffset keeps the fleet off the top of the hour, where GitHub
// queues every cron on the platform at once and delivers them late.
const scheduleMinuteOffset = 7

// ScheduleCronFor derives a stable weekly slot from the repository slug.
//
// Deterministic on purpose: the workflow is regenerated in full on every
// `gha setup`, so a random or clock-derived time would rewrite the schedule (and
// produce a diff) every single run. Hashing the slug means the same repository
// always lands in the same slot, and a repository added to the fleet does not
// move anybody else — which an index-into-a-sorted-list scheme would.
//
// The week is cut into 20-minute slots, three per hour, 504 in all. The CLI runs
// inside one repository and cannot see the others, so slots are assigned by hash
// rather than allocated; two repositories colliding is possible and costs only
// that one of them queues behind the other.
func ScheduleCronFor(slug string) string {
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return DefaultScheduleCron
	}

	// FNV-1a, written out rather than imported so the derivation is visible and
	// pinned: this value must not move when a dependency changes.
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	var h uint32 = offset32
	for i := 0; i < len(slug); i++ {
		h ^= uint32(slug[i])
		h *= prime32
	}

	slotsPerHour := 60 / scheduleSlotMinutes
	slot := h % uint32(7*24*slotsPerHour)

	minute := int(slot%uint32(slotsPerHour))*scheduleSlotMinutes + scheduleMinuteOffset
	hour := int(slot/uint32(slotsPerHour)) % 24
	weekday := int(slot) / (24 * slotsPerHour)

	return fmt.Sprintf("%d %d * * %d", minute, hour, weekday)
}

// renderTriggers writes the `on:` block.
func renderTriggers(opt Options) string {
	triggers := opt.Triggers
	if len(triggers) == 0 {
		triggers = []string{"push", "workflow_dispatch"}
	}

	var b strings.Builder
	b.WriteString("on:\n")
	for _, t := range triggers {
		switch t {
		case "schedule":
			cron := opt.ScheduleCron
			if cron == "" {
				cron = ScheduleCronFor(opt.RepoSlug)
			}
			fmt.Fprintf(&b, "  schedule:\n    - cron: '%s'\n", cron)
		default:
			fmt.Fprintf(&b, "  %s:\n", t)
		}
	}
	b.WriteString("\n")

	return b.String()
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
	b.WriteString(renderTriggers(opt))
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
	// Without this a scanner that hangs holds a runner until GitHub kills it at
	// six hours, and on a 24-slot pool that is a quarter of the fleet's capacity
	// spent on a job nobody is waiting for.
	timeout := t.TimeoutMinutes
	if timeout <= 0 {
		timeout = DefaultJobTimeoutMinutes
	}
	fmt.Fprintf(&b, "    timeout-minutes: %d\n", timeout)
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
	if s.If != "" {
		// Written verbatim. A GitHub expression is already its own syntax, and
		// quoting it as a YAML scalar would double every apostrophe in it for
		// no gain; the catalog is first-party content, not user input.
		fmt.Fprintf(&b, "        if: %s\n", s.If)
	}
	// Every scanner step tolerates failure: one broken scanner must not stop the
	// others from publishing.
	b.WriteString("        continue-on-error: true\n")
	if s.TimeoutMinutes > 0 {
		fmt.Fprintf(&b, "        timeout-minutes: %d\n", s.TimeoutMinutes)
	}

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
		// NOT the default shell. GitHub runs `bash -e`, which aborts the step at
		// the first non-zero command — and a scanner that found something exits
		// non-zero by design (govulncheck 3, terrascan 3, zizmor 14). Under `-e`
		// the recipe dies on the scan line, so the lines that follow it — the
		// ones that check the report is valid SARIF and delete it when it is not
		// — never run. The empty file is then uploaded as an artifact and the
		// publish job rejects it, which is how a green scan turns into a red
		// workflow.
		//
		// The step already carries continue-on-error, so aborting early was never
		// what was wanted. Each recipe decides for itself which exit codes matter.
		b.WriteString("        shell: bash --noprofile --norc {0}\n")
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
	fmt.Fprintf(&b, "    timeout-minutes: %d\n", publishTimeoutMinutes)
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
	// The credential check is a skip, not a failure.
	//
	// A repository that has not been given VULNETIX_ORG_ID and
	// VULNETIX_API_KEY yet is not broken — it simply has nowhere to publish.
	// Without this the publish job exits non-zero on every single run, so the
	// repository shows a permanent red X that says "authentication required"
	// and tells nobody which secret to set. A warning that names both secrets
	// is the useful form of the same information.
	b.WriteString("        run: |\n")
	b.WriteString("          if [ -z \"${VULNETIX_ORG_ID:-}\" ] || [ -z \"${VULNETIX_API_KEY:-}\" ]; then\n")
	b.WriteString("            echo \"::warning::VULNETIX_ORG_ID and VULNETIX_API_KEY are not set for this repository, so the scanners ran but nothing was published. Add both as repository secrets.\"\n")
	b.WriteString("            exit 0\n")
	b.WriteString("          fi\n")
	b.WriteString("          vulnetix gha upload --org-id \"$VULNETIX_ORG_ID\" --json --no-banner --no-progress\n")
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
