package ghainit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const managedHeader = "# Managed by `vulnetix gha init`. Edit .vulnetix/workflow.yaml and re-run it.\n"

// IsManaged reports whether a workflow is this command's.
func IsManaged(content string) bool { return strings.HasPrefix(content, managedHeader) }

var usesRef = regexp.MustCompile(`(?m)^(\s*(?:- )?uses: [^@\s]+)@\S+.*$`)

// Normalize drops action refs, which a lock tool narrows to exact tags, so a
// locked workflow still compares equal to what this command renders.
func Normalize(content string) string { return usesRef.ReplaceAllString(content, "$1") }

// Options are the values a render needs beyond the policy.
type Options struct {
	// Ref is the action ref, v4 by default.
	Ref string
	// CheckoutRef is the actions/checkout ref.
	CheckoutRef string
}

type renderer struct {
	p     *Policy
	ref   string
	co    string
	guard string
}

type step struct {
	uses   string
	with   [][2]string
	run    string
	noFail bool
}

type job struct {
	id, name string
	steps    []step
	perms    map[string]string
	needs    string
	// when is the job's own condition, joined to the trigger guard.
	when string
	// fullHistory fetches tags, for git describe.
	fullHistory bool
}

// Legs resolves a selection against what was detected: the granular names, or
// nil when the high-level scanner applies.
func legs(sel Selection, found []string) (names []string, high, none bool) {
	switch {
	case len(sel.Names) > 0:
		return sel.Names, false, false
	case sel.Mode == "none":
		return nil, false, true
	case sel.Mode == "high":
		return nil, true, false
	}
	if len(found) == 0 {
		return nil, false, true
	}
	if len(found) > granularLimit {
		return nil, true, false
	}
	return found, false, false
}

// Render writes the workflow.
func Render(p *Policy, sig *Signals, opt Options) string {
	r := &renderer{p: p, ref: opt.Ref, co: opt.CheckoutRef}
	if r.ref == "" {
		r.ref = "v4"
	}
	if r.co == "" {
		r.co = "v7"
	}
	if p.Triggers == TriggerBelai {
		r.guard = "github.event_name != 'pull_request' || startsWith(github.head_ref, 'belai/')"
	}
	var jobs []job
	if on(p.Secrets) {
		jobs = append(jobs, r.scanJob("secrets", "Secrets", "secrets", "secrets", nil, ""))
	}
	jobs = append(jobs, r.scoped("sast", "SAST", p.SAST, sig.Languages, "language", "not-language")...)
	jobs = append(jobs, r.scoped("sca", "SCA", p.SCA, sig.Managers, "package-manager", "not-package-manager")...)
	if p.IaC == "on" || (p.IaC == "auto" && sig.Terraform) {
		jobs = append(jobs, r.scanJob("iac", "IaC", "iac", "iac", nil, ""))
	}
	if p.Containers == "on" || (p.Containers == "auto" && sig.Containers) {
		jobs = append(jobs, r.scanJob("containers", "Containers", "containers", "containers", nil, ""))
	}
	if p.License {
		jobs = append(jobs, r.scanJob("license", "License", "license", "license", nil, ""))
	}
	for _, s := range []struct {
		on       bool
		id, name string
	}{{p.Malscan, "malscan", "Malscan"}, {p.CBOM, "cbom", "CBOM"}, {p.AIBOM, "aibom", "AIBOM"}, {p.Analyze, "analyze", "Analyze"}} {
		if s.on {
			jobs = append(jobs, r.plainJob(s.id, s.name, s.id))
		}
	}
	if on(p.SBOM) && len(sig.Managers) > 0 {
		jobs = append(jobs, r.sbomJob())
	}
	for _, e := range p.Extras {
		jobs = append(jobs, r.extraJob(e))
	}
	if len(jobs) > 0 {
		jobs = append(jobs, r.publishJob(jobs))
	}
	if t := r.teaJob(jobs, sig); t != nil {
		jobs = append(jobs, *t)
	}
	return r.write(jobs)
}

func (r *renderer) scoped(kind, title string, sel Selection, found []string, only, not string) []job {
	names, high, none := legs(sel, found)
	if none {
		return nil
	}
	if high {
		return []job{r.scanJob(kind, title, kind, kind, nil, "")}
	}
	var out []job
	for i, n := range names {
		var rest string
		// The rest step sits in the largest leg, the first. It keeps the union of
		// the legs equal to the high-level scanner.
		if i == 0 && !r.p.NoRest {
			rest = strings.Join(names, ",")
		}
		j := r.scanJob(kind+"-"+n, title+" "+n, kind+"/"+n, kind, nil, "")
		if rest != "" {
			j.steps = append(j.steps, r.scanStep(kind, kind, [][2]string{{not, rest}}, ""))
		}
		out = append(out, j)
	}
	return out
}

func (r *renderer) scanStep(action, gate string, with [][2]string, artifact string) step {
	s := step{uses: "Vulnetix/cli/" + action + "@" + r.ref}
	s.with = append(s.with, [2]string{"org-id", "${{ secrets.VULNETIX_ORG_ID }}"}, [2]string{"api-key", "${{ secrets.VULNETIX_API_KEY }}"})
	s.with = append(s.with, with...)
	if g := r.p.Gates[gate]; g != "" {
		s.with = append(s.with, [2]string{"fail-on", g}, [2]string{"fail-on-findings", "true"})
	} else {
		s.with = append(s.with, [2]string{"fail-on-findings", "false"})
	}
	if rules := r.p.Rules[gate]; len(rules) > 0 {
		s.with = append(s.with, [2]string{"rules", strings.Join(rules, "\n")})
	}
	if rules := r.p.Rules[action]; action != gate && len(rules) > 0 {
		s.with = append(s.with, [2]string{"rules", strings.Join(rules, "\n")})
	}
	if r.p.Publish {
		s.with = append(s.with, [2]string{"github-code-scanning", "${{ github.event_name == 'push' }}"})
	}
	return s
}

func (r *renderer) scanJob(id, name, action, gate string, with [][2]string, _ string) job {
	j := job{id: id, name: name, steps: []step{r.scanStep(action, gate, with, "")}}
	if r.p.Publish {
		j.perms = map[string]string{"security-events": "write"}
	}
	return j
}

func (r *renderer) plainJob(id, name, action string) job {
	return job{id: id, name: name, steps: []step{{uses: "Vulnetix/cli/" + action + "@" + r.ref, with: [][2]string{
		{"org-id", "${{ secrets.VULNETIX_ORG_ID }}"}, {"api-key", "${{ secrets.VULNETIX_API_KEY }}"},
		{"artifact-name", id}, {"fail-on-findings", "false"}}}}}
}

// sbomJob is the whole-repository leg. Its job id and artifact name stay fixed:
// attestation, the dependency graph and TEA read them.
func (r *renderer) sbomJob() job {
	j := r.plainJob("sbom", "SBOM", "sbom")
	j.steps[0].with[2] = [2]string{"artifact-name", "sca"}
	if r.p.Publish {
		j.steps[0].with = append(j.steps[0].with, [2]string{"dependency-graph", "${{ github.event_name == 'push' }}"},
			[2]string{"attest", "${{ github.event_name == 'push' }}"})
		j.perms = map[string]string{"contents": "write", "id-token": "write", "attestations": "write"}
	}
	return j
}

// publishJob hands this run's reports to Vulnetix. It runs whatever the legs
// did: a partial scan still publishes.
func (r *renderer) publishJob(legs []job) job {
	needs := make([]string, 0, len(legs))
	for _, j := range legs {
		needs = append(needs, j.id)
	}
	return job{id: "publish", name: "Publish", needs: "[" + strings.Join(needs, ", ") + "]", when: "${{ !cancelled() }}",
		perms: map[string]string{"actions": "read"},
		steps: []step{{uses: "Vulnetix/cli/gha-upload@" + r.ref, with: [][2]string{
			{"org-id", "${{ secrets.VULNETIX_ORG_ID }}"}, {"api-key", "${{ secrets.VULNETIX_API_KEY }}"},
			{"fail-on-findings", "false"}}}}}
}

// teaJob publishes the run's BOMs. Publishing is evidence, not a gate: it never
// fails the run, and it runs with what the legs left behind.
func (r *renderer) teaJob(jobs []job, sig *Signals) *job {
	t := r.p.TEA
	if t != nil && t.Off {
		return nil
	}
	var needs []string
	for _, j := range jobs {
		if j.id == "sbom" || j.id == "cbom" || j.id == "aibom" {
			needs = append(needs, j.id)
		}
	}
	if len(needs) == 0 {
		return nil
	}
	with := [][2]string{
		{"org-id", "${{ secrets.VULNETIX_ORG_ID }}"}, {"api-key", "${{ secrets.VULNETIX_API_KEY }}"},
		{"tea-files", "boms/*.cdx.json"}, {"tea-auto-version", "true"}, {"tea-checksums-from-release", "true"},
		{"fail-on-findings", "false"}}
	if t != nil && t.Visibility != "" {
		with = append(with, [2]string{"tea-visibility", t.Visibility})
	}
	if t != nil && len(t.Channels) > 0 {
		with = append(with, [2]string{"tea-channels", strings.Join(t.Channels, "\n")})
	}
	return &job{id: "tea", name: "TEA", needs: "[" + strings.Join(needs, ", ") + "]", when: "${{ !cancelled() }}", fullHistory: true,
		perms: map[string]string{"actions": "read"},
		steps: []step{{uses: "actions/download-artifact@v8", noFail: true, with: [][2]string{
			{"pattern", "'{sca,cbom,aibom}'"}, {"merge-multiple", "true"}, {"path", "boms"}}},
			{uses: "Vulnetix/cli/tea-release@" + r.ref, with: with}}}
}

func (r *renderer) extraJob(e Extra) job {
	id := e.ID
	if id == "" {
		id = strings.ReplaceAll(e.Action, "/", "-")
	}
	j := job{id: id, name: e.Action, perms: e.Permissions, needs: e.Needs}
	for _, a := range e.Prior {
		j.steps = append(j.steps, step{uses: "Vulnetix/cli/" + a + "@" + r.ref, with: [][2]string{
			{"org-id", "${{ secrets.VULNETIX_ORG_ID }}"}, {"api-key", "${{ secrets.VULNETIX_API_KEY }}"},
			{"fail-on-findings", "false"}}})
	}
	for _, c := range e.Run {
		j.steps = append(j.steps, step{run: c})
	}
	s := step{uses: "Vulnetix/cli/" + e.Action + "@" + r.ref, with: [][2]string{
		{"org-id", "${{ secrets.VULNETIX_ORG_ID }}"}, {"api-key", "${{ secrets.VULNETIX_API_KEY }}"}}}
	keys := make([]string, 0, len(e.With))
	for k := range e.With {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s.with = append(s.with, [2]string{k, e.With[k]})
	}
	if _, set := e.With["fail-on-findings"]; !set {
		s.with = append(s.with, [2]string{"fail-on-findings", "false"})
	}
	j.steps = append(j.steps, s)
	return j
}

func (r *renderer) write(jobs []job) string {
	var b strings.Builder
	b.WriteString(managedHeader)
	b.WriteString("name: Vulnetix Security\n\non:\n  push:\n    branches: [main]\n")
	if r.p.Triggers != TriggerPush {
		b.WriteString("  pull_request:\n    branches: [main]\n")
	}
	b.WriteString("  release:\n    types: [published]\n  workflow_dispatch:\n\npermissions:\n  contents: read\n\njobs:\n")
	for i, j := range jobs {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "  %s:\n    name: %s\n", j.id, j.name)
		fmt.Fprintf(&b, "    runs-on: %s\n", r.runsOn())
		switch {
		case r.guard != "" && j.when != "":
			fmt.Fprintf(&b, "    if: ${{ !cancelled() && (%s) }}\n", r.guard)
		case r.guard != "":
			fmt.Fprintf(&b, "    if: %s\n", r.guard)
		case j.when != "":
			fmt.Fprintf(&b, "    if: %s\n", j.when)
		}
		if j.needs != "" {
			fmt.Fprintf(&b, "    needs: %s\n", j.needs)
		}
		if len(j.perms) > 0 {
			b.WriteString("    permissions:\n")
			if _, ok := j.perms["contents"]; !ok {
				b.WriteString("      contents: read\n")
			}
			keys := make([]string, 0, len(j.perms))
			for k := range j.perms {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "      %s: %s\n", k, j.perms[k])
			}
		}
		fmt.Fprintf(&b, "    timeout-minutes: 60\n    steps:\n      - uses: actions/checkout@%s\n", r.co)
		if j.fullHistory {
			b.WriteString("        with:\n          fetch-depth: 0\n")
		}
		for _, s := range j.steps {
			if s.run != "" {
				fmt.Fprintf(&b, "      - run: %s\n", s.run)
				continue
			}
			fmt.Fprintf(&b, "      - uses: %s\n", s.uses)
			if s.noFail {
				b.WriteString("        continue-on-error: true\n")
			}
			if len(s.with) > 0 {
				b.WriteString("        with:\n")
			}
			for _, kv := range s.with {
				if strings.Contains(kv[1], "\n") {
					fmt.Fprintf(&b, "          %s: |\n", kv[0])
					for _, l := range strings.Split(kv[1], "\n") {
						fmt.Fprintf(&b, "            %s\n", l)
					}
					continue
				}
				fmt.Fprintf(&b, "          %s: %s\n", kv[0], kv[1])
			}
		}
	}
	return b.String()
}

// runsOn keeps a fork's pull request off the self-hosted pool: public pull
// request jobs always use a hosted runner.
func (r *renderer) runsOn() string {
	if r.p.Runner == "" {
		return "ubuntu-latest"
	}
	pool := fmt.Sprintf(`["self-hosted","Linux","X64",%q]`, r.p.Runner)
	if r.p.Triggers == TriggerPR {
		return fmt.Sprintf(`${{ github.event_name == 'pull_request' && fromJSON('["ubuntu-latest"]') || fromJSON('%s') }}`, pool)
	}
	return fmt.Sprintf("[self-hosted, Linux, X64, %s]", r.p.Runner)
}
