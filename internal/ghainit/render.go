package ghainit

import (
	"encoding/json"
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
	always bool // runs even when an earlier step failed
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
func legs(sel Selection, found []string, emptyHigh bool) (names []string, high, none bool) {
	switch {
	case len(sel.Names) > 0:
		return sel.Names, false, false
	case sel.Mode == "none":
		return nil, false, true
	case sel.Mode == "high":
		return nil, true, false
	}
	if len(found) == 0 {
		// Below the threshold everywhere, source can still be there, and the
		// high-level scanner reads all of it. sca has nothing to scan without a
		// manifest.
		return nil, emptyHigh, !emptyHigh
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
		// A fork's branch can be named belai/x too, so the head repository is checked.
		r.guard = "github.event_name != 'pull_request' || (startsWith(github.head_ref, 'belai/') && github.event.pull_request.head.repo.full_name == github.repository)"
	}
	var jobs []job
	if on(p.Secrets) {
		// Binaries and git history are slow and belong to a scheduled deep scan.
		jobs = append(jobs, r.scanJob("secrets", "Secrets", "secrets", "secrets",
			[][2]string{{"extra-args", "--ignore-binaries\n--ignore-git"}}, ""))
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
			j := r.plainJob(s.id, s.name, s.id)
			switch s.id {
			case "analyze": // it reads history and the repository's pull requests and issues
				j.fullHistory = true
				j.perms = map[string]string{"pull-requests": "read", "issues": "read"}
				// The forge pass reads every pull request and issue in the window and
				// spends the job token down to its reserve. That token shares the
				// repository's hourly quota with every other job, CodeQL's SARIF
				// upload among them, so on a pull request it would fail the run's
				// required checks. The push to the default branch measures the forge.
				j.steps[0].with = append(j.steps[0].with, [2]string{"extra-args", "${{ github.event_name == 'pull_request' && '--no-forge' || '' }}"})
			case "aibom": // a commit scan is slow and this runs on every push
				j.steps[0].with = append(j.steps[0].with, [2]string{"extra-args", "--commit-scan-max\n1"})
			}
			jobs = append(jobs, j)
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
	names, high, none := legs(sel, found, kind == "sast")
	if none {
		return nil
	}
	if high {
		j := r.scanJob(kind, title, kind, kind, nil, "")
		if kind == "sca" { // the whole-repository SBOM job owns the artifact name sca
			for i, kv := range j.steps[0].with {
				if kv[0] == "artifact-name" {
					j.steps[0].with[i][1] = "sca-scan"
				}
			}
		}
		return []job{j}
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
			// Always: a gate failing the first step must not hide what the rest covers.
			st := r.scanStep(kind, kind, [][2]string{{not, rest}}, kind+"-"+n+"-rest")
			st.always = true
			j.steps = append(j.steps, st)
		}
		out = append(out, j)
	}
	return out
}

func (r *renderer) scanStep(action, gate string, with [][2]string, artifact string) step {
	s := step{uses: "Vulnetix/cli/" + action + "@" + r.ref}
	s.with = append(s.with, [2]string{"org-id", "${{ secrets.VULNETIX_ORG_ID }}"}, [2]string{"api-key", "${{ secrets.VULNETIX_API_KEY }}"})
	s.with = append(s.with, with...)
	if artifact != "" {
		s.with = append(s.with, [2]string{"artifact-name", artifact})
	}
	if g := r.p.Gates[gate]; g != "" {
		s.with = append(s.with, [2]string{"fail-on", g}, [2]string{"fail-on-findings", "true"})
	} else {
		s.with = append(s.with, [2]string{"fail-on-findings", "false"})
	}
	rules := append([]string{}, r.p.Rules[gate]...)
	if action != gate {
		rules = append(rules, r.p.Rules[action]...)
	}
	if len(rules) > 0 {
		s.with = append(s.with, [2]string{"rules", strings.Join(rules, "\n")})
	}
	if r.p.Publish {
		s.with = append(s.with, [2]string{"github-code-scanning", "${{ github.event_name == 'push' }}"})
	}
	s.with = append(s.with, [2]string{"github-token", scanToken})
	return s
}

// scanToken withholds the job token from a scanner on a pull request. With a
// token the CLI resolves every licence the registries and deps.dev left unknown
// through the GitHub API, several requests a package, and a scan of a large
// repository spends the repository's hourly quota in minutes. That quota is
// shared with every other job, CodeQL's SARIF upload among them, so the run's
// required code-scanning check failed. A pull request publishes nothing to
// GitHub from these jobs; the push to the default branch keeps the token.
const scanToken = "${{ github.event_name != 'pull_request' && github.token || '' }}"

func (r *renderer) scanJob(id, name, action, gate string, with [][2]string, _ string) job {
	j := job{id: id, name: name, steps: []step{r.scanStep(action, gate, with, id)}}
	if r.p.Publish {
		j.perms = map[string]string{"security-events": "write"}
	}
	return j
}

func (r *renderer) plainJob(id, name, action string) job {
	return job{id: id, name: name, steps: []step{{uses: "Vulnetix/cli/" + action + "@" + r.ref, with: [][2]string{
		{"org-id", "${{ secrets.VULNETIX_ORG_ID }}"}, {"api-key", "${{ secrets.VULNETIX_API_KEY }}"},
		{"artifact-name", id}, {"fail-on-findings", "false"}, {"github-token", scanToken}}}}}
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
			{"pattern", "{sca,cbom,aibom}"}, {"merge-multiple", "true"}, {"path", "boms"}}},
			{uses: "Vulnetix/cli/tea-release@" + r.ref, with: with}}}
}

// actionRef names a catalogue action. "." is the root action, used with task:.
func actionRef(action, ref string) string {
	if action == "." {
		return "Vulnetix/cli@" + ref
	}
	return "Vulnetix/cli/" + action + "@" + ref
}

func (r *renderer) extraJob(e Extra) job {
	id := e.ID
	if id == "" {
		id = strings.ReplaceAll(strings.ReplaceAll(e.Action, ".", "root"), "/", "-")
	}
	j := job{id: id, name: e.Action, perms: e.Permissions, needs: e.Needs}
	for _, a := range e.Prior {
		p := step{uses: actionRef(a, r.ref)}
		if a != "setup" { // setup takes none of these
			p.with = [][2]string{{"org-id", "${{ secrets.VULNETIX_ORG_ID }}"}, {"api-key", "${{ secrets.VULNETIX_API_KEY }}"},
				{"fail-on-findings", "false"}}
		}
		j.steps = append(j.steps, p)
	}
	for _, c := range e.Run {
		j.steps = append(j.steps, step{run: c})
	}
	s := step{uses: actionRef(e.Action, r.ref), with: [][2]string{
		{"org-id", "${{ secrets.VULNETIX_ORG_ID }}"}, {"api-key", "${{ secrets.VULNETIX_API_KEY }}"}}}
	if e.Action == "setup" { // it takes neither credential
		s.with = nil
	}
	keys := make([]string, 0, len(e.With))
	for k := range e.With {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s.with = append(s.with, [2]string{k, e.With[k]})
	}
	// setup installs and runs nothing, so it has no findings to fail on.
	if _, set := e.With["fail-on-findings"]; !set && e.Action != "setup" {
		s.with = append(s.with, [2]string{"fail-on-findings", "false"})
	}
	j.steps = append(j.steps, s)
	for _, c := range e.Then {
		j.steps = append(j.steps, step{run: c})
	}
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
				fmt.Fprintf(&b, "      - run: %s\n", yamlValue(s.run))
				continue
			}
			fmt.Fprintf(&b, "      - uses: %s\n", s.uses)
			if s.always {
				b.WriteString("        if: ${{ !cancelled() }}\n")
			}
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
				fmt.Fprintf(&b, "          %s: %s\n", kv[0], yamlValue(kv[1]))
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

// plainScalar is text YAML reads back as the same string: no leading or
// trailing space and none of the characters that start a flow, alias, anchor,
// tag, comment or quote. A colon is fine unless a space follows it.
var plainScalar = regexp.MustCompile(`^[A-Za-z0-9_./@+,-]([A-Za-z0-9_./@+,: -]*[A-Za-z0-9_./@+,-])?$`)

// yamlValue writes a policy-supplied string as a YAML scalar that means that
// string: plain when it is safe as one, an expression when it is a single
// ${{ }}, and double-quoted otherwise, so *.cdx.json, "a: b" and a trailing
// comment marker survive.
func yamlValue(s string) string {
	switch {
	case plainScalar.MatchString(s) && !strings.Contains(s, ": ") && !strings.Contains(s, " #") && !strings.HasPrefix(s, "- ") && s != "null":
		return s
	case strings.HasPrefix(s, "${{") && strings.HasSuffix(s, "}}") && !strings.ContainsAny(s, "\n\r\"#"):
		return s
	}
	b, _ := json.Marshal(s)
	return string(b)
}
