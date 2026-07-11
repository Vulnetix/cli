package analyze

// The trustworthiness collector: the open-source compliance checks.
//
// This is repolinter's default ruleset, which is the best-considered checklist of its kind and
// which repolinter itself is now archived. The rules are data, not code, so a policy change is
// a catalog edit rather than a release.
//
// The evidence for a passing check is the file that satisfied it. The evidence for a failing
// one is the SARIF result that records the absence — and it names the globs that were searched,
// because "we looked for LICENSE, LICENCE and COPYING and found none" is a finding, whereas
// "no license" is an accusation with no working shown. repolinter got this right too: its
// ResultTarget carries the pattern when nothing matched.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/sast"
)

// policyRule is one compliance check. Globs are matched case-insensitively against the
// repository root and a small set of conventional subdirectories.
type policyRule struct {
	ID    string
	Name  string
	Globs []string
	// Level decides whether a breach is an error or a warning in the SARIF, mirroring
	// repolinter's level field. Nothing here fails a build by default.
	Level string
	Why   string
}

var policyRules = []policyRule{
	{ID: "license-file-exists", Name: "License file", Level: "error",
		Globs: []string{"LICENSE*", "LICENCE*", "COPYING*"},
		Why:   "Without a license file the code is not legally reusable, whatever the README says."},
	{ID: "readme-file-exists", Name: "README", Level: "error",
		Globs: []string{"README*"},
		Why:   "The entry point for every new reader of the repository."},
	{ID: "contributing-file-exists", Name: "Contributing guide", Level: "warning",
		Globs: []string{"CONTRIBUTING*", "docs/CONTRIBUTING*", ".github/CONTRIBUTING*"},
		Why:   "Tells a would-be contributor how to contribute without having to ask."},
	{ID: "code-of-conduct-file-exists", Name: "Code of conduct", Level: "warning",
		Globs: []string{"CODE_OF_CONDUCT*", "CODE-OF-CONDUCT*", "docs/CODE_OF_CONDUCT*", ".github/CODE_OF_CONDUCT*"},
		Why:   "States the behavioural expectations and who to contact when they are breached."},
	{ID: "security-file-exists", Name: "Security policy", Level: "error",
		Globs: []string{"SECURITY.md", "docs/SECURITY.md", ".github/SECURITY.md"},
		Why:   "Tells a security researcher where to send a vulnerability instead of publishing it."},
	{ID: "changelog-file-exists", Name: "Changelog", Level: "warning",
		Globs: []string{"CHANGELOG*", "docs/CHANGELOG*"},
		Why:   "Lets a consumer see what changed between the version they have and the one they are considering."},
	{ID: "support-file-exists", Name: "Support policy", Level: "warning",
		Globs: []string{"SUPPORT*", "docs/SUPPORT*", ".github/SUPPORT*"},
		Why:   "States where support questions go, so they do not arrive as security reports."},
	{ID: "codeowners-file-exists", Name: "Code owners", Level: "warning",
		Globs: []string{"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"},
		Why:   "Names who must review which code — the mechanism behind review coverage."},
	{ID: "issue-template-exists", Name: "Issue template", Level: "warning",
		Globs: []string{".github/ISSUE_TEMPLATE*", "ISSUE_TEMPLATE*"},
		Why:   "Gets the information needed to triage an issue at the point it is filed."},
	{ID: "pull-request-template-exists", Name: "Pull request template", Level: "warning",
		Globs: []string{".github/PULL_REQUEST_TEMPLATE*", ".github/pull_request_template.md", "PULL_REQUEST_TEMPLATE*"},
		Why:   "Prompts the author for the context a reviewer will need."},
	{ID: "integrates-with-ci", Name: "CI configuration", Level: "error",
		Globs: []string{".github/workflows/*", ".gitlab-ci.yml", ".circleci/config.yml", "Jenkinsfile", ".travis.yml", "azure-pipelines.yml", ".drone.yml"},
		Why:   "Without CI, nothing is checked before it merges except by hand."},
	{ID: "dependency-automation", Name: "Dependency automation", Level: "warning",
		Globs: []string{".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json", ".renovaterc", ".github/renovate.json"},
		Why:   "Without it, dependency updates depend on somebody remembering."},
	{ID: "test-directory-exists", Name: "Tests", Level: "error",
		Globs: []string{"test", "tests", "spec", "specs", "**/*_test.go", "**/test_*.py", "**/*.test.ts", "**/*.test.js", "**/*_test.py", "**/*Test.java"},
		Why:   "A repository with no tests has no way to know when it breaks."},
}

// trustResult carries the SARIF findings out rather than writing them, so that the policy
// breaches and the history secrets end up in ONE SARIF log. Two logs would mean two findings
// surfaces for one scan, and `analyze` would show up twice in Scanner Results.
type trustResult struct {
	findings []sast.Finding
	rules    []sast.RuleMetadata
}

func collectTrust(b *Builder, root string) *trustResult {
	type outcome struct {
		rule    policyRule
		matched string
	}

	var passed, failed []outcome
	for _, r := range policyRules {
		if m := findFirstMatch(root, r.Globs); m != "" {
			passed = append(passed, outcome{r, m})
		} else {
			failed = append(failed, outcome{rule: r})
		}
	}

	// Failures become SARIF results — a policy breach is anchored to the repository, and SARIF is
	// how every other file-and-line finding in this product is already expressed.
	findings := make([]sast.Finding, 0, len(failed))
	rules := make([]sast.RuleMetadata, 0, len(failed))
	for _, f := range failed {
		level := "warning"
		if f.rule.Level == "error" {
			level = "error"
		}
		severity := "medium"
		if f.rule.Level == "error" {
			severity = "high"
		}
		rules = append(rules, sast.RuleMetadata{
			ID:          f.rule.ID,
			Name:        f.rule.Name,
			Description: f.rule.Name + " is missing. " + f.rule.Why,
			Severity:    severity,
			Level:       level,
			Kind:        "analyze",
			Tags:        []string{"compliance", "open-source"},
		})
		findings = append(findings, sast.Finding{
			RuleID: f.rule.ID,
			// The globs that were searched are part of the finding. "No license" is an accusation;
			// "we looked for LICENSE*, LICENCE*, COPYING* and found none" is a finding.
			Message: f.rule.Name + " not found. Searched: " + strings.Join(f.rule.Globs, ", ") +
				". " + f.rule.Why,
			Severity:    severity,
			Level:       level,
			ArtifactURI: ".",
			StartLine:   1,
		})
	}

	// A failing check's evidence is its SARIF result; a passing check's evidence is the file that
	// satisfied it. Both are inspectable — which is the point.
	sort.Slice(failed, func(i, j int) bool { return failed[i].rule.ID < failed[j].rule.ID })

	failedRefs := make([]EvidenceRef, 0, len(failed))
	for i := range failed {
		failedRefs = append(failedRefs, SARIFRef(i))
	}

	// The file that satisfied a check is very often one the file walker already described — a
	// README, a CI config. AddFile folds this into that record and hands back a ref to it, so the
	// policy metric and the file metrics cite the same file rather than two half-descriptions of
	// it under different ids.
	passedRefs := make([]EvidenceRef, 0, len(passed))
	for _, p := range passed {
		passedRefs = append(passedRefs, b.AddFile(&FileRecord{
			ID:   "policy-" + p.rule.ID,
			Type: "file",
			Path: p.matched,
			Tags: []string{"policy", p.rule.ID},
		}))
	}

	b.Count(Metric{
		ID: "trust.policy.breaches", Family: "trust", Name: "Open-source policy breaches",
		Definition: "Compliance checks with no satisfying file: license, README, contributing guide, code of conduct, security policy, changelog, support policy, code owners, issue and PR templates, CI configuration, dependency automation, tests. Each breach records the globs that were searched.",
		Classification: &Classification{
			Label:      policyClass(len(failed)),
			Thresholds: "0 = clean, 1-3 = minor, 4+ = significant",
		},
		References: []Reference{{Title: "repolinter default ruleset", URL: "https://github.com/todogroup/repolinter/blob/master/rulesets/default.json"}},
	}, failedRefs)

	b.Count(Metric{
		ID: "trust.policy.satisfied", Family: "trust", Name: "Open-source policy checks satisfied",
		Definition: "Compliance checks with a satisfying file present. The evidence is the file that satisfied each one.",
	}, passedRefs)

	// The individual checks that matter most, as assertions, so a consumer can gate on one
	// without having to parse a count.
	for _, r := range []string{"security-file-exists", "license-file-exists", "integrates-with-ci"} {
		present := false
		var ref []EvidenceRef
		for i, p := range passed {
			if p.rule.ID == r {
				present = true
				ref = []EvidenceRef{passedRefs[i]}

				break
			}
		}
		if !present {
			for i, f := range failed {
				if f.rule.ID == r {
					ref = []EvidenceRef{SARIFRef(i)}

					break
				}
			}
		}
		b.Assertion(Metric{
			ID:         "trust." + strings.ReplaceAll(r, "-", "_"),
			Family:     "trust",
			Name:       ruleName(r),
			Definition: ruleDefinition(r),
			Unit:       "boolean",
		}, present, ref)
	}

	return &trustResult{findings: findings, rules: rules}
}

func policyClass(n int) string {
	switch {
	case n == 0:
		return "clean"
	case n <= 3:
		return "minor"
	default:
		return "significant"
	}
}

func ruleName(id string) string {
	for _, r := range policyRules {
		if r.ID == id {
			return r.Name + " present"
		}
	}

	return id
}

func ruleDefinition(id string) string {
	for _, r := range policyRules {
		if r.ID == id {
			return "Whether a matching file exists. Searched: " + strings.Join(r.Globs, ", ") + ". " + r.Why
		}
	}

	return id
}

// findFirstMatch returns the first path matching any glob, relative to root, or "".
// Case-insensitive on the basename, because LICENSE and license are the same file to a human.
func findFirstMatch(root string, globs []string) string {
	for _, g := range globs {
		if strings.Contains(g, "**/") {
			if m := findRecursive(root, strings.TrimPrefix(g, "**/")); m != "" {
				return m
			}

			continue
		}
		matches, err := filepath.Glob(filepath.Join(root, g))
		if err == nil && len(matches) > 0 {
			for _, m := range matches {
				if rel, rerr := filepath.Rel(root, m); rerr == nil {
					return filepath.ToSlash(rel)
				}
			}
		}
		// Case-insensitive retry against the directory listing.
		dir := filepath.Dir(filepath.Join(root, g))
		pattern := strings.ToLower(filepath.Base(g))
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if ok, _ := filepath.Match(pattern, strings.ToLower(e.Name())); ok {
				if rel, rerr := filepath.Rel(root, filepath.Join(dir, e.Name())); rerr == nil {
					return filepath.ToSlash(rel)
				}
			}
		}
	}

	return ""
}

func findRecursive(root, pattern string) string {
	var found string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}

			return nil
		}
		if ok, _ := filepath.Match(pattern, d.Name()); ok {
			if rel, rerr := filepath.Rel(root, path); rerr == nil {
				found = filepath.ToSlash(rel)
			}
		}

		return nil
	})

	return found
}
