package ghtasks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Vulnetix/vdb-sca-match/ghaudit"
)

// RuleDocs renders the website pages for the GitHub posture rules:
// website/content/docs/github-rules/_index.md and one page per rule, at the
// URL ghaudit's Rule.HelpURI and the console's rule links point to.
func RuleDocs() map[string]string {
	pages := map[string]string{}
	rules := ghaudit.Rules()
	var idx strings.Builder
	idx.WriteString(`---
title: GitHub Rules
weight: 7
description: "Vulnetix GitHub posture rules: workflow injection and privilege flaws, the action supply chain, and repository and organisation settings."
---

<!-- Generated from vdb-sca-match ghaudit by ` + "`GHRULES_UPDATE=1 go test ./internal/ghtasks/`" + `; do not edit. -->

The GitHub rules run in ` + "`vulnetix gha workflows`, `actions`, `settings`, `org` and `audit`" + `, and in the
Vulnetix Software Factory on GitHub App events, from the same engine. Rules marked *needs* report
"not evaluated" when those GitHub settings could not be read, never a pass. Rules marked *uses* run
on the files alone and read the settings, when present, to lower or raise a finding's severity.
`)
	titles := map[ghaudit.Task]string{
		ghaudit.TaskWorkflows: "Workflows (`vulnetix gha workflows`)",
		ghaudit.TaskActions:   "Actions and images (`vulnetix gha actions`)",
		ghaudit.TaskSettings:  "Repository settings (`vulnetix gha settings`)",
		ghaudit.TaskOrg:       "Organisation settings (`vulnetix gha org`)",
	}
	for _, t := range ghaudit.AllTasks {
		fmt.Fprintf(&idx, "\n## %s\n\n| Rule | Severity | Context |\n|---|---|---|\n", titles[t])
		for _, r := range rules {
			if r.Task != t {
				continue
			}
			fmt.Fprintf(&idx, "| [%s – %s](%s/) | %s | %s |\n", r.ID, r.Name, strings.ToLower(r.ID), sevLabel(r.Severity), contextText(r))
		}
	}
	pages["_index.md"] = idx.String()

	for _, r := range rules {
		var b strings.Builder
		fmt.Fprintf(&b, "---\ntitle: %q\ndescription: %q\n---\n\n", r.ID+" – "+r.Name, r.Summary)
		b.WriteString("<!-- Generated from vdb-sca-match ghaudit; do not edit. -->\n\n")
		b.WriteString("## Overview\n\n" + r.Description + "\n\n")
		cwes := make([]string, len(r.CWE))
		for i, c := range r.CWE {
			cwes[i] = fmt.Sprintf("[CWE-%d](https://cwe.mitre.org/data/definitions/%d.html)", c, c)
		}
		fmt.Fprintf(&b, "**Severity:** %s | **Confidence:** %s | **CWE:** %s | **Command:** `vulnetix gha %s`\n\n", sevLabel(r.Severity), r.Confidence, strings.Join(cwes, ", "), r.Task)
		if len(r.Requires) > 0 {
			b.WriteString("**Needs:** " + factList(r.Requires) + ". Without them the rule is reported as not evaluated.\n\n")
		}
		if len(r.Enhances) > 0 {
			b.WriteString("**Uses, when available:** " + factList(r.Enhances) + ", to rate each finding against the repository's own configuration.\n\n")
		}
		if len(r.CAPEC) > 0 || len(r.ATTACK) > 0 {
			refs := append(append([]string{}, r.CAPEC...), r.ATTACK...)
			sort.Strings(refs)
			b.WriteString("**Mappings:** " + strings.Join(refs, ", ") + "\n\n")
		}
		b.WriteString("## Remediation\n\n" + r.Remediation + "\n")
		if r.CWSS != "" {
			b.WriteString("\n## Scoring\n\nCWSS vector at the rule's default severity: `" + r.CWSS + "`. A finding whose severity the repository's settings moved is scored at its adjusted severity.\n")
		}
		pages[strings.ToLower(r.ID)+".md"] = b.String()
	}
	return pages
}

func sevLabel(s ghaudit.Severity) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(string(s[:1])) + string(s[1:])
}

func contextText(r *ghaudit.Rule) string {
	var parts []string
	if len(r.Requires) > 0 {
		parts = append(parts, "needs "+factList(r.Requires))
	}
	if len(r.Enhances) > 0 {
		parts = append(parts, "uses "+factList(r.Enhances))
	}
	return strings.Join(parts, "; ")
}

func factList(groups []string) string {
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = strings.ReplaceAll(g, "_", " ")
	}
	return strings.Join(out, ", ")
}
