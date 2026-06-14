// Command secretsgen renders the high-fidelity secret-detection rule set and
// its documentation from a single source of truth: catalog.json.
//
// For every catalog entry it emits:
//   - internal/sast/rules/vnx-sec-<id>.rego   (the OPA rule)
//   - a row in website/content/docs/sast-rules/secrets/<category>.md
//
// Rules and docs are therefore guaranteed never to drift. Run via:
//
//	just gen-secrets        # go run ./internal/sast/secretsgen
//
// The catalog is build-time only and is NOT embedded in the shipped binary
// (it lives outside internal/sast/rules, which is the only embedded tree).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

// Entry is one secret-detection pattern in the catalog.
type Entry struct {
	ID          int      `json:"id"`
	Category    string   `json:"category"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Strategy    string   `json:"strategy"` // fixed_prefix | keyword_entropy | regex_only
	Pattern     string   `json:"token_pattern"`
	Keywords    []string `json:"keywords"`
	EntropyMin  float64  `json:"entropy_min"`
	CWE         []int    `json:"cwe"`
	CAPEC       []string `json:"capec"`
	Attack      []string `json:"attack_technique"`
	Tags        []string `json:"tags"`
	Message     string   `json:"message"`
	ExampleTok  string   `json:"example_token"`
	Deprecated  bool     `json:"deprecated"`
}

// category display metadata, ordered by weight.
type catMeta struct {
	Title  string
	Desc   string
	Weight int
}

var categories = map[string]catMeta{
	"cloud":              {"Secrets — Cloud Providers", "AWS, Azure, GCP, Alibaba, Oracle, DigitalOcean, IBM and other cloud-provider credential detection rules.", 1},
	"source-control":     {"Secrets — Source Control & CI/CD", "GitHub, GitLab, Bitbucket, Azure DevOps tokens and CI/CD pipeline credentials.", 2},
	"ai":                 {"Secrets — AI / LLM Providers", "OpenAI, Anthropic, Google Gemini, Hugging Face, Cohere, Mistral and other AI provider keys.", 3},
	"payment":            {"Secrets — Payment Processors", "Stripe, PayPal, Square, Braintree, Adyen and other payment-platform credentials.", 4},
	"communication":      {"Secrets — Communication & Messaging", "Slack, Twilio, Discord, Telegram, SendGrid, Mailgun and other messaging credentials.", 5},
	"package-registries": {"Secrets — Package Registries", "npm, PyPI, RubyGems, NuGet, Artifactory, Crates and other registry tokens.", 6},
	"monitoring":         {"Secrets — Monitoring & Observability", "Datadog, New Relic, Sentry, Grafana, PagerDuty and other observability keys.", 7},
	"saas":               {"Secrets — SaaS & Developer APIs", "Atlassian, Notion, Linear, Airtable, Shopify, Figma, Vercel, Netlify and other SaaS tokens.", 8},
	"database":           {"Secrets — Database Credentials", "PostgreSQL, MySQL, MongoDB, Redis and other connection strings with embedded credentials.", 9},
	"private-keys":       {"Secrets — Private Keys & Certificates", "RSA, EC, OpenSSH, PGP, WireGuard, age and other private-key material.", 10},
	"tokens":             {"Secrets — Tokens, JWT & Auth Headers", "JWTs, OAuth tokens, Bearer/Basic auth headers and generic bearer credentials.", 11},
	"crypto-blockchain":  {"Secrets — Crypto & Blockchain", "Ethereum, Bitcoin and other blockchain private keys and wallet credentials.", 12},
	"webhooks":           {"Secrets — Webhooks & Signed URLs", "Slack/Teams/Discord webhook URLs and signed URLs with embedded secrets.", 13},
	"generic":            {"Secrets — Generic High-Entropy", "Context-driven, high-entropy credential detection for unbranded API keys and passwords.", 14},
}

func severityLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func cwssFor(sev string) string {
	switch sev {
	case "critical":
		return "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H"
	case "high":
		return "CWSS:1.0/TI:H/AP:A/AL:M/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:M"
	case "medium":
		return "CWSS:1.0/TI:M/AP:A/AL:M/IC:M/FC:M/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:M"
	default:
		return "CWSS:1.0/TI:L/AP:A/AL:L/IC:L/FC:L/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:L"
	}
}

func ruleID(id int) string  { return fmt.Sprintf("VNX-SEC-%03d", id) }
func pkgName(id int) string { return fmt.Sprintf("vnx_sec_%03d", id) }
func fileName(id int) string {
	return fmt.Sprintf("vnx-sec-%03d.rego", id)
}
func docAnchor(id int) string { return fmt.Sprintf("vnx-sec-%03d", id) }

// jsonStr quotes a Go string as a JSON string literal (safe for embedding in
// Rego, which uses JSON-compatible string syntax).
func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func intList(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprintf("%d", x)
	}
	return strings.Join(parts, ", ")
}

func strList(xs []string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = jsonStr(x)
	}
	return strings.Join(parts, ", ")
}

const regoTmpl = `package vulnetix.rules.{{.Pkg}}

import rego.v1
import data.vulnetix.lib.secrets

# GENERATED by internal/sast/secretsgen from catalog.json — do not edit by hand.

metadata := {
	"id": "{{.RuleID}}",
	"name": {{.NameJSON}},
	"description": {{.DescJSON}},
	"help_uri": "{{.HelpURI}}",
	"languages": [],
	"severity": "{{.Severity}}",
	"level": "{{.Level}}",
	"kind": "secrets",
	"cwe": [{{.CWEList}}],
	"capec": [{{.CAPECList}}],
	"attack_technique": [{{.AttackList}}],
	"cvssv4": "",
	"cwss": "{{.CWSS}}",
	"tags": [{{.TagList}}],
}

_pattern := ` + "`{{.Pattern}}`" + `
{{if .HasKeywords}}_keywords := [{{.KeywordList}}]

{{end}}findings contains finding if {
	some path in object.keys(input.file_contents)
	not secrets.skip_path(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
{{if .HasKeywords}}	secrets.has_keyword(line, _keywords)
{{end}}	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(token)
{{if .HasEntropy}}	secrets.high_entropy(token, {{.EntropyMin}})
{{end}}	finding := {
		"rule_id": metadata.id,
		"message": {{.MessageJSON}},
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
`

type regoData struct {
	Pkg, RuleID, HelpURI, Severity, Level, CWSS string
	NameJSON, DescJSON, MessageJSON             string
	CWEList, CAPECList, AttackList, TagList     string
	Pattern, KeywordList                        string
	EntropyMin                                  string
	HasKeywords, HasEntropy                     bool
}

func main() {
	base := "."
	if len(os.Args) > 1 {
		base = os.Args[1]
	}
	catalogPath := filepath.Join(base, "internal", "sast", "secretsgen", "catalog.json")
	rulesDir := filepath.Join(base, "internal", "sast", "rules")
	docsDir := filepath.Join(base, "website", "content", "docs", "sast-rules", "secrets")

	raw, err := os.ReadFile(catalogPath)
	if err != nil {
		fatal("read catalog: %v", err)
	}
	var entries []Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		fatal("parse catalog: %v", err)
	}

	// Validate: unique IDs, known categories, required fields.
	seen := map[int]bool{}
	for _, e := range entries {
		if e.Deprecated {
			continue
		}
		if seen[e.ID] {
			fatal("duplicate rule id %d (%s)", e.ID, e.Name)
		}
		seen[e.ID] = true
		if _, ok := categories[e.Category]; !ok {
			fatal("rule %d: unknown category %q", e.ID, e.Category)
		}
		if e.Pattern == "" {
			fatal("rule %d (%s): empty token_pattern", e.ID, e.Name)
		}
		if e.Severity == "" {
			fatal("rule %d (%s): empty severity", e.ID, e.Name)
		}
		if e.Message == "" {
			fatal("rule %d (%s): empty message", e.ID, e.Name)
		}
	}

	tmpl := template.Must(template.New("rego").Parse(regoTmpl))

	if err := os.MkdirAll(docsDir, 0o755); err != nil {
		fatal("mkdir docs: %v", err)
	}

	// Remove previously generated rules so deletions in the catalog propagate.
	// Only files carrying the generator marker are removed; the hand-written
	// vnx-sec-001..080 rules have no marker and are left untouched.
	cleanGenerated(rulesDir)

	// Emit rego files.
	written := 0
	skipped := 0
	byCat := map[string][]Entry{}
	for _, e := range entries {
		if e.Deprecated {
			continue
		}

		// Validate the pattern against Go's RE2 engine (same engine OPA's
		// regex.match uses). Reject backreferences/lookaround/syntax errors and
		// require at least one capture group (group 1 = the secret token), so a
		// single malformed entry can never break the whole rule bundle.
		re, rerr := regexp.Compile(e.Pattern)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "secretsgen: skip rule %d (%s): invalid RE2 pattern: %v\n", e.ID, e.Name, rerr)
			skipped++
			continue
		}
		if re.NumSubexp() < 1 {
			fmt.Fprintf(os.Stderr, "secretsgen: skip rule %d (%s): pattern has no capture group for the token\n", e.ID, e.Name)
			skipped++
			continue
		}

		byCat[e.Category] = append(byCat[e.Category], e)

		cwe := e.CWE
		if len(cwe) == 0 {
			cwe = []int{798}
		}
		capec := e.CAPEC
		if len(capec) == 0 {
			capec = []string{"CAPEC-191"}
		}
		attack := e.Attack
		if len(attack) == 0 {
			attack = []string{"T1552.001"}
		}
		tags := e.Tags
		if len(tags) == 0 {
			tags = []string{"secrets"}
		}

		d := regoData{
			Pkg:         pkgName(e.ID),
			RuleID:      ruleID(e.ID),
			HelpURI:     fmt.Sprintf("https://docs.cli.vulnetix.com/docs/sast-rules/secrets/%s/#%s", e.Category, docAnchor(e.ID)),
			Severity:    e.Severity,
			Level:       severityLevel(e.Severity),
			CWSS:        cwssFor(e.Severity),
			NameJSON:    jsonStr(e.Name),
			DescJSON:    jsonStr(e.Description),
			MessageJSON: jsonStr(e.Message),
			CWEList:     intList(cwe),
			CAPECList:   strList(capec),
			AttackList:  strList(attack),
			TagList:     strList(tags),
			Pattern:     e.Pattern,
			KeywordList: strList(e.Keywords),
			HasKeywords: len(e.Keywords) > 0,
			HasEntropy:  e.EntropyMin > 0,
			EntropyMin:  strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", e.EntropyMin), "0"), "."),
		}

		var buf strings.Builder
		if err := tmpl.Execute(&buf, d); err != nil {
			fatal("render rule %d: %v", e.ID, err)
		}
		out := filepath.Join(rulesDir, fileName(e.ID))
		if err := os.WriteFile(out, []byte(buf.String()), 0o644); err != nil {
			fatal("write rule %d: %v", e.ID, err)
		}
		written++
	}

	// Emit category doc pages + section index.
	emitDocs(docsDir, byCat)

	fmt.Printf("secretsgen: wrote %d rego rules across %d categories (%d skipped)\n", written, len(byCat), skipped)
}

func emitDocs(docsDir string, byCat map[string][]Entry) {
	// Section index.
	var idx strings.Builder
	idx.WriteString("---\ntitle: \"Secrets / Credentials\"\ndescription: \"Exhaustive, high-fidelity hardcoded-secret detection rules grouped by category.\"\nweight: 6\n---\n\n")
	idx.WriteString("Vulnetix detects hardcoded credentials, API keys, tokens and private keys across source code, configuration, binaries (via printable-string and EXIF extraction) and full git history. Each rule runs a cheap keyword/prefix prefilter, extracts the candidate token, then applies allowlist and Shannon-entropy filtering to suppress false positives before reporting a SARIF finding.\n\n")
	idx.WriteString("## Categories\n\n{{< cards >}}\n")

	// Order categories by weight.
	var slugs []string
	for s := range byCat {
		slugs = append(slugs, s)
	}
	sort.Slice(slugs, func(i, j int) bool {
		return categories[slugs[i]].Weight < categories[slugs[j]].Weight
	})

	for _, slug := range slugs {
		cm := categories[slug]
		fmt.Fprintf(&idx, "  {{< card link=\"%s\" title=%q subtitle=%q >}}\n", slug, cm.Title, fmt.Sprintf("%d rules", len(byCat[slug])))
	}
	idx.WriteString("{{< /cards >}}\n")
	if err := os.WriteFile(filepath.Join(docsDir, "_index.md"), []byte(idx.String()), 0o644); err != nil {
		fatal("write secrets index: %v", err)
	}

	for slug, list := range byCat {
		cm := categories[slug]
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		var b strings.Builder
		fmt.Fprintf(&b, "---\ntitle: %q\ndescription: %q\nweight: %d\n---\n\n", cm.Title, cm.Desc, cm.Weight)
		b.WriteString(cm.Desc)
		b.WriteString("\n\n")
		b.WriteString("All rules in this category are kind `secrets`. They run under `vulnetix secrets` and the secrets stage of `vulnetix scan`.\n\n")
		b.WriteString("| Rule ID | Name | Severity | Detection |\n|---------|------|----------|-----------|\n")
		for _, e := range list {
			det := detectionLabel(e)
			fmt.Fprintf(&b, "| <a id=%q></a>%s | %s | %s | %s |\n", docAnchor(e.ID), ruleID(e.ID), e.Name, capitalize(e.Severity), det)
		}
		b.WriteString("\n## Remediation\n\nRotate any exposed credential immediately, remove it from source, and load it from a secrets manager or environment variable instead. Purge it from git history with `git filter-repo`. See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) and the [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).\n")
		if err := os.WriteFile(filepath.Join(docsDir, slug+".md"), []byte(b.String()), 0o644); err != nil {
			fatal("write category %s: %v", slug, err)
		}
	}
}

func detectionLabel(e Entry) string {
	switch {
	case e.EntropyMin > 0 && len(e.Keywords) > 0:
		return "keyword + regex + entropy"
	case e.EntropyMin > 0:
		return "regex + entropy"
	case len(e.Keywords) > 0:
		return "keyword + regex"
	default:
		return "regex"
	}
}

// cleanGenerated removes every vnx-sec-*.rego file that carries the generator
// marker, so a catalog deletion does not leave an orphan rule behind.
func cleanGenerated(rulesDir string) {
	matches, _ := filepath.Glob(filepath.Join(rulesDir, "vnx-sec-*.rego"))
	for _, p := range matches {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if strings.Contains(string(b), "GENERATED by internal/sast/secretsgen") {
			_ = os.Remove(p)
		}
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "secretsgen: "+format+"\n", a...)
	os.Exit(1)
}
