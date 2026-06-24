package aibom

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/sast"
)

// detectFiles records on-disk evidence: for every tool, every categorised path
// glob is matched against the scanned file set, and any model-config extractors
// are run over their matching files.
func (c *collector) detectFiles(input *sast.ScanInput) {
	if input == nil {
		return
	}
	// A stable slice of paths, reused for every glob rule.
	paths := make([]string, 0, len(input.FileSet))
	for p := range input.FileSet {
		paths = append(paths, p)
	}

	for i := range c.cat.Tools {
		t := &c.cat.Tools[i]
		for _, rule := range t.Paths {
			if rule.Exact {
				if input.FileSet[rule.Raw] {
					c.toolFileHit(t.Def, rule.Category, rule.Raw)
				}
				continue
			}
			for _, p := range paths {
				if rule.Re.MatchString(p) {
					c.toolFileHit(t.Def, rule.Category, p)
				}
			}
		}
	}

	c.runConfigExtractors(paths)
}

func (c *collector) toolFileHit(def ToolDef, category, path string) {
	h := c.tool(def)
	h.methods["file"] = true
	// Shared convention files (AGENTS.md, .mcp.json, ...) record evidence but do
	// not establish a tool on their own, nor drive its confidence.
	if sharedConventionBasenames[strings.ToLower(filepath.Base(path))] {
		h.shared++
	} else {
		h.primary++
		h.counts[category]++
	}
	if len(h.evidence) < maxEvidenceCollect {
		h.evidence = append(h.evidence, cdx.AIEvidence{Method: "file", Category: category, Locator: path})
	}
}

// runConfigExtractors reads each file that matches a tool's model-config
// extractor and records the model literals it carries.
func (c *collector) runConfigExtractors(paths []string) {
	for i := range c.cat.Tools {
		t := &c.cat.Tools[i]
		if len(t.Extractors) == 0 {
			continue
		}
		for _, p := range paths {
			var content string
			loaded := false
			for _, ex := range t.Extractors {
				if !ex.FileGlob.MatchString(p) {
					continue
				}
				if !loaded {
					data, err := os.ReadFile(filepath.Join(c.root, filepath.FromSlash(p)))
					if err != nil {
						break
					}
					content = string(data)
					loaded = true
				}
				var hits []extracted
				if ex.JSONKey != "" {
					hits = extractKeyValue(content, ex.JSONKey)
				} else {
					hits = findSubmatches(content, ex.Re)
				}
				for _, h := range hits {
					loc := p
					if h.line > 0 {
						loc = p + ":" + itoa(h.line)
					}
					c.addModel(h.value, t.Def.Vendor, "", "config", cdx.AIEvidence{
						Method: "config", Category: "model", Locator: loc, Snippet: h.value,
					})
				}
			}
		}
	}
}

// detectHome probes the user's home directory for each tool's config directory
// (e.g. ~/.claude, ~/.cursor). Only the literal prefix of a config/skills glob
// is checked, and only its existence is recorded — never its contents.
func (c *collector) detectHome() {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	for i := range c.cat.Tools {
		t := &c.cat.Tools[i]
		seen := map[string]bool{}
		for _, rule := range t.Paths {
			if rule.Category != "config" && rule.Category != "skills" {
				continue
			}
			prefix := literalPrefix(rule.Raw)
			if prefix == "" || seen[prefix] {
				continue
			}
			seen[prefix] = true
			if _, err := os.Stat(filepath.Join(home, filepath.FromSlash(prefix))); err == nil {
				h := c.tool(t.Def)
				h.methods["home"] = true
				h.counts[rule.Category]++
				if len(h.evidence) < maxEvidenceCollect {
					h.evidence = append(h.evidence, cdx.AIEvidence{
						Method: "home", Category: rule.Category, Locator: "~/" + prefix,
					})
				}
			}
		}
	}
}

// extractKeyValue pulls the value of a JSON/YAML key from file content. Handles
// both "key": "value" (JSON) and key: value (YAML) forms.
func extractKeyValue(content, key string) []extracted {
	re := regexp.MustCompile(`(?m)(?:"` + regexp.QuoteMeta(key) + `"|\b` + regexp.QuoteMeta(key) + `)\s*[:=]\s*["']?([^"'\s,}#]+)`)
	out := findSubmatches(content, re)
	cleaned := out[:0]
	for _, e := range out {
		e.value = strings.TrimRight(e.value, ",")
		if e.value != "" {
			cleaned = append(cleaned, e)
		}
	}
	return cleaned
}
