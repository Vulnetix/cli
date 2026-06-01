package license

// Repo-level license detection. Distinct from DetectLicenses (which resolves
// per-package licenses for everything in a manifest) — this scans the repo
// root for LICENSE / COPYING text files and the top-level license field in
// common manifest files (package.json, pyproject.toml, Cargo.toml, etc.).
//
// Output is fed into CliEnv.Licenses so /v2/cli.sca can populate SBOMLicense +
// CycloneDXInfoLicense rows for the project as a whole.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RepoLicenseHit mirrors the shape vdb-api expects on CliEnv.Licenses.
type RepoLicenseHit struct {
	SPDXID      string `json:"spdxId,omitempty"`
	Name        string `json:"name,omitempty"`
	URL         string `json:"url,omitempty"`
	Source      string `json:"source,omitempty"`          // "file:LICENSE" | "manifest:package.json"
	Acknowledge string `json:"acknowledgement,omitempty"` // "declared" | "concluded"
	Text        string `json:"text,omitempty"`            // first N bytes of license text
}

// commonLicenseFiles is the literal-filename list we probe for a license at
// the repo root. Case-sensitive on Linux; we also try lower-case variants.
var commonLicenseFiles = []string{
	"LICENSE",
	"LICENCE",
	"LICENSE.md",
	"LICENCE.md",
	"LICENSE.txt",
	"LICENCE.txt",
	"COPYING",
	"COPYING.md",
	"COPYING.txt",
	"MIT-LICENSE",
	"MIT-LICENSE.txt",
	"APACHE-LICENSE",
	"BSD-LICENSE",
}

// commonManifestFiles maps a top-level manifest file → the kind of parse we
// run on it to extract the project license string. Keep this list short and
// focused on the most-used ecosystems; per-language deep parsing belongs in
// DetectLicenses (which already handles package-level extraction).
var commonManifestFiles = map[string]manifestParser{
	"package.json":   parsePackageJSONLicense,
	"composer.json":  parseComposerJSONLicense,
	"Cargo.toml":     parseCargoTOMLLicense,
	"pyproject.toml": parsePyprojectLicense,
	"setup.cfg":      parseSetupCfgLicense,
}

type manifestParser func(path string) string

// DetectRepoLicense scans the given repo root for license signals. Returns
// one hit per distinct (SPDX, source) tuple. Always returns nil rather than
// an error on read failure — license detection is best-effort context.
func DetectRepoLicense(repoRoot string) []RepoLicenseHit {
	if repoRoot == "" {
		return nil
	}
	var hits []RepoLicenseHit
	seen := make(map[string]bool) // spdx|source → dedup

	add := func(spdx, source, text string) {
		spdx = strings.TrimSpace(spdx)
		if spdx == "" || strings.EqualFold(spdx, "UNKNOWN") {
			return
		}
		key := strings.ToUpper(spdx) + "|" + source
		if seen[key] {
			return
		}
		seen[key] = true
		hit := RepoLicenseHit{
			SPDXID:      spdx,
			Source:      source,
			Acknowledge: "declared",
		}
		if rec := LookupSPDX(spdx); rec != nil {
			hit.Name = rec.Name
			hit.URL = "https://spdx.org/licenses/" + rec.SpdxID + ".html"
		}
		if hit.Name == "" {
			hit.Name = spdx
		}
		if text != "" {
			hit.Text = truncateText(text, 4000)
		}
		hits = append(hits, hit)
	}

	// 1) Standalone license text files at repo root.
	for _, name := range commonLicenseFiles {
		path := filepath.Join(repoRoot, name)
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := string(body)
		spdx := identifyLicenseFromText(text)
		if spdx == "" {
			// We still know there's a license file even if we couldn't classify it.
			spdx = "NOASSERTION"
		}
		add(spdx, "file:"+name, text)
	}

	// 2) Top-level manifest license fields.
	for fileName, parser := range commonManifestFiles {
		path := filepath.Join(repoRoot, fileName)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if spdx := parser(path); spdx != "" {
			add(spdx, "manifest:"+fileName, "")
		}
	}

	return hits
}

func parsePackageJSONLicense(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var pkg struct {
		License  any `json:"license"`
		Licenses []struct {
			Type string `json:"type"`
		} `json:"licenses"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return ""
	}
	switch v := pkg.License.(type) {
	case string:
		return v
	case map[string]any:
		if t, ok := v["type"].(string); ok {
			return t
		}
	}
	if len(pkg.Licenses) > 0 && pkg.Licenses[0].Type != "" {
		return pkg.Licenses[0].Type
	}
	return ""
}

func parseComposerJSONLicense(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var pkg struct {
		License any `json:"license"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return ""
	}
	switch v := pkg.License.(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// parseCargoTOMLLicense and parsePyprojectLicense use a minimal regex
// extractor — we deliberately avoid pulling in a TOML parser dependency for
// what is two trivial string lookups.
var (
	cargoLicRe  = regexp.MustCompile(`(?m)^\s*license\s*=\s*"([^"]+)"`)
	pyprojectRe = regexp.MustCompile(`(?m)^\s*license\s*=\s*"([^"]+)"`)
	setupcfgRe  = regexp.MustCompile(`(?m)^\s*license\s*=\s*(.+)$`)
)

func parseCargoTOMLLicense(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if m := cargoLicRe.FindStringSubmatch(string(body)); len(m) == 2 {
		return m[1]
	}
	return ""
}

func parsePyprojectLicense(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := string(body)
	// Try plain `license = "MIT"` first.
	if m := pyprojectRe.FindStringSubmatch(s); len(m) == 2 {
		return m[1]
	}
	// Then PEP 621 inline table: `license = { text = "MIT" }`.
	textRe := regexp.MustCompile(`(?m)^\s*license\s*=\s*\{\s*text\s*=\s*"([^"]+)"`)
	if m := textRe.FindStringSubmatch(s); len(m) == 2 {
		return m[1]
	}
	return ""
}

func parseSetupCfgLicense(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if m := setupcfgRe.FindStringSubmatch(string(body)); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// identifyLicenseFromText runs a small set of high-confidence header matches.
// Returns "" when nothing matches; the caller substitutes NOASSERTION so the
// file still surfaces as evidence even when classification fails.
func identifyLicenseFromText(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "mit license"):
		return "MIT"
	case strings.Contains(lower, "apache license") && strings.Contains(lower, "version 2.0"):
		return "Apache-2.0"
	case strings.Contains(lower, "gnu general public license") && strings.Contains(lower, "version 3"):
		return "GPL-3.0-or-later"
	case strings.Contains(lower, "gnu general public license") && strings.Contains(lower, "version 2"):
		return "GPL-2.0-or-later"
	case strings.Contains(lower, "gnu lesser general public license"):
		return "LGPL-3.0-or-later"
	case strings.Contains(lower, "gnu affero general public license"):
		return "AGPL-3.0-or-later"
	case strings.Contains(lower, "mozilla public license") && strings.Contains(lower, "version 2.0"):
		return "MPL-2.0"
	case strings.Contains(lower, "bsd 3-clause"):
		return "BSD-3-Clause"
	case strings.Contains(lower, "bsd 2-clause"):
		return "BSD-2-Clause"
	case strings.Contains(lower, "isc license"):
		return "ISC"
	case strings.Contains(lower, "unlicense"):
		return "Unlicense"
	}
	return ""
}

func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
