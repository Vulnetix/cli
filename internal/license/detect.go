package license

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/vulnetix/cli/internal/scan"
)

// DetectLicenses takes already-parsed packages and resolves their licenses.
// It reads the original manifest files to extract license fields where possible,
// falling back to the embedded SPDX database for well-known packages.
// When groups is non-nil, dependency paths are computed for each package.
func DetectLicenses(packages []scan.ScopedPackage, groups []scan.ManifestGroup) []PackageLicense {
	result := make([]PackageLicense, 0, len(packages))

	// Group packages by source file so we only read each manifest once.
	byFile := map[string][]int{} // sourceFile → indices into packages
	for i, pkg := range packages {
		byFile[pkg.SourceFile] = append(byFile[pkg.SourceFile], i)
	}

	// Extract per-manifest license maps.
	fileLicenses := map[string]map[string]string{} // sourceFile → packageName → spdxID
	for file := range byFile {
		if lm := extractManifestLicenses(file); lm != nil {
			fileLicenses[file] = lm
		}
	}

	for i, pkg := range packages {
		pl := PackageLicense{
			PackageName:    pkg.Name,
			PackageVersion: pkg.Version,
			Ecosystem:      pkg.Ecosystem,
			Scope:          pkg.Scope,
			SourceFile:     pkg.SourceFile,
			IsDirect:       pkg.IsDirect,
		}

		// 1. Check manifest-extracted licenses.
		if lm, ok := fileLicenses[pkg.SourceFile]; ok {
			if lic, ok := lm[pkg.Name]; ok {
				pl.LicenseSpdxID = lic
				pl.LicenseSource = "manifest"
			}
		}

		// 2. Fallback: check if the package itself declares a license in its manifest
		//    (for the root package.json, the "license" field applies to the project itself).
		if pl.LicenseSpdxID == "" {
			// For the project's own manifest, we may have a project-level license.
			if lm, ok := fileLicenses[pkg.SourceFile]; ok {
				if lic, ok := lm[""]; ok && pkg.IsDirect {
					// Project-level license — don't assign to deps.
					_ = lic
				}
			}
		}

		// 3. Fallback: filesystem — look for LICENSE files in Go module cache.
		if pl.LicenseSpdxID == "" && pkg.Ecosystem == "golang" {
			if lic := FindLicenseInModuleCache(pkg.Name, pkg.Version); lic != "" {
				pl.LicenseSpdxID = lic
				pl.LicenseSource = "filesystem"
			}
		}

		// 4. Fallback: container/IaC — Docker labels, Terraform registry, Nix CLI.
		if pl.LicenseSpdxID == "" {
			if lic := FetchContainerLicense(pkg.Name, pkg.Version, pkg.Ecosystem); lic != "" {
				pl.LicenseSpdxID = lic
				pl.LicenseSource = "container"
			}
		}

		// 5. Fallback: embedded SPDX DB lookup by well-known package names.
		if pl.LicenseSpdxID == "" {
			if guessed := guessLicenseFromDB(pkg.Name, pkg.Ecosystem); guessed != "" {
				pl.LicenseSpdxID = guessed
				pl.LicenseSource = "embedded-db"
			}
		}

		if pl.LicenseSpdxID == "" {
			pl.LicenseSpdxID = "UNKNOWN"
		}

		// Resolve record from SPDX DB.
		if pl.LicenseSpdxID != "UNKNOWN" {
			ids := ParseSPDXExpression(pl.LicenseSpdxID)
			if len(ids) > 0 {
				pl.Record = LookupSPDX(ids[0])
			}
		}

		_ = i
		result = append(result, pl)
	}

	// 6. Batch-resolve remaining UNKNOWNs via deps.dev API.
	BatchFetchLicenses(result, nil)

	// 7. Batch-resolve remaining UNKNOWNs via GitHub (gh CLI or API with PAT).
	BatchFetchGitHubLicenses(result, nil)

	// 8. Compute dependency provenance paths from ManifestGroups.
	computeProvenance(result, groups)

	return result
}

// computeProvenance fills IntroducedPaths and PathCount on each PackageLicense
// using the dependency graphs from ManifestGroups.
func computeProvenance(packages []PackageLicense, groups []scan.ManifestGroup) {
	if len(groups) == 0 {
		return
	}

	for i := range packages {
		pkg := &packages[i]

		// Find the matching ManifestGroup for this package's ecosystem and source file.
		for _, mg := range groups {
			if mg.Graph == nil {
				continue
			}

			// Match by ecosystem and directory.
			if !strings.EqualFold(mg.Ecosystem, pkg.Ecosystem) {
				continue
			}

			// Check if this package's source file belongs to this group.
			inGroup := false
			for _, f := range mg.Files {
				if f == pkg.SourceFile {
					inGroup = true
					break
				}
			}
			if !inGroup {
				continue
			}

			if mg.Graph.IsDirect(pkg.PackageName) {
				pkg.PathCount = 1
				// Direct deps have no introduction chain — they ARE the root.
			} else {
				chain := mg.Graph.FindPath(pkg.PackageName)
				if len(chain) > 1 {
					pkg.IntroducedPaths = append(pkg.IntroducedPaths, chain)
					pkg.PathCount = len(pkg.IntroducedPaths)
				} else {
					pkg.PathCount = 1 // couldn't determine path, but package exists
				}
			}
			break // matched a group
		}
	}
}

// extractManifestLicenses reads a manifest file and returns a map of
// package-name → SPDX license ID for packages that declare licenses inline.
// The key "" is used for the project-level license.
func extractManifestLicenses(filePath string) map[string]string {
	base := manifestBasename(filePath)
	switch base {
	case "package.json":
		return extractPackageJSONLicenses(filePath)
	case "composer.json":
		return extractComposerJSONLicenses(filePath)
	case "Cargo.toml":
		return extractCargoTOMLLicenses(filePath)
	case "pyproject.toml":
		return extractPyprojectTOMLLicenses(filePath)
	default:
		return nil
	}
}

func manifestBasename(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return path
	}
	return parts[len(parts)-1]
}

// ── package.json ──────────────────────────────────────────────────────────

func extractPackageJSONLicenses(filePath string) map[string]string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	result := map[string]string{}

	// Project-level license.
	if licRaw, ok := raw["license"]; ok {
		var licStr string
		if json.Unmarshal(licRaw, &licStr) == nil {
			result[""] = NormalizeSPDX(licStr)
		} else {
			// Handle {type: "MIT"} format.
			var licObj struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(licRaw, &licObj) == nil && licObj.Type != "" {
				result[""] = NormalizeSPDX(licObj.Type)
			}
		}
	}

	// Dependencies don't have license fields in package.json — they're in
	// each dep's own package.json inside node_modules. We can't reliably
	// read those, so we return just the project license.
	return result
}

// ── composer.json ─────────────────────────────────────────────────────────

func extractComposerJSONLicenses(filePath string) map[string]string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	var raw struct {
		License json.RawMessage `json:"license"`
	}
	if err := json.Unmarshal(data, &raw); err != nil || raw.License == nil {
		return nil
	}

	result := map[string]string{}

	// License can be a string or array of strings.
	var licStr string
	if json.Unmarshal(raw.License, &licStr) == nil {
		result[""] = NormalizeSPDX(licStr)
		return result
	}
	var licArr []string
	if json.Unmarshal(raw.License, &licArr) == nil && len(licArr) > 0 {
		result[""] = NormalizeSPDX(licArr[0])
	}
	return result
}

// ── Cargo.toml ────────────────────────────────────────────────────────────

func extractCargoTOMLLicenses(filePath string) map[string]string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	result := map[string]string{}
	// Simple TOML parser — look for license = "..." in [package] section.
	inPackage := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inPackage = strings.HasPrefix(trimmed, "[package]")
			continue
		}
		if inPackage && strings.HasPrefix(trimmed, "license") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				if key == "license" {
					val := strings.TrimSpace(parts[1])
					val = strings.Trim(val, "\"'")
					if val != "" {
						result[""] = NormalizeSPDX(val)
					}
				}
			}
		}
	}
	return result
}

// ── pyproject.toml ────────────────────────────────────────────────────────

func extractPyprojectTOMLLicenses(filePath string) map[string]string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	result := map[string]string{}
	// Look for license = "..." or license = {text = "..."} in [project] section.
	inProject := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inProject = strings.HasPrefix(trimmed, "[project]")
			continue
		}
		if inProject && strings.HasPrefix(trimmed, "license") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				if key == "license" {
					// Handle simple string: license = "MIT"
					if (strings.HasPrefix(val, "\"") || strings.HasPrefix(val, "'")) && !strings.HasPrefix(val, "{") {
						val = strings.Trim(val, "\"'")
						if val != "" {
							result[""] = NormalizeSPDX(val)
						}
					}
					// Handle inline table: license = {text = "MIT"}
					if strings.HasPrefix(val, "{") {
						if idx := strings.Index(val, "text"); idx >= 0 {
							after := val[idx:]
							eqIdx := strings.Index(after, "=")
							if eqIdx >= 0 {
								rest := strings.TrimSpace(after[eqIdx+1:])
								rest = strings.Trim(rest, "\"' }")
								if rest != "" {
									result[""] = NormalizeSPDX(rest)
								}
							}
						}
					}
				}
			}
		}
	}
	return result
}

// ── Well-known package license DB ─────────────────────────────────────────

// guessLicenseFromDB returns a license SPDX ID for well-known packages.
// This is a small curated set; unknown packages return "".
func guessLicenseFromDB(name, ecosystem string) string {
	key := ecosystem + ":" + name
	if lic, ok := wellKnownLicenses[key]; ok {
		return lic
	}
	return ""
}

// wellKnownLicenses maps ecosystem:packageName to SPDX ID for common packages
// that don't declare licenses in their manifests (e.g., Go modules).
var wellKnownLicenses = map[string]string{
	// Go standard library ecosystem
	"golang:golang.org/x/crypto":  "BSD-3-Clause",
	"golang:golang.org/x/net":     "BSD-3-Clause",
	"golang:golang.org/x/sys":     "BSD-3-Clause",
	"golang:golang.org/x/text":    "BSD-3-Clause",
	"golang:golang.org/x/tools":   "BSD-3-Clause",
	"golang:golang.org/x/sync":    "BSD-3-Clause",
	"golang:golang.org/x/mod":     "BSD-3-Clause",
	"golang:golang.org/x/exp":     "BSD-3-Clause",
	"golang:golang.org/x/time":    "BSD-3-Clause",
	"golang:golang.org/x/oauth2":  "BSD-3-Clause",
	"golang:golang.org/x/term":    "BSD-3-Clause",
	"golang:golang.org/x/image":   "BSD-3-Clause",
	"golang:google.golang.org/protobuf": "BSD-3-Clause",
	"golang:google.golang.org/grpc":     "Apache-2.0",
	"golang:google.golang.org/genproto": "Apache-2.0",
	"golang:google.golang.org/api":      "BSD-3-Clause",
	"golang:github.com/google/uuid":     "BSD-3-Clause",
	"golang:github.com/google/go-cmp":   "BSD-3-Clause",
	"golang:github.com/stretchr/testify": "MIT",
	"golang:github.com/spf13/cobra":     "Apache-2.0",
	"golang:github.com/spf13/viper":     "MIT",
	"golang:github.com/spf13/pflag":     "BSD-3-Clause",
	"golang:github.com/spf13/afero":     "Apache-2.0",
	"golang:github.com/gorilla/mux":     "BSD-3-Clause",
	"golang:github.com/gin-gonic/gin":   "MIT",
	"golang:github.com/sirupsen/logrus": "MIT",
	"golang:github.com/go-chi/chi":      "MIT",
	"golang:github.com/pkg/errors":      "BSD-2-Clause",
	"golang:github.com/rs/zerolog":      "MIT",
	"golang:github.com/fatih/color":     "MIT",
	"golang:github.com/mattn/go-isatty": "MIT",
	"golang:github.com/charmbracelet/lipgloss": "MIT",
	"golang:github.com/charmbracelet/bubbletea": "MIT",
	"golang:github.com/charmbracelet/bubbles":   "MIT",
	"golang:github.com/muesli/termenv":          "MIT",
	"golang:github.com/muesli/reflow":           "MIT",
	"golang:gopkg.in/yaml.v3":           "Apache-2.0",
	"golang:gopkg.in/yaml.v2":           "Apache-2.0",

	// npm popular packages
	"npm:express":    "MIT",
	"npm:react":      "MIT",
	"npm:react-dom":  "MIT",
	"npm:vue":        "MIT",
	"npm:lodash":     "MIT",
	"npm:axios":      "MIT",
	"npm:typescript":  "Apache-2.0",
	"npm:webpack":    "MIT",
	"npm:next":       "MIT",
	"npm:eslint":     "MIT",
	"npm:prettier":   "MIT",
	"npm:jest":       "MIT",
	"npm:mocha":      "MIT",
	"npm:chalk":      "MIT",
	"npm:commander":  "MIT",

	// Python popular packages
	"pypi:requests":    "Apache-2.0",
	"pypi:flask":       "BSD-3-Clause",
	"pypi:django":      "BSD-3-Clause",
	"pypi:numpy":       "BSD-3-Clause",
	"pypi:pandas":      "BSD-3-Clause",
	"pypi:pytest":      "MIT",
	"pypi:setuptools":  "MIT",
	"pypi:pip":         "MIT",
	"pypi:boto3":       "Apache-2.0",
	"pypi:pyyaml":      "MIT",
	"pypi:cryptography": "Apache-2.0",
	"pypi:urllib3":     "MIT",
	"pypi:certifi":     "MPL-2.0",
	"pypi:click":       "BSD-3-Clause",

	// Rust popular crates
	"cargo:serde":       "MIT",
	"cargo:serde_json":  "MIT",
	"cargo:tokio":       "MIT",
	"cargo:clap":        "MIT",
	"cargo:rand":        "MIT",
	"cargo:log":         "MIT",
	"cargo:regex":       "MIT",
	"cargo:reqwest":     "MIT",
	"cargo:hyper":       "MIT",
	"cargo:anyhow":      "MIT",
	"cargo:thiserror":   "MIT",
}
