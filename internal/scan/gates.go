package scan

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ValidExploitThresholds lists the accepted values for the --exploits flag,
// in ascending order of exploit maturity (least → most dangerous).
var ValidExploitThresholds = []string{"poc", "active", "weaponized"}

// ExploitMeetsThreshold reports whether ev's exploit signals reach the given tier.
//
// Tiers form a strict hierarchy — each tier also captures all higher-maturity signals:
//
//	poc       : any public exploit exists (ExploitCount > 0, or any KEV entry)
//	active    : known active exploitation (InCisaKev || InVulnCheckKev || InEuKev || HasWeaponized)
//	weaponized: weaponised in-the-wild (ExploitIntel.HasWeaponized)
func ExploitMeetsThreshold(ev EnrichedVuln, threshold string) bool {
	switch threshold {
	case "poc":
		return (ev.ExploitIntel != nil && ev.ExploitIntel.ExploitCount > 0) ||
			ev.InCisaKev || ev.InVulnCheckKev || ev.InEuKev
	case "active":
		return ev.InCisaKev || ev.InVulnCheckKev || ev.InEuKev ||
			(ev.ExploitIntel != nil && ev.ExploitIntel.HasWeaponized)
	case "weaponized":
		return ev.ExploitIntel != nil && ev.ExploitIntel.HasWeaponized
	}
	return false
}

// HasAnyKev returns true if the vulnerability is listed in any KEV catalog
// (CISA, VulnCheck, or EU ENISA).
func HasAnyKev(ev EnrichedVuln) bool {
	return ev.InCisaKev || ev.InVulnCheckKev || ev.InEuKev
}

// IsVersionSpecPinned reports whether spec represents an exact version pin.
// An empty spec (e.g. lock-file entries) is treated as pinned.
// Specs that begin with range operators (^, ~, >=, >, <=, <, !=) or are
// symbolic (*, latest, x) are considered unpinned.
func IsVersionSpecPinned(spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true // lock-file entry — always pinned
	}
	if spec == "*" || spec == "latest" || spec == "x" {
		return false
	}
	// Check two-character prefixes before single-character ones to avoid partial matches.
	for _, prefix := range []string{"~=", ">=", "<=", "!="} {
		if strings.HasPrefix(spec, prefix) {
			return false
		}
	}
	for _, prefix := range []string{"^", "~", ">", "<"} {
		if strings.HasPrefix(spec, prefix) {
			return false
		}
	}
	return true // starts with digit or "v" — exact pin
}

// RuntimePin records a runtime version detected from a version-pin file.
type RuntimePin struct {
	Product    string // VDB EOL product name: "go", "nodejs", "python", "ruby"
	Release    string // normalised for the EOL API: "1.21", "18", "3.10"
	RawVersion string // raw version string from the file
	SourceFile string // relative path of the pin file within the project root
}

// DetectRuntimeVersionPins scans rootPath for common runtime version-pin files
// and returns the detected runtime versions. Only the project root is inspected
// (no recursion). Errors reading individual files are silently skipped.
//
// Files inspected: go.mod, .nvmrc, .node-version, .python-version,
// .tool-versions, .ruby-version, Gemfile, Dockerfile, Containerfile.
// LTS aliases in .nvmrc (e.g. "lts/hydrogen") are silently skipped.
func DetectRuntimeVersionPins(rootPath string) []RuntimePin {
	var pins []RuntimePin

	// alreadyPinned returns true if a pin for the given product has already been recorded.
	alreadyPinned := func(product string) bool {
		for _, p := range pins {
			if p.Product == product {
				return true
			}
		}
		return false
	}

	// tryFile reads a single file and extracts a version via parse. A non-empty
	// return value is normalised and appended to pins (dedup by product).
	tryFile := func(name, product string, parse func([]byte) string) {
		if alreadyPinned(product) {
			return
		}
		data, err := os.ReadFile(filepath.Join(rootPath, name))
		if err != nil {
			return
		}
		raw := parse(data)
		if raw == "" {
			return
		}
		release := NormaliseReleaseForEOL(product, raw)
		if release == "" {
			return
		}
		pins = append(pins, RuntimePin{
			Product:    product,
			Release:    release,
			RawVersion: raw,
			SourceFile: name,
		})
	}

	// ── go.mod — "go X.Y" or "go X.Y.Z" directive ─────────────────────────
	tryFile("go.mod", "go", func(b []byte) string {
		re := regexp.MustCompile(`(?m)^go\s+(\d+\.\d+(?:\.\d+)?)`)
		if m := re.FindSubmatch(b); m != nil {
			return string(m[1])
		}
		return ""
	})

	// ── .nvmrc / .node-version — raw version string ────────────────────────
	nodeParser := func(b []byte) string {
		v := strings.TrimSpace(string(b))
		if strings.HasPrefix(strings.ToLower(v), "lts/") {
			return "" // LTS aliases are not version strings
		}
		return strings.TrimPrefix(v, "v")
	}
	tryFile(".nvmrc", "nodejs", nodeParser)
	tryFile(".node-version", "nodejs", nodeParser)

	// ── .python-version ────────────────────────────────────────────────────
	tryFile(".python-version", "python", func(b []byte) string {
		return strings.TrimSpace(string(b))
	})

	// ── .ruby-version / Gemfile ruby directive ─────────────────────────────
	tryFile(".ruby-version", "ruby", func(b []byte) string {
		return strings.TrimSpace(string(b))
	})
	tryFile("Gemfile", "ruby", func(b []byte) string {
		re := regexp.MustCompile(`(?m)^ruby\s+['"](\d+\.\d+(?:\.\d+)?)['"]`)
		if m := re.FindSubmatch(b); m != nil {
			return string(m[1])
		}
		return ""
	})

	// ── .tool-versions (asdf) — "tool version" lines ──────────────────────
	if data, err := os.ReadFile(filepath.Join(rootPath, ".tool-versions")); err == nil {
		asdfMap := map[string]string{
			"python": "python",
			"nodejs": "nodejs",
			"node":   "nodejs",
			"ruby":   "ruby",
			"golang": "go",
			"go":     "go",
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			product, ok := asdfMap[strings.ToLower(parts[0])]
			if !ok || alreadyPinned(product) {
				continue
			}
			raw := parts[1]
			release := NormaliseReleaseForEOL(product, raw)
			if release == "" {
				continue
			}
			pins = append(pins, RuntimePin{
				Product:    product,
				Release:    release,
				RawVersion: raw,
				SourceFile: ".tool-versions",
			})
		}
	}

	// ── Dockerfile / Containerfile — FROM <image>:<tag> ───────────────────
	dockerProducts := map[string]string{
		"node":   "nodejs",
		"python": "python",
		"golang": "go",
		"ruby":   "ruby",
	}
	fromRe := regexp.MustCompile(`(?im)^FROM\s+(\S+)`)
	tagVersionRe := regexp.MustCompile(`^(\d+(?:\.\d+)*)`)

	for _, dfName := range []string{"Dockerfile", "Containerfile"} {
		data, err := os.ReadFile(filepath.Join(rootPath, dfName))
		if err != nil {
			continue
		}
		for _, m := range fromRe.FindAllSubmatch(data, -1) {
			imageRef := strings.ToLower(string(m[1]))
			// Strip registry prefix (e.g. "docker.io/library/node:18" → "node:18").
			if idx := strings.LastIndex(imageRef, "/"); idx != -1 {
				imageRef = imageRef[idx+1:]
			}
			parts := strings.SplitN(imageRef, ":", 2)
			if len(parts) < 2 {
				continue
			}
			product, ok := dockerProducts[parts[0]]
			if !ok || alreadyPinned(product) {
				continue
			}
			tm := tagVersionRe.FindStringSubmatch(parts[1])
			if tm == nil {
				continue
			}
			raw := tm[1]
			release := NormaliseReleaseForEOL(product, raw)
			if release == "" {
				continue
			}
			pins = append(pins, RuntimePin{
				Product:    product,
				Release:    release,
				RawVersion: raw,
				SourceFile: dfName,
			})
		}
	}

	return pins
}

// NormaliseReleaseForEOL reduces a full version string to the form expected by
// the VDB EOL API for the given product.
//
//	go     : major.minor  ("1.21.3" → "1.21",  "1.21" → "1.21")
//	nodejs : major only   ("18.20.4" → "18",   "18" → "18")
//	python : major.minor  ("3.10.4"  → "3.10", "3.10" → "3.10")
//	ruby   : major.minor  ("3.2.1"   → "3.2",  "3.2"  → "3.2")
//
// Returns "" if the version string cannot be parsed.
func NormaliseReleaseForEOL(product, version string) string {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.Split(version, ".")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	switch product {
	case "nodejs":
		return parts[0] // major only
	case "go", "python", "ruby":
		if len(parts) >= 2 {
			return parts[0] + "." + parts[1]
		}
		return parts[0]
	default:
		if len(parts) >= 2 {
			return parts[0] + "." + parts[1]
		}
		return parts[0]
	}
}
