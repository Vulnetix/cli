package license

import (
	"os"
	"path/filepath"
	"strings"
)

// licenseFileNames lists license file patterns in priority order.
var licenseFileNames = []string{
	"LICENSE",
	"LICENSE.txt",
	"LICENSE.md",
	"LICENCE",
	"LICENCE.txt",
	"LICENCE.md",
	"License",
	"License.txt",
	"COPYING",
	"COPYING.txt",
	"COPYING.md",
}

// FindLicenseInModuleCache looks for a license file in the Go module cache
// for the given module and version, reads it, and classifies the license.
// Returns "" if not found or unclassifiable.
func FindLicenseInModuleCache(moduleName, version string) string {
	goModCache := goModCachePath()
	if goModCache == "" {
		return ""
	}

	// Go module cache stores versions with "v" prefix.
	cacheVersion := version
	if !strings.HasPrefix(cacheVersion, "v") {
		cacheVersion = "v" + cacheVersion
	}

	// Go module cache uses case-encoding for uppercase letters (e.g. M → !m).
	encodedPath := goModCaseEncode(moduleName)
	modDir := filepath.Join(goModCache, encodedPath+"@"+cacheVersion)
	if lic := classifyLicenseInDir(modDir); lic != "" {
		return lic
	}

	// Also try without case-encoding (some cache layouts vary).
	modDir = filepath.Join(goModCache, moduleName+"@"+cacheVersion)
	return classifyLicenseInDir(modDir)
}

// FindLicenseInDir searches for a license file in the given directory
// and classifies it. Works for any ecosystem where deps are on the filesystem.
func FindLicenseInDir(dir string) string {
	return classifyLicenseInDir(dir)
}

func classifyLicenseInDir(dir string) string {
	for _, name := range licenseFileNames {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if lic := ClassifyLicenseText(string(data)); lic != "" {
			return lic
		}
	}
	return ""
}

func goModCachePath() string {
	// GOMODCACHE takes precedence, then GOPATH/pkg/mod, then ~/go/pkg/mod.
	if v := os.Getenv("GOMODCACHE"); v != "" {
		return v
	}
	if v := os.Getenv("GOPATH"); v != "" {
		return filepath.Join(v, "pkg", "mod")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "go", "pkg", "mod")
}

// ClassifyLicenseText identifies a license SPDX ID from the full text content.
// Uses keyword matching — not a full license parser, but handles the vast majority
// of standard open-source licenses.
func ClassifyLicenseText(text string) string {
	if len(text) == 0 {
		return ""
	}

	// Normalise for matching.
	upper := strings.ToUpper(text)

	// Check in specificity order (more specific first to avoid false positives).

	// AGPL must be checked before GPL.
	if strings.Contains(upper, "GNU AFFERO GENERAL PUBLIC LICENSE") {
		if strings.Contains(upper, "VERSION 3") {
			return "AGPL-3.0-only"
		}
		return "AGPL-3.0-only"
	}

	// LGPL must be checked before GPL.
	if strings.Contains(upper, "GNU LESSER GENERAL PUBLIC LICENSE") {
		if strings.Contains(upper, "VERSION 3") {
			return "LGPL-3.0-only"
		}
		if strings.Contains(upper, "VERSION 2.1") {
			return "LGPL-2.1-only"
		}
		if strings.Contains(upper, "VERSION 2") {
			return "LGPL-2.0-only"
		}
		return "LGPL-2.1-only"
	}

	// GPL
	if strings.Contains(upper, "GNU GENERAL PUBLIC LICENSE") {
		if strings.Contains(upper, "VERSION 3") {
			return "GPL-3.0-only"
		}
		if strings.Contains(upper, "VERSION 2") {
			return "GPL-2.0-only"
		}
		return "GPL-2.0-only"
	}

	// Apache
	if strings.Contains(upper, "APACHE LICENSE") {
		if strings.Contains(upper, "VERSION 2.0") || strings.Contains(upper, "VERSION 2") {
			return "Apache-2.0"
		}
		if strings.Contains(upper, "VERSION 1.1") {
			return "Apache-1.1"
		}
		return "Apache-2.0"
	}

	// MPL
	if strings.Contains(upper, "MOZILLA PUBLIC LICENSE") {
		if strings.Contains(upper, "VERSION 2.0") || strings.Contains(upper, "VERSION 2") {
			return "MPL-2.0"
		}
		if strings.Contains(upper, "VERSION 1.1") {
			return "MPL-1.1"
		}
		return "MPL-2.0"
	}

	// EPL
	if strings.Contains(upper, "ECLIPSE PUBLIC LICENSE") {
		if strings.Contains(upper, "VERSION 2.0") || strings.Contains(upper, "V 2.0") {
			return "EPL-2.0"
		}
		return "EPL-1.0"
	}

	// ISC — check before MIT since MIT is a substring match.
	if strings.Contains(upper, "ISC LICENSE") ||
		(strings.Contains(upper, "PERMISSION TO USE, COPY, MODIFY, AND/OR DISTRIBUTE") &&
			strings.Contains(upper, "ISC")) {
		return "ISC"
	}

	// BSD — check variants.
	if isBSD(upper) {
		if strings.Count(upper, "REDISTRIBUTION") >= 1 {
			// Count the restriction clauses.
			clauses := 0
			if strings.Contains(upper, "REDISTRIBUTIONS OF SOURCE CODE") {
				clauses++
			}
			if strings.Contains(upper, "REDISTRIBUTIONS IN BINARY FORM") {
				clauses++
			}
			if strings.Contains(upper, "NEITHER THE NAME") || strings.Contains(upper, "THE NAME OF") ||
				strings.Contains(upper, "NAMES OF") || strings.Contains(upper, "NOR THE NAMES") {
				clauses++
			}
			if clauses >= 3 {
				return "BSD-3-Clause"
			}
			return "BSD-2-Clause"
		}
		return "BSD-3-Clause"
	}

	// MIT — very common, broad match.
	if strings.Contains(upper, "MIT LICENSE") ||
		strings.Contains(upper, "PERMISSION IS HEREBY GRANTED, FREE OF CHARGE") {
		return "MIT"
	}

	// Unlicense / public domain.
	if strings.Contains(upper, "THIS IS FREE AND UNENCUMBERED SOFTWARE RELEASED INTO THE PUBLIC DOMAIN") {
		return "Unlicense"
	}

	// CC0
	if strings.Contains(upper, "CC0 1.0 UNIVERSAL") || strings.Contains(upper, "CC0-1.0") {
		return "CC0-1.0"
	}

	// WTFPL
	if strings.Contains(upper, "DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE") {
		return "WTFPL"
	}

	// Boost
	if strings.Contains(upper, "BOOST SOFTWARE LICENSE") {
		return "BSL-1.0"
	}

	// Zlib
	if strings.Contains(upper, "ZLIB LICENSE") ||
		(strings.Contains(upper, "THIS SOFTWARE IS PROVIDED") && strings.Contains(upper, "ALTERED SOURCE VERSIONS")) {
		return "Zlib"
	}

	return ""
}

// goModCaseEncode applies the Go module cache case-encoding.
// Uppercase letters are replaced with '!' followed by the lowercase letter.
// e.g., "github.com/Microsoft/go-winio" → "github.com/!microsoft/go-winio"
func goModCaseEncode(path string) string {
	var b strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isBSD(upper string) bool {
	return strings.Contains(upper, "BSD LICENSE") ||
		strings.Contains(upper, "BSD 2-CLAUSE") ||
		strings.Contains(upper, "BSD 3-CLAUSE") ||
		(strings.Contains(upper, "REDISTRIBUTION AND USE IN SOURCE AND BINARY FORMS") &&
			!strings.Contains(upper, "GNU") &&
			!strings.Contains(upper, "APACHE"))
}
