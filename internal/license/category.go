package license

import "strings"

// ClassifyCategory returns the license category for a given SPDX ID.
func ClassifyCategory(spdxID string) Category {
	if cat, ok := categoryMap[spdxID]; ok {
		return cat
	}
	// Heuristic fallback based on ID patterns.
	upper := strings.ToUpper(spdxID)
	switch {
	case strings.Contains(upper, "GPL") && !strings.Contains(upper, "LGPL"):
		return CategoryStrongCopyleft
	case strings.Contains(upper, "LGPL"):
		return CategoryWeakCopyleft
	case strings.Contains(upper, "MPL"):
		return CategoryWeakCopyleft
	case strings.Contains(upper, "CPAL"):
		return CategoryWeakCopyleft
	case strings.Contains(upper, "EUPL"):
		return CategoryStrongCopyleft
	case strings.Contains(upper, "AGPL"):
		return CategoryStrongCopyleft
	case strings.Contains(upper, "SSPL"):
		return CategoryProprietary
	case strings.Contains(upper, "BSL"):
		return CategoryProprietary
	case strings.Contains(upper, "CC0") || strings.Contains(upper, "UNLICENSE") || upper == "0BSD":
		return CategoryPublicDomain
	}
	return CategoryUnknown
}

// categoryMap maps common SPDX IDs to their categories.
var categoryMap = map[string]Category{
	// ── Public domain ─────────────────────────────────────────────────
	"CC0-1.0":       CategoryPublicDomain,
	"Unlicense":     CategoryPublicDomain,
	"0BSD":          CategoryPublicDomain,
	"WTFPL":         CategoryPublicDomain,
	"SAX-PD":        CategoryPublicDomain,
	"CC-PDDC":       CategoryPublicDomain,
	"PDDL-1.0":     CategoryPublicDomain,

	// ── Permissive ────────────────────────────────────────────────────
	"MIT":                   CategoryPermissive,
	"MIT-0":                 CategoryPermissive,
	"Apache-2.0":            CategoryPermissive,
	"Apache-1.1":            CategoryPermissive,
	"Apache-1.0":            CategoryPermissive,
	"BSD-2-Clause":          CategoryPermissive,
	"BSD-3-Clause":          CategoryPermissive,
	"BSD-3-Clause-Clear":    CategoryPermissive,
	"BSD-3-Clause-LBNL":     CategoryPermissive,
	"ISC":                   CategoryPermissive,
	"Zlib":                  CategoryPermissive,
	"X11":                   CategoryPermissive,
	"Artistic-2.0":          CategoryPermissive,
	"BSL-1.0":               CategoryPermissive, // Boost Software License, not Business Source License
	"curl":                  CategoryPermissive,
	"ECL-2.0":               CategoryPermissive,
	"EFL-2.0":               CategoryPermissive,
	"FTL":                   CategoryPermissive,
	"JSON":                  CategoryPermissive,
	"Libpng":                CategoryPermissive,
	"libpng-2.0":            CategoryPermissive,
	"MulanPSL-2.0":          CategoryPermissive,
	"NCSA":                  CategoryPermissive,
	"OpenSSL":               CategoryPermissive,
	"PHP-3.01":              CategoryPermissive,
	"PHP-3.0":               CategoryPermissive,
	"PostgreSQL":            CategoryPermissive,
	"PSF-2.0":               CategoryPermissive,
	"Python-2.0":            CategoryPermissive,
	"Python-2.0.1":          CategoryPermissive,
	"Ruby":                  CategoryPermissive,
	"Unicode-DFS-2016":      CategoryPermissive,
	"Unicode-3.0":           CategoryPermissive,
	"UPL-1.0":               CategoryPermissive,
	"W3C":                   CategoryPermissive,
	"W3C-20150513":          CategoryPermissive,
	"Xnet":                  CategoryPermissive,
	"Zend-2.0": CategoryPermissive,
	"BlueOak-1.0.0":         CategoryPermissive,
	"HPND":                  CategoryPermissive,
	"MIT-Modern-Variant":    CategoryPermissive,
	"Mulan-PSL-2.0":         CategoryPermissive,
	"NAIST-2003":            CategoryPermissive,
	"NTP":                   CategoryPermissive,
	"OFL-1.1":               CategoryPermissive,
	"OFL-1.0":               CategoryPermissive,
	"SHL-0.51":              CategoryPermissive,
	"SSH-OpenSSH":           CategoryPermissive,
	"TOML":                  CategoryPermissive,
	"Vim":                   CategoryPermissive,
	"XFree86-1.1":           CategoryPermissive,
	"Beerware":              CategoryPermissive,
	"Fair":                  CategoryPermissive,
	"FSFAP":                 CategoryPermissive,
	"ICU":                   CategoryPermissive,
	"IJG":                   CategoryPermissive,
	"Info-ZIP":              CategoryPermissive,
	"LAL-1.3":               CategoryPermissive,
	"Latex2e":               CategoryPermissive,
	"MIT-advertising":       CategoryPermissive,
	"MIT-enna":              CategoryPermissive,
	"MIT-feh":               CategoryPermissive,
	"OLDAP-2.8":             CategoryPermissive,
	"blessing":              CategoryPermissive,
	"DWTFYWT":               CategoryPermissive,
	"ANTLR-PD-fallback":     CategoryPermissive,

	// ── Weak copyleft ─────────────────────────────────────────────────
	"LGPL-2.0-only":    CategoryWeakCopyleft,
	"LGPL-2.0-or-later": CategoryWeakCopyleft,
	"LGPL-2.1-only":    CategoryWeakCopyleft,
	"LGPL-2.1-or-later": CategoryWeakCopyleft,
	"LGPL-3.0-only":    CategoryWeakCopyleft,
	"LGPL-3.0-or-later": CategoryWeakCopyleft,
	"MPL-1.0":          CategoryWeakCopyleft,
	"MPL-1.1":          CategoryWeakCopyleft,
	"MPL-2.0":          CategoryWeakCopyleft,
	"MPL-2.0-no-copyleft-exception": CategoryWeakCopyleft,
	"CDDL-1.0":         CategoryWeakCopyleft,
	"CDDL-1.1":         CategoryWeakCopyleft,
	"CPL-1.0":          CategoryWeakCopyleft,
	"EPL-1.0":          CategoryWeakCopyleft,
	"EPL-2.0":          CategoryWeakCopyleft,
	"IPL-1.0":          CategoryWeakCopyleft,
	"OSL-3.0":          CategoryWeakCopyleft,
	"OSL-2.1":          CategoryWeakCopyleft,
	"OSL-2.0":          CategoryWeakCopyleft,
	"OSL-1.0":          CategoryWeakCopyleft,
	"CECILL-2.1":       CategoryWeakCopyleft,
	"CPAL-1.0":         CategoryWeakCopyleft,
	"CUA-OPL-1.0":      CategoryWeakCopyleft,
	"EUDatagrid":       CategoryWeakCopyleft,
	"MS-RL":            CategoryWeakCopyleft,
	"Nokia":            CategoryWeakCopyleft,
	"RPSL-1.0":         CategoryWeakCopyleft,
	"RSCPL":            CategoryWeakCopyleft,
	"SimPL-2.0":        CategoryWeakCopyleft,
	"Watcom-1.0":       CategoryWeakCopyleft,

	// ── Strong copyleft ───────────────────────────────────────────────
	"GPL-2.0-only":     CategoryStrongCopyleft,
	"GPL-2.0-or-later": CategoryStrongCopyleft,
	"GPL-3.0-only":     CategoryStrongCopyleft,
	"GPL-3.0-or-later": CategoryStrongCopyleft,
	"AGPL-1.0-only":    CategoryStrongCopyleft,
	"AGPL-1.0-or-later": CategoryStrongCopyleft,
	"AGPL-3.0-only":    CategoryStrongCopyleft,
	"AGPL-3.0-or-later": CategoryStrongCopyleft,
	"EUPL-1.1":         CategoryStrongCopyleft,
	"EUPL-1.2":         CategoryStrongCopyleft,
	"CECILL-2.0":       CategoryStrongCopyleft,
	"QPL-1.0":          CategoryStrongCopyleft,
	"Sleepycat":        CategoryStrongCopyleft,
	"MS-PL":            CategoryStrongCopyleft,
	"SSPL-1.0":         CategoryStrongCopyleft,

	// ── Proprietary / non-free ────────────────────────────────────────
	"BUSL-1.1": CategoryProprietary,
	"Parity-7.0.0": CategoryProprietary,
	"PolyForm-Noncommercial-1.0.0": CategoryProprietary,
	"PolyForm-Small-Business-1.0.0": CategoryProprietary,

	// ── Creative Commons (non-software, but common in data deps) ─────
	"CC-BY-4.0":       CategoryPermissive,
	"CC-BY-3.0":       CategoryPermissive,
	"CC-BY-SA-4.0":    CategoryWeakCopyleft,
	"CC-BY-SA-3.0":    CategoryWeakCopyleft,
	"CC-BY-NC-4.0":    CategoryProprietary,
	"CC-BY-NC-SA-4.0": CategoryProprietary,
	"CC-BY-ND-4.0":    CategoryProprietary,
	"CC-BY-NC-ND-4.0": CategoryProprietary,
}

// ConflictSeverity describes a conflict rule result.
type ConflictSeverity struct {
	Severity       string
	Description    string
	Recommendation string
}

// CategoryConflict checks if two license categories conflict and returns severity info.
// Returns nil if the combination is compatible.
func CategoryConflict(cat1, cat2 Category) *ConflictSeverity {
	// Normalise order so we don't need both permutations.
	a, b := cat1, cat2
	if a > b {
		a, b = b, a
	}
	key := [2]Category{a, b}
	if cs, ok := categoryConflicts[key]; ok {
		return &cs
	}
	return nil
}

// IDConflict checks for specific SPDX ID pair overrides.
// Returns nil if no specific rule exists.
func IDConflict(id1, id2 string) *ConflictSeverity {
	a, b := id1, id2
	if a > b {
		a, b = b, a
	}
	key := [2]string{a, b}
	if cs, ok := idConflicts[key]; ok {
		return &cs
	}
	return nil
}

// categoryConflicts defines incompatibilities between category pairs.
// Keys are sorted alphabetically.
var categoryConflicts = map[[2]Category]ConflictSeverity{
	{CategoryProprietary, CategoryStrongCopyleft}: {
		Severity:       "critical",
		Description:    "Strong copyleft license is incompatible with proprietary licensing",
		Recommendation: "Replace the proprietary component or the copyleft-licensed dependency",
	},
	{CategoryProprietary, CategoryWeakCopyleft}: {
		Severity:       "high",
		Description:    "Weak copyleft license may conflict with proprietary licensing depending on linking",
		Recommendation: "Verify that the weak-copyleft component is used as a separate library, not modified",
	},
	{CategoryProprietary, CategoryPublicDomain}: {}, // compatible — no entry needed
	// Strong copyleft mixed with different strong copyleft families is handled by ID overrides.
}

// idConflicts defines specific SPDX ID pair incompatibilities.
// Keys are sorted alphabetically.
var idConflicts = map[[2]string]ConflictSeverity{
	{"Apache-2.0", "GPL-2.0-only"}: {
		Severity:       "high",
		Description:    "Apache-2.0 contains patent retaliation clauses incompatible with GPL-2.0",
		Recommendation: "Upgrade to GPL-3.0 which is compatible with Apache-2.0, or replace one dependency",
	},
	{"Apache-2.0", "GPL-2.0-or-later"}: {
		Severity:       "medium",
		Description:    "Apache-2.0 is incompatible with GPL-2.0 but compatible with GPL-3.0; the 'or-later' clause may resolve this if GPL-3.0 is chosen",
		Recommendation: "Ensure the GPL-2.0-or-later dependency is used under GPL-3.0 terms",
	},
	{"AGPL-3.0-only", "GPL-2.0-only"}: {
		Severity:       "high",
		Description:    "AGPL-3.0 and GPL-2.0-only are not compatible",
		Recommendation: "Replace one dependency or check if GPL-2.0-or-later is available",
	},
	{"GPL-2.0-only", "GPL-3.0-only"}: {
		Severity:       "high",
		Description:    "GPL-2.0-only and GPL-3.0-only are not cross-compatible",
		Recommendation: "Check if either dependency offers an 'or-later' variant",
	},
}
