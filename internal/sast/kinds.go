package sast

import "strings"

// Rule kinds. Every embedded rule declares one in its metadata block; a module
// that declares none is treated as sast.
//
// The distribution across the ~1,900 embedded rules is lopsided and that shape
// drives the language server's scheduling: roughly 1,092 secrets, 791 sast, 7
// oci and 7 iac. Secrets rules declare no languages, so the language filter can
// never drop them, and each one iterates every file. Measured on a Go
// repository, evaluating a single file costs 231 ms against all kinds but
// 10.4 ms against sast+iac+oci alone, so the editor's keystroke path runs
// without secrets and picks them up on save. See session_bench_test.go.
const (
	KindSAST    = "sast"
	KindSecrets = "secrets"
	KindOCI     = "oci"
	KindIAC     = "iac"
)

// InteractiveKinds are the kinds cheap enough to evaluate on every keystroke.
var InteractiveKinds = []string{KindSAST, KindIAC, KindOCI}

// AllKinds is every kind the embedded corpus declares.
var AllKinds = []string{KindSAST, KindSecrets, KindOCI, KindIAC}

// ExtractRegoID returns the "id" field from a Rego module's metadata block, or
// "" when none is declared.
//
// A string scan rather than a parse: this runs over every module on every load,
// including the ~1,900 embedded ones, and parsing them twice (once here, once
// in the compiler) would be the more expensive way to learn one field.
func ExtractRegoID(src string) string {
	return regoMetaField(src, `"id"`, "")
}

// ExtractRegoKind returns the "kind" field from a Rego module's metadata block.
// Modules that declare no kind default to sast, which is the historical
// behaviour every rule was written against.
func ExtractRegoKind(src string) string {
	return regoMetaField(src, `"kind"`, KindSAST)
}

// regoMetaField pulls the first quoted string following `key` in src.
func regoMetaField(src, key, fallback string) string {
	i := strings.Index(src, key)
	if i < 0 {
		return fallback
	}
	rest := src[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return fallback
	}
	rest = rest[j+1:]
	k := strings.Index(rest, `"`)
	if k < 0 {
		return fallback
	}
	return rest[:k]
}

// IsRuleModule reports whether src is a rule rather than a shared library.
// Libraries declare no metadata id and produce no findings.
func IsRuleModule(src string) bool { return ExtractRegoID(src) != "" }

// FilterModulesToKinds keeps only the modules whose declared kind is in the
// allowed set. Unlike FilterModulesByKind it does NOT exempt externally
// imported (--rule) packs: a locked specialized subcommand applies its kind
// scope to every rule regardless of origin, so `containers --rule <pack>` never
// bleeds into that pack's secrets or iac rules.
//
// Shared libraries are always retained. OPA compiles every module together, so
// dropping a dependency of a kept rule fails the whole evaluation; libraries
// produce no findings, so a few extra cost nothing.
//
// An empty kinds slice means "no lock" and returns modules unchanged.
func FilterModulesToKinds(modules map[string]string, kinds []string) map[string]string {
	if len(kinds) == 0 {
		return modules
	}
	allowed := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		allowed[k] = true
	}
	filtered := make(map[string]string, len(modules))
	for name, src := range modules {
		if !IsRuleModule(src) || allowed[ExtractRegoKind(src)] {
			filtered[name] = src
		}
	}
	return filtered
}

// FilterModulesByKind removes embedded modules whose kind matches a disabled
// feature. Externally imported rules (anything not under the embedded "rules/"
// prefix) bypass the filter: the user asked for them explicitly.
func FilterModulesByKind(modules map[string]string, noSAST, noSecrets, noContainers, noIAC bool) map[string]string {
	if !noSAST && !noSecrets && !noContainers && !noIAC {
		return modules
	}
	filtered := make(map[string]string, len(modules))
	for name, src := range modules {
		if !strings.HasPrefix(name, "rules/") {
			filtered[name] = src
			continue
		}
		switch ExtractRegoKind(src) {
		case KindSAST:
			if noSAST {
				continue
			}
		case KindSecrets:
			if noSecrets {
				continue
			}
		case KindOCI:
			if noContainers {
				continue
			}
		case KindIAC:
			if noIAC {
				continue
			}
		}
		filtered[name] = src
	}
	return filtered
}

// FilterModulesByID retains only the module whose metadata id matches ruleID,
// case-insensitively. An empty ruleID returns modules unchanged.
func FilterModulesByID(modules map[string]string, ruleID string) map[string]string {
	if ruleID == "" {
		return modules
	}
	target := strings.ToUpper(strings.TrimSpace(ruleID))
	filtered := make(map[string]string, 1)
	for name, src := range modules {
		if strings.ToUpper(ExtractRegoID(src)) == target {
			filtered[name] = src
			break
		}
	}
	return filtered
}

// CountByKind reports how many rule modules declare each kind. Libraries are
// not counted.
func CountByKind(modules map[string]string) map[string]int {
	counts := make(map[string]int, len(AllKinds))
	for _, src := range modules {
		if IsRuleModule(src) {
			counts[ExtractRegoKind(src)]++
		}
	}
	return counts
}
