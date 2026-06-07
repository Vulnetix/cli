package fix

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func Apply(root string, plans []FixCandidate) error {
	for _, p := range plans {
		if p.Skipped || p.TargetVer == "" {
			continue
		}
		switch p.Method {
		case MethodParentUpdate:
			// No manifest edit: a Safe-Harbour child already satisfies the
			// parent's declared range, so the install command re-resolves it.
			continue
		case MethodParentUpgrade:
			// Bump the direct parent's declared range so the lockfile re-resolves
			// the vulnerable child to a safe version.
			if err := applyParentUpgrade(root, p); err != nil {
				return err
			}
			continue
		case MethodOverride:
			// Deterministically pin the vulnerable child via the package
			// manager's override mechanism.
			if err := ApplyOverride(root, p); err != nil {
				return err
			}
			continue
		}
		if err := applyOne(root, p); err != nil {
			return err
		}
	}
	return nil
}

func applyOne(root string, p FixCandidate) error {
	path := filepath.Join(root, p.SourceFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	original := string(data)
	next, changed := editManifest(original, p)
	if !changed {
		return fmt.Errorf("could not locate %s in %s for autofix edit", p.PackageName, p.SourceFile)
	}
	return os.WriteFile(path, []byte(next), 0o644)
}

// applyParentUpgrade rewrites a direct parent dependency's declared range to the
// resolved parent target so the lockfile re-resolves the vulnerable child. If the
// parent cannot be located in the manifest, the install command remains the
// fallback (no error — the report still records the recommendation).
func applyParentUpgrade(root string, p FixCandidate) error {
	if p.ParentName == "" || p.ParentTarget == "" {
		return nil
	}
	path := filepath.Join(root, p.SourceFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	next, changed := replaceScopedJSONDependency(string(data), p.ParentName, p.ParentTarget)
	if !changed {
		return nil
	}
	return os.WriteFile(path, []byte(next), 0o644)
}

func editManifest(content string, p FixCandidate) (string, bool) {
	base := strings.ToLower(filepath.Base(p.SourceFile))
	switch {
	case base == "package.json" || base == "composer.json":
		return replaceScopedJSONDependency(content, p.PackageName, p.TargetVer)
	case base == "go.mod":
		return replaceGoMod(content, p.PackageName, p.TargetVer)
	case base == "requirements.txt" || strings.HasSuffix(base, ".in"):
		return replaceRequirements(content, p.PackageName, p.TargetVer)
	case base == "pyproject.toml":
		return replacePyproject(content, p.PackageName, p.TargetVer)
	case base == "cargo.toml":
		return replaceTomlDependency(content, p.PackageName, p.TargetVer)
	case base == "pom.xml":
		return replacePomXML(content, p.PackageName, p.TargetVer)
	case base == "gemfile":
		return replaceGemfile(content, p.PackageName, p.TargetVer)
	default:
		return content, false
	}
}

// jsonDependencyBlocks are the object keys under which a manifest declares
// dependencies. Scoping edits to these blocks avoids accidentally rewriting an
// unrelated field (overrides/resolutions/engines/scripts or the package's own
// "name") that happens to share the dependency's name.
var jsonDependencyBlocks = []string{
	"dependencies", "devDependencies", "peerDependencies", "optionalDependencies",
	"require", "require-dev",
}

func replaceScopedJSONDependency(content, name, target string) (string, bool) {
	for _, block := range jsonDependencyBlocks {
		start, end, ok := jsonObjectSpan(content, block)
		if !ok {
			continue
		}
		seg := content[start:end]
		next, changed := replaceJSONDependencyRaw(seg, name, target)
		if changed {
			return content[:start] + next + content[end:], true
		}
	}
	return content, false
}

// jsonObjectSpan returns the [start,end) byte range of the object value of the
// given top-level key (start at its opening brace). Dependency blocks contain
// only "name":"range" pairs, so naive brace counting is safe here.
func jsonObjectSpan(content, key string) (int, int, bool) {
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(key) + `"\s*:\s*\{`)
	loc := re.FindStringIndex(content)
	if loc == nil {
		return 0, 0, false
	}
	open := loc[1] - 1
	depth := 0
	for i := open; i < len(content); i++ {
		switch content[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return open, i + 1, true
			}
		}
	}
	return 0, 0, false
}

func replaceJSONDependencyRaw(content, name, target string) (string, bool) {
	re := regexp.MustCompile(`("` + regexp.QuoteMeta(name) + `"\s*:\s*")([^"]+)(")`)
	changed := false
	next := re.ReplaceAllStringFunc(content, func(match string) string {
		if changed {
			return match
		}
		parts := re.FindStringSubmatch(match)
		if len(parts) != 4 {
			return match
		}
		changed = true
		return parts[1] + preserveRangeOperator(parts[2], target) + parts[3]
	})
	return next, changed
}

func replaceGoMod(content, name, target string) (string, bool) {
	re := regexp.MustCompile(`(?m)^(\s*` + regexp.QuoteMeta(name) + `\s+)v?[^\s]+`)
	next, n := replaceFirst(content, re, `${1}v`+target)
	if n > 0 {
		return next, true
	}
	re = regexp.MustCompile(`(?m)^(require\s+` + regexp.QuoteMeta(name) + `\s+)v?[^\s]+`)
	next, n = replaceFirst(content, re, `${1}v`+target)
	return next, n > 0
}

func replaceRequirements(content, name, target string) (string, bool) {
	re := regexp.MustCompile(`(?mi)^(\s*` + regexp.QuoteMeta(name) + `(?:\[[^\]]+\])?\s*(?:==|~=|>=|<=|!=|>|<)\s*)[^\s;]+`)
	next, n := replaceFirst(content, re, `${1}`+target)
	if n > 0 {
		return next, true
	}
	// Bare dependency with no version operator → pin it so the fix is durable.
	bare := regexp.MustCompile(`(?mi)^(\s*` + regexp.QuoteMeta(name) + `(?:\[[^\]]+\])?)\s*$`)
	next, n = replaceFirstFunc(content, bare, func(parts []string) string {
		return parts[1] + "==" + target
	})
	return next, n > 0
}

func replacePyproject(content, name, target string) (string, bool) {
	// Poetry table form: name = "^1.0".
	if next, ok := replaceTomlDependency(content, name, target); ok {
		return next, true
	}
	// PEP 621 array form: "name>=1.0" or "name[extra]" or bare "name".
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(name) + `(\[[^\]]+\])?[^"]*"`)
	next, n := replaceFirstFunc(content, re, func(parts []string) string {
		extras := ""
		if len(parts) > 1 {
			extras = parts[1]
		}
		return `"` + name + extras + "==" + target + `"`
	})
	return next, n > 0
}

func replaceTomlDependency(content, name, target string) (string, bool) {
	re := regexp.MustCompile(`(?m)^(\s*` + regexp.QuoteMeta(name) + `\s*=\s*")([^"]+)(")`)
	next, n := replaceFirstFunc(content, re, func(parts []string) string {
		return parts[1] + preserveRangeOperator(parts[2], target) + parts[3]
	})
	if n > 0 {
		return next, true
	}
	re = regexp.MustCompile(`(?m)^(\s*` + regexp.QuoteMeta(name) + `\s*=\s*\{[^}\n]*version\s*=\s*")([^"]+)(")`)
	next, n = replaceFirstFunc(content, re, func(parts []string) string {
		return parts[1] + preserveRangeOperator(parts[2], target) + parts[3]
	})
	return next, n > 0
}

// replacePomXML rewrites the <version> of the matching <dependency> block. A
// maven package name is groupId:artifactId; a bare artifactId also matches. A
// property-indirected version (<version>${x}</version>) is left untouched
// (best-effort) since editing the property is ambiguous.
func replacePomXML(content, name, target string) (string, bool) {
	group, artifact := splitMaven(name)
	depRe := regexp.MustCompile(`(?s)<dependency>.*?</dependency>`)
	verRe := regexp.MustCompile(`(<version>)[^<$][^<]*(</version>)`)
	changed := false
	next := depRe.ReplaceAllStringFunc(content, func(block string) string {
		if changed {
			return block
		}
		if !strings.Contains(block, "<artifactId>"+artifact+"</artifactId>") {
			return block
		}
		if group != "" && !strings.Contains(block, "<groupId>"+group+"</groupId>") {
			return block
		}
		if !verRe.MatchString(block) {
			return block
		}
		changed = true
		return verRe.ReplaceAllString(block, "${1}"+target+"${2}")
	})
	return next, changed
}

func splitMaven(name string) (group, artifact string) {
	if i := strings.LastIndex(name, ":"); i >= 0 {
		return name[:i], name[i+1:]
	}
	return "", name
}

func replaceGemfile(content, name, target string) (string, bool) {
	re := regexp.MustCompile(`(?m)^(\s*gem\s+['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*['"])([^'"]+)(['"])`)
	next, n := replaceFirstFunc(content, re, func(parts []string) string {
		return parts[1] + preserveRangeOperator(parts[2], target) + parts[3]
	})
	return next, n > 0
}

// ApplyOverride pins the (transitive) package to its safe version via the
// package manager's override mechanism in the nearest package.json:
//
//	npm / bun → "overrides"
//	pnpm      → "pnpm": { "overrides" }
//	yarn      → "resolutions"
//
// No-op (nil) when no package.json is found in the manifest's directory.
func ApplyOverride(root string, p FixCandidate) error {
	if p.PackageName == "" || p.TargetVer == "" {
		return nil
	}
	dir := filepath.Dir(filepath.Join(root, p.SourceFile))
	path := filepath.Join(dir, "package.json")
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	return applyPackageJSONOverrides(path, p.PackageManager, map[string]string{p.PackageName: p.TargetVer})
}

// applyPackageJSONOverrides merges the given name→version pins into package.json
// using the override style for the package manager. Shared by the planned
// override path and the npm peer-conflict install retry.
func applyPackageJSONOverrides(path, pm string, pins map[string]string) error {
	if len(pins) == 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	if !mergeOverrides(doc, pm, pins) {
		return nil
	}
	next, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	next = append(next, '\n')
	return os.WriteFile(path, next, 0o644)
}

func mergeOverrides(doc map[string]any, pm string, pins map[string]string) bool {
	target := overrideContainer(doc, pm)
	changed := false
	for name, ver := range pins {
		if name == "" || ver == "" {
			continue
		}
		if cur, ok := target[name].(string); !ok || cur != ver {
			target[name] = ver
			changed = true
		}
	}
	return changed
}

// overrideContainer returns the map into which override pins are written,
// creating the nesting as needed for the package manager.
func overrideContainer(doc map[string]any, pm string) map[string]any {
	switch strings.ToLower(pm) {
	case "yarn":
		return childObject(doc, "resolutions")
	case "pnpm":
		pnpm := childObject(doc, "pnpm")
		return childObject(pnpm, "overrides")
	default: // npm, bun, unknown
		return childObject(doc, "overrides")
	}
}

func childObject(parent map[string]any, key string) map[string]any {
	if existing, ok := parent[key].(map[string]any); ok {
		return existing
	}
	created := map[string]any{}
	parent[key] = created
	return created
}

func replaceFirst(content string, re *regexp.Regexp, replacement string) (string, int) {
	done := false
	n := 0
	next := re.ReplaceAllStringFunc(content, func(match string) string {
		if done {
			return match
		}
		done = true
		n++
		return re.ReplaceAllString(match, replacement)
	})
	return next, n
}

func replaceFirstFunc(content string, re *regexp.Regexp, fn func(parts []string) string) (string, int) {
	done := false
	n := 0
	next := re.ReplaceAllStringFunc(content, func(match string) string {
		if done {
			return match
		}
		parts := re.FindStringSubmatch(match)
		if len(parts) == 0 {
			return match
		}
		done = true
		n++
		return fn(parts)
	})
	return next, n
}

func preserveRangeOperator(oldSpec, target string) string {
	spec := strings.TrimSpace(oldSpec)
	for _, op := range []string{"^", "~>", "~", ">=", "<=", ">", "<"} {
		if strings.HasPrefix(spec, op) {
			return op + target
		}
	}
	return target
}
