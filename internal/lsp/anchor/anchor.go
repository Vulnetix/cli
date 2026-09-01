// Package anchor resolves which line of a dependency manifest declares a given
// package.
//
// This is the piece the SCA path needs and nothing else in the codebase
// provides. parse.ScopedPackage records the manifest a package came from but no
// position within it, and rangefix.Columns only refines columns on a line that
// is already known. Without an anchor a dependency finding has nowhere to go.
//
// Resolution is textual rather than parser-derived on purpose:
//
//   - It works on the editor's unsaved buffer, which is the whole point in a
//     language server. The user is typing a version number when they most want
//     to know it is vulnerable.
//   - Several of the underlying parsers cannot help even in principle.
//     BurntSushi/toml exposes no positions, so Cargo.toml would need this
//     fallback regardless.
//
// The expected anchors are pinned per ecosystem in the extension's fixture at
// test/fixtures/vulnetix-fixture-app/.vulnetix/expected.json ("anchors"), which
// is the acceptance spec for this package.
package anchor

import (
	"regexp"
	"strings"
)

// Confidence describes how the line was derived, so the editor can render an
// approximate anchor as approximate rather than implying a precision it does
// not have.
//
// The vocabulary is deliberately the one the fixture uses. rangefix has its own
// three-value scale for column synthesis; Narrow maps between them so the two
// do not drift apart.
type Confidence string

const (
	// ConfidenceExact means the line declares this package and only this
	// package: a key in a JSON dependency block, a requirements.txt line, a
	// gem call.
	ConfidenceExact Confidence = "exact"
	// ConfidenceToken means the line was found by scanning for a token rather
	// than by structure, or the anchor is the enclosing block rather than the
	// declaration itself — a <dependency> element in a pom, a table-scoped
	// regex hit in a TOML file.
	ConfidenceToken Confidence = "token"
)

// Result is one resolved anchor.
type Result struct {
	// Line is 1-based, matching the fixture and every parser in the tree. LSP
	// positions are 0-based; convert at the protocol boundary, not here.
	Line       int
	Confidence Confidence
	// Snippet is the text to hand rangefix so it can narrow the range to the
	// package name rather than underlining the whole line.
	Snippet string
}

// Find returns the line declaring name in a manifest of the given type.
//
// manifestType uses the same keys as parse.ParseManifest, so a caller that
// parsed a file can pass the same string straight through. Returns false when
// the package cannot be located, which is not an error: a transitive package
// genuinely is not declared in the manifest that pulled it in, and inventing a
// line for it would put a red squiggle on unrelated code.
func Find(text, manifestType, name string) (Result, bool) {
	if text == "" || name == "" {
		return Result{}, false
	}
	lines := strings.Split(text, "\n")

	switch manifestType {
	case "package.json":
		return findJSONDependency(lines, name, npmBlocks)
	case "composer.json":
		return findJSONDependency(lines, name, composerBlocks)
	case "package-lock.json", "npm-shrinkwrap.json":
		return findNPMLock(lines, name)
	case "yarn.lock":
		return findYarnLock(lines, name)
	case "pnpm-lock.yaml":
		return findPnpmLock(lines, name)
	case "requirements.txt", "requirements.in":
		return findRequirements(lines, name)
	case "pyproject.toml", "Pipfile", "pylock.toml":
		return findPyprojectDependency(lines, name)
	case "go.mod":
		return findGoMod(lines, name)
	case "go.sum":
		return findGoSum(lines, name)
	case "Cargo.toml":
		return findCargoToml(lines, name)
	case "Cargo.lock", "poetry.lock", "uv.lock", "Pipfile.lock", "pubspec.lock":
		return findTOMLPackageTable(lines, name)
	case "Gemfile":
		return findGemfile(lines, name)
	case "Gemfile.lock":
		return findGemfileLock(lines, name)
	case "pom.xml":
		return findPomXML(lines, name)
	case "composer.lock":
		return findComposerLock(lines, name)
	case "build.gradle", "build.gradle.kts", "gradle.lockfile":
		return findGradle(lines, name)
	}

	// An ecosystem without a dedicated resolver still gets a usable anchor when
	// the name appears verbatim on a line. Reported as token so the client can
	// render it as approximate.
	return findLiteral(lines, name)
}

// ── JSON manifests ───────────────────────────────────────────────────────────

var npmBlocks = []string{
	"dependencies", "devDependencies", "peerDependencies",
	"optionalDependencies", "bundledDependencies", "resolutions", "overrides",
}

var composerBlocks = []string{"require", "require-dev"}

// findJSONDependency locates a dependency key inside one of the named blocks.
//
// Scoping to the blocks matters rather than being tidy: a package legitimately
// named "version", "name" or "license" would otherwise match the manifest's own
// top-level metadata key and anchor the diagnostic on the wrong line.
func findJSONDependency(lines []string, name string, blocks []string) (Result, bool) {
	keyRe := regexp.MustCompile(`^\s*"` + regexp.QuoteMeta(name) + `"\s*:`)

	for _, block := range blocks {
		start, end, ok := jsonBlockSpan(lines, block)
		if !ok {
			continue
		}
		for i := start; i <= end && i < len(lines); i++ {
			if keyRe.MatchString(lines[i]) {
				return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: `"` + name + `"`}, true
			}
		}
	}
	return Result{}, false
}

// jsonBlockSpan returns the inclusive line span of the object value of a
// top-level key, found by brace counting.
//
// Brace counting rather than json.Unmarshal because the buffer is mid-edit and
// frequently not valid JSON — refusing to anchor while the user is typing is
// the behaviour this whole package exists to avoid. String contents are skipped
// so a brace inside a URL or a version range does not unbalance the count.
func jsonBlockSpan(lines []string, key string) (int, int, bool) {
	openRe := regexp.MustCompile(`^\s*"` + regexp.QuoteMeta(key) + `"\s*:\s*\{`)

	for i, line := range lines {
		if !openRe.MatchString(line) {
			continue
		}
		depth := 0
		for j := i; j < len(lines); j++ {
			depth += braceDelta(lines[j])
			if depth <= 0 && j > i {
				return i, j, true
			}
			if depth <= 0 && j == i && strings.Contains(lines[j], "}") {
				return i, j, true
			}
		}
		return i, len(lines) - 1, true
	}
	return 0, 0, false
}

// braceDelta counts unquoted braces on a line.
func braceDelta(line string) int {
	delta := 0
	inString := false
	escaped := false
	for _, r := range line {
		switch {
		case escaped:
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			inString = !inString
		case inString:
			// Braces inside a string are data, not structure.
		case r == '{':
			delta++
		case r == '}':
			delta--
		}
	}
	return delta
}

// findNPMLock anchors a package in an npm lockfile.
//
// Lockfile v2/v3 key packages by install path ("node_modules/qs"), v1 by bare
// name under "dependencies". Both are tried because a repo can be on either and
// the file gives no cheap version marker at the point of the scan.
func findNPMLock(lines []string, name string) (Result, bool) {
	pathRe := regexp.MustCompile(`^\s*"(?:.*/)?node_modules/` + regexp.QuoteMeta(name) + `"\s*:`)
	for i, line := range lines {
		if pathRe.MatchString(line) {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: name}, true
		}
	}

	bareRe := regexp.MustCompile(`^\s*"` + regexp.QuoteMeta(name) + `"\s*:\s*\{`)
	for i, line := range lines {
		if bareRe.MatchString(line) {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: `"` + name + `"`}, true
		}
	}
	return Result{}, false
}

// findComposerLock anchors on the "name" field of a package object.
func findComposerLock(lines []string, name string) (Result, bool) {
	re := regexp.MustCompile(`^\s*"name"\s*:\s*"` + regexp.QuoteMeta(name) + `"`)
	for i, line := range lines {
		if re.MatchString(line) {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: name}, true
		}
	}
	return Result{}, false
}

// ── JavaScript lockfiles ─────────────────────────────────────────────────────

// findYarnLock anchors on the entry header, which lists one or more descriptors
// such as `lodash@^4.17.0, lodash@^4.17.20:`.
func findYarnLock(lines []string, name string) (Result, bool) {
	quoted := regexp.QuoteMeta(name)
	re := regexp.MustCompile(`(?:^|[\s,"])` + quoted + `@`)
	for i, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, " ") {
			continue
		}
		if re.MatchString(line) {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: name}, true
		}
	}
	return Result{}, false
}

// findPnpmLock anchors on the package key, which pnpm writes as `/name@version`
// in older lockfiles and `name@version` under `packages:` in newer ones.
func findPnpmLock(lines []string, name string) (Result, bool) {
	quoted := regexp.QuoteMeta(name)
	re := regexp.MustCompile(`^\s+'?/?` + quoted + `@`)
	for i, line := range lines {
		if re.MatchString(line) {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: name}, true
		}
	}
	return Result{}, false
}

// ── Python ───────────────────────────────────────────────────────────────────

// findRequirements anchors a PEP 508 requirement line.
//
// PyPI names are compared normalised (PEP 503): case-insensitive with runs of
// -, _ and . equivalent, so a manifest saying PyYAML matches a finding keyed
// pyyaml. Comments and -r includes are skipped.
func findRequirements(lines []string, name string) (Result, bool) {
	want := normalizePyPI(name)
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if declared, ok := requirementName(line); ok && normalizePyPI(declared) == want {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: declared}, true
		}
	}
	return Result{}, false
}

// requirementName extracts the distribution name from a requirement line,
// stopping at the first version specifier, extras bracket, marker or comment.
func requirementName(line string) (string, bool) {
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	end := strings.IndexFunc(line, func(r rune) bool {
		switch r {
		case '=', '<', '>', '!', '~', '[', ';', ' ', '\t', '@', ',':
			return true
		}
		return false
	})
	if end == 0 {
		return "", false
	}
	if end > 0 {
		line = line[:end]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	return line, true
}

// normalizePyPI applies PEP 503 name normalisation.
func normalizePyPI(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	lastDash := false
	for _, r := range lower {
		if r == '-' || r == '_' || r == '.' {
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
			continue
		}
		lastDash = false
		b.WriteRune(r)
	}
	return b.String()
}

// findPyprojectDependency covers both shapes a pyproject uses: PEP 621's
// dependencies array of requirement strings, and Poetry's table of name = spec.
func findPyprojectDependency(lines []string, name string) (Result, bool) {
	want := normalizePyPI(name)

	// Poetry / Pipfile style: a bare key in a dependency table.
	keyRe := regexp.MustCompile(`^\s*["']?([A-Za-z0-9._-]+)["']?\s*=`)
	inDeps := false
	for i, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "[") {
			inDeps = strings.Contains(trimmed, "dependencies") || strings.Contains(trimmed, "packages")
			// A [tool.poetry.dependencies.<name>] header is itself the anchor.
			if inDeps && strings.HasSuffix(trimmed, "."+name+"]") {
				return Result{Line: i + 1, Confidence: ConfidenceToken, Snippet: name}, true
			}
			continue
		}
		if inDeps {
			if m := keyRe.FindStringSubmatch(raw); m != nil && normalizePyPI(m[1]) == want {
				return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: m[1]}, true
			}
		}
	}

	// PEP 621 style: one requirement string per line inside an array.
	for i, raw := range lines {
		trimmed := strings.Trim(strings.TrimSpace(raw), `",'`)
		if trimmed == "" {
			continue
		}
		if declared, ok := requirementName(trimmed); ok && normalizePyPI(declared) == want {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: declared}, true
		}
	}
	return Result{}, false
}

// ── Go ───────────────────────────────────────────────────────────────────────

// findGoMod anchors a module path in a require directive, single-line or block.
//
// The path is matched as a whole token so golang.org/x/text does not also match
// golang.org/x/text/encoding.
func findGoMod(lines []string, name string) (Result, bool) {
	re := regexp.MustCompile(`(?:^|\s)` + regexp.QuoteMeta(name) + `(?:\s+v|\s*=>|\s*$)`)
	for i, raw := range lines {
		line := raw
		if i := strings.Index(line, "//"); i >= 0 {
			// Keep "// indirect" out of the match window but retain the
			// directive itself.
			line = line[:i]
		}
		if re.MatchString(line) {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: name}, true
		}
	}
	return Result{}, false
}

// findGoSum anchors the first checksum line for a module.
func findGoSum(lines []string, name string) (Result, bool) {
	prefix := name + " "
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: name}, true
		}
	}
	return Result{}, false
}

// ── Rust ─────────────────────────────────────────────────────────────────────

// cargoDepTable matches the dependency tables Cargo understands, including the
// target-specific and per-package forms.
var cargoDepTable = regexp.MustCompile(`^\s*\[(?:.*\.)?(?:dependencies|dev-dependencies|build-dependencies)(?:\.([A-Za-z0-9._-]+))?\]`)

// findCargoToml anchors a dependency inside a Cargo dependency table.
//
// Scoped to the table because a bare `name = "..."` also appears under
// [package], where it names the crate being built rather than a dependency.
// The fixture pins this as token confidence: BurntSushi/toml exposes no
// positions, so this regex fallback is the only route.
func findCargoToml(lines []string, name string) (Result, bool) {
	keyRe := regexp.MustCompile(`^\s*["']?` + regexp.QuoteMeta(name) + `["']?\s*=`)
	inTable := false

	for i, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "[") {
			m := cargoDepTable.FindStringSubmatch(trimmed)
			inTable = m != nil
			// [dependencies.<name>] declares the dependency in the header.
			if m != nil && m[1] == name {
				return Result{Line: i + 1, Confidence: ConfidenceToken, Snippet: name}, true
			}
			continue
		}
		if inTable && keyRe.MatchString(raw) {
			return Result{Line: i + 1, Confidence: ConfidenceToken, Snippet: name}, true
		}
	}
	return Result{}, false
}

// findTOMLPackageTable anchors on the name field of a [[package]] array entry,
// the shape Cargo.lock, poetry.lock, uv.lock and friends share.
func findTOMLPackageTable(lines []string, name string) (Result, bool) {
	re := regexp.MustCompile(`^\s*name\s*=\s*["']` + regexp.QuoteMeta(name) + `["']`)
	for i, line := range lines {
		if re.MatchString(line) {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: name}, true
		}
	}
	// Pipfile.lock is JSON despite sharing this slot.
	jsonRe := regexp.MustCompile(`^\s*"` + regexp.QuoteMeta(name) + `"\s*:`)
	for i, line := range lines {
		if jsonRe.MatchString(line) {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: name}, true
		}
	}
	return Result{}, false
}

// ── Ruby ─────────────────────────────────────────────────────────────────────

// findGemfile anchors a gem declaration.
func findGemfile(lines []string, name string) (Result, bool) {
	re := regexp.MustCompile(`^\s*gem\s+["']` + regexp.QuoteMeta(name) + `["']`)
	for i, line := range lines {
		if re.MatchString(line) {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: name}, true
		}
	}
	return Result{}, false
}

// findGemfileLock anchors the spec entry, which is indented under specs:.
func findGemfileLock(lines []string, name string) (Result, bool) {
	re := regexp.MustCompile(`^\s+` + regexp.QuoteMeta(name) + `\s*\(`)
	for i, line := range lines {
		if re.MatchString(line) {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: name}, true
		}
	}
	return Result{}, false
}

// ── Java ─────────────────────────────────────────────────────────────────────

// findPomXML anchors the enclosing <dependency> element rather than the
// <artifactId> line.
//
// That is what the fixture requires, and it is the right target: the version a
// quick fix rewrites is a sibling of the artifactId, so highlighting the
// element keeps the finding and its fix in one visible block.
func findPomXML(lines []string, name string) (Result, bool) {
	group, artifact := splitMaven(name)
	artifactRe := regexp.MustCompile(`<artifactId>\s*` + regexp.QuoteMeta(artifact) + `\s*</artifactId>`)

	for i, line := range lines {
		if !artifactRe.MatchString(line) {
			continue
		}
		open, ok := enclosingDependency(lines, i)
		if !ok {
			continue
		}
		if group != "" && !dependencyHasGroup(lines, open, group) {
			continue
		}
		return Result{Line: open + 1, Confidence: ConfidenceToken, Snippet: "<dependency>"}, true
	}
	return Result{}, false
}

// enclosingDependency walks back from an artifactId line to its <dependency>.
func enclosingDependency(lines []string, from int) (int, bool) {
	for i := from; i >= 0; i-- {
		if strings.Contains(lines[i], "</dependency>") && i != from {
			return 0, false
		}
		if strings.Contains(lines[i], "<dependency>") {
			return i, true
		}
	}
	return 0, false
}

// dependencyHasGroup confirms the groupId inside the element starting at open.
func dependencyHasGroup(lines []string, open int, group string) bool {
	groupRe := regexp.MustCompile(`<groupId>\s*` + regexp.QuoteMeta(group) + `\s*</groupId>`)
	for i := open; i < len(lines); i++ {
		if groupRe.MatchString(lines[i]) {
			return true
		}
		if strings.Contains(lines[i], "</dependency>") {
			return false
		}
	}
	return false
}

// splitMaven splits a group:artifact coordinate, matching internal/fix.
func splitMaven(name string) (group, artifact string) {
	if i := strings.LastIndex(name, ":"); i >= 0 {
		return name[:i], name[i+1:]
	}
	return "", name
}

// findGradle anchors a Gradle dependency declaration, which may use the compact
// "group:artifact:version" string or the map form.
func findGradle(lines []string, name string) (Result, bool) {
	group, artifact := splitMaven(name)
	compact := regexp.MustCompile(`["']` + regexp.QuoteMeta(name) + `[:"']`)
	mapForm := regexp.MustCompile(`name\s*[:=]\s*["']` + regexp.QuoteMeta(artifact) + `["']`)

	for i, line := range lines {
		if compact.MatchString(line) {
			return Result{Line: i + 1, Confidence: ConfidenceExact, Snippet: name}, true
		}
		if mapForm.MatchString(line) && (group == "" || strings.Contains(line, group)) {
			return Result{Line: i + 1, Confidence: ConfidenceToken, Snippet: artifact}, true
		}
	}
	return Result{}, false
}

// ── Fallback ─────────────────────────────────────────────────────────────────

// findLiteral is the last resort for an ecosystem without a resolver: the first
// line carrying the name as a delimited token.
//
// Delimited rather than a substring search, so "time" does not match "runtime".
func findLiteral(lines []string, name string) (Result, bool) {
	re := regexp.MustCompile(`(?:^|[^A-Za-z0-9._/-])` + regexp.QuoteMeta(name) + `(?:[^A-Za-z0-9._/-]|$)`)
	for i, line := range lines {
		if re.MatchString(line) {
			return Result{Line: i + 1, Confidence: ConfidenceToken, Snippet: name}, true
		}
	}
	return Result{}, false
}
