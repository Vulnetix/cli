# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1099

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1099",
	"name": "Inconsistent Naming Conventions for Identifiers",
	"description": "One file defines two functions in the same scope (the same indentation with no enclosing block closing between them) whose names differ only in naming convention, one snake_case and one camelCase (validate_token and validateToken, get_user and getUser). Callers cannot tell from the name which one they get, so it is easy to call the unchecked or outdated variant, and a fix applied to one silently misses the other. Reported: the later definition, in Python (def, async def) and JavaScript/TypeScript (function declarations, const/let/var function or arrow assignments, and class or object-literal methods written as name(args) {). Not reported: names that differ only by leading or trailing underscores (_impl beside impl), deliberate compatibility aliases whose body (within ten lines, after a docstring or deprecation warning) calls the other name, functions in different scopes (different indentation, or separate classes at the same indentation), names that differ in more than convention, bundled third-party JavaScript (node_modules, vendor, dist, static libs, minified or library-named files, files over 150 KB), test files and comments. Convention mixing across files, or in variables and classes, is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1099/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1099],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["naming", "maintainability", "cwe-1099"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_py_def_re := `^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`

_js_def_re := `^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\s*\*?\s*([A-Za-z_$][\w$]*)\s*[<(]|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>))`

# Whole-file gates, each led by a literal so the scan skips ahead cheaply.
# (Go's regexp is several times slower on a leading alternation, so each
# keyword is its own pattern.)
_js_has_snake_def(content) if regex.match(`function\s+_*[a-z0-9]+_[a-z]`, content)

_js_has_snake_def(content) if regex.match(`const\s+_*[a-z0-9]+_[a-z]`, content)

_js_has_snake_def(content) if regex.match(`let\s+_*[a-z0-9]+_[a-z]`, content)

_js_has_snake_def(content) if regex.match(`var\s+_*[a-z0-9]+_[a-z]`, content)

# A snake_case method: `get_item(key) {`.
_js_has_snake_def(content) if regex.match(`_[a-z][\w$]*[ \t]*\([^()\n]*\)[ \t]*(?::[^{}\n=]*)?\{[ \t]*\r?\n`, content)

# Cheap anchored prefilter: a line that starts a definition of a snake_case name.
_js_snake_head := `^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:static\s+)?(?:function\s*\*?\s*|(?:const|let|var)\s+)?_*[a-z0-9]+_[a-z0-9_$]*\s*[=(:<]`

# A class or object-literal method: `getUser(id) {`, `static async get_user(id) {`.
_js_method_re := `^\s*(?:(?:static|async|public|private|protected|override|readonly)\s+)*\*?\s*([A-Za-z_$][\w$]*)\s*\([^()]*\)\s*(?::\s*[^={}]+)?\{\s*$`

_js_path(path) ifregex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)

_core(name) := trim(name, "_$")

# snake_case: a lowercase name with an inner underscore; camelCase: an inner
# uppercase letter and no underscore.
_snake(n) if regex.match(`^[a-z0-9]+(_[a-z0-9]+)+$`, n)

_camel(n) if regex.match(`^[a-z][a-z0-9]*([A-Z][a-z0-9]*)+$`, n)

_norm(n) := lower(replace(n, "_", ""))

_name(m) := m[1] if m[1] != ""

_name(m) := m[2] if {
	count(m) > 2
	m[1] == ""
	m[2] != ""
}

# Body of definition k only delegates to `other`: a compatibility alias.
_delegates(lines, k, other) if {
	end := min([count(lines) - 1, k + 10])
	k + 1 <= end
	some j in numbers.range(k + 1, end)
	regex.match(concat("", [`^\s*(?:return\s+)?(?:await\s+)?(?:self\.|this\.|cls\.)?`, other, `\s*\(`]), lines[j])
	_same_body(lines, k, j)
}

# Line j is still inside the body of the definition at k: nothing between
# them is indented at or left of the definition.
_same_body(lines, k, j) if {
	ik := _indent(lines[k])
	not _dedent_between(lines, k, j, ik + 1)
	_indent(lines[j]) > ik
}

# Some code line strictly between a and b is indented less than `lim`.
_dedent_between(lines, a, b, lim) if {
	a + 1 <= b - 1
	some m in helpers.span(a + 1, b - 1)
	trim_space(lines[m]) != ""
	not helpers.is_comment_line(lines[m])
	_indent(lines[m]) < lim
}

_delegates(lines, k, other) if regex.match(concat("", [`=>\s*(?:this\.)?`, other, `\s*\(`]), lines[k])

# Pairs are found through set membership first (a camelCase core whose
# normalised form some snake_case core shares), so the quadratic pairing only
# runs over the few names that collide.
_report(lines, defs, path) := {[i, a, b] |
	snakes := {_norm(c) | some n in defs; c := _core(n); _snake(c)}
	camels := {_norm(c) | some n in defs; c := _core(n); _camel(c)}
	both := snakes & camels
	count(both) > 0
	cand := {k: n | some k, n in defs; _norm(_core(n)) in both}
	some i, a in cand
	some j, b in cand
	j < i
	_indent(lines[i]) == _indent(lines[j])
	not _dedent_between(lines, j, i, _indent(lines[i]))
	ca := _core(a)
	cb := _core(b)
	ca != cb
	_norm(ca) == _norm(cb)
	_mixed(ca, cb)
	not _delegates(lines, i, b)
	not _delegates(lines, j, a)
}

_mixed(a, b) if {
	_snake(a)
	_camel(b)
}

_mixed(a, b) if {
	_camel(a)
	_snake(b)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)^\s*(?:async\s+)?def\s+_*[a-z0-9]+[A-Z]`, content)
	regex.match(`(?m)^\s*(?:async\s+)?def\s+_*[a-z0-9]+_[a-z]`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	defs := {i: m[0][1] |
		some i, l in lines
		contains(l, "def ")
		m := regex.find_all_string_submatch_n(_py_def_re, l, 1)
		count(m) > 0
	}
	some r in _report(lines, defs, path)
	finding := _finding(path, r[0], lines[r[0]], r[1], r[2])
}

findings contains finding if {
	some path, content in input.file_contents
	_js_path(path)
	not endswith(path, ".min.js")
	not regex.match(`(^|/)(node_modules|vendor|dist|build|bower_components|(?:static|public|assets|js)/libs?|plugins|third[_-]?party|external)/|\.bundle\.js$`, path)
	not regex.match(`(?i)(^|/)(jquery|bootstrap|angular|react|vue|lodash|three|ace|d3|moment)[\w.-]*\.js$`, path)
	count(content) < 150000
	_js_has_snake_def(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")

	# snake_case definitions first (only lines holding an underscore), then
	# camelCase definitions only on lines naming one of them case-insensitively.
	snakes := {i: n |
		some i, l in lines
		contains(l, "_")
		regex.match(_js_snake_head, l)
		n := _js_def_name(l)
		_snake(_core(n))
	}
	count(snakes) > 0
	alt := concat("", [`(?i)\b_*(?:`, concat("|", {_norm(_core(n)) | some n in snakes}), `)\b`])
	regex.match(alt, content)
	camels := {i: n |
		some i, l in lines
		regex.match(alt, l)
		n := _js_def_name(l)
		_camel(_core(n))
	}
	count(camels) > 0
	defs := object.union(snakes, camels)
	some r in _report(lines, defs, path)
	finding := _finding(path, r[0], lines[r[0]], r[1], r[2])
}

_finding(path, i, line, a, b) := {
	"rule_id": metadata.id,
	"message": sprintf("'%s' differs from '%s' (defined earlier in this file) only in naming convention; rename or merge them so callers cannot pick the wrong one", [a, b]),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_js_def_name(l) := n if {
	_maybe_js_def(l)
	m := regex.find_all_string_submatch_n(_js_def_re, l, 1)
	count(m) > 0
	n := _name(m[0])
}

_js_def_name(l) := n if {
	not _js_fn_def(l)
	endswith(trim_right(l, " \t\r"), "{")
	m := regex.find_all_string_submatch_n(_js_method_re, l, 1)
	count(m) > 0
	n := m[0][1]
}

_js_fn_def(l) if {
	_maybe_js_def(l)
	regex.match(_js_def_re, l)
}

_maybe_js_def(l) if contains(l, "function")

_maybe_js_def(l) if contains(l, "const ")

_maybe_js_def(l) if contains(l, "let ")

_maybe_js_def(l) if contains(l, "var ")
