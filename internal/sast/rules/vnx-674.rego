# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_674

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-674",
	"name": "Unconditional self-recursion or a disabled recursion guard",
	"description": "Recursion that nothing bounds. Reported: (1) a method, property or accessor whose first statement calls itself with the same arguments, so every call recurses until the stack is exhausted: a Python @property/@cached_property returning self.<same name>, an @<name>.setter assigning self.<same name>, a method returning self.<same name>(<same parameters>); a JavaScript/TypeScript getter returning this.<same name>, a setter assigning this.<same name>, a method returning this.<same name>(<same parameters>); a Java method whose first statement is <same name>(<same parameters>) or this.<same name>(...), with or without return, also a one-line method `{ return getX(); }` (the classic getter that forgot the field); (2) Python sys.setrecursionlimit() raised to 50000 or more (also written 1_000_000, 10**5+, 2**16+, int(1e5), sys.maxsize), which removes the interpreter's guard so attacker-shaped deep input (nested JSON, GraphQL queries, XML) crashes the process with a C stack overflow instead of a RecursionError. Not reported: accessors backed by another field (self._name, this._name), delegation to another receiver or to super, overloads called with different or converted arguments, recursion with a base case or a depth check, smaller recursion limits, comments and string literals. General recursion over untrusted nested data without a depth limit is not decided line by line and is not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-674/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [674],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["uncontrolled-recursion", "cwe-674"],
}

_js_exts := [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	some ext in _js_exts
	endswith(path, ext)
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_nows(s) := regex.replace(s, `\s+`, "")

# Parameter names, in order, from a parameter list.
_param(lang, p) := n if {
	lang in {"py", "js"}
	n := trim(trim_space(split(split(p, "=")[0], ":")[0]), "*.?")
}

_param("java", p) := n if {
	toks := split(trim_space(regex.replace(p, `@\w+(?:\([^)]*\))?`, "")), " ")
	n := trim(toks[count(toks) - 1], ".[]")
}

_params(_, s) := "" if trim_space(s) == ""

_params(lang, s) := concat(",", [n | some p in split(s, ","); n := _param(lang, p); n != "self"]) if trim_space(s) != ""

_finding(path, j, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": j + 1,
	"snippet": line,
}

_msg := "This calls itself unconditionally with the same arguments: every call recurses until the stack overflows. Use the backing field (e.g. self._x / this._x / this.x) or add a base case"

# ── Python ────────────────────────────────────────────────────────────────

_py_def := `^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(\s*self\s*(?:,(.*))?\)\s*(?:->\s*[^:]+)?:\s*$`

_decorated(lines, i, re) if {
	some k in numbers.range(max([0, i - 3]), i - 1)
	regex.match(re, lines[k])
}

_py_recurses(lines, i, name, _, body) if {
	_decorated(lines, i, `^\s*@(?:property|(?:functools\.)?cached_property)\s*$`)
	regex.match(concat("", [`^\s*return\s+self\.`, name, `(?:$|[^\w(])`]), body)
}

_py_recurses(lines, i, name, _, body) if {
	_decorated(lines, i, concat("", [`^\s*@`, name, `\.setter\s*$`]))
	regex.match(concat("", [`^\s*self\.`, name, `\s*=[^=]`]), body)
}

_py_recurses(_, _, name, params, body) if {
	m := regex.find_all_string_submatch_n(concat("", [`^\s*return\s+(?:await\s+)?self\.`, name, `\((.*)\)\s*$`]), body, 1)
	_nows(m[0][1]) == _params("py", params)
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "py"
	contains(content, "def ")
	contains(content, "self.")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "def ")
	m := regex.find_all_string_submatch_n(_py_def, line, 1)
	name := m[0][2]
	params := m[0][3]
	j := helpers.next_code_index(lines, i, 3)
	_indent(lines[j]) > _indent(line)
	_py_recurses(lines, i, name, params, lines[j])
	finding := _finding(path, j, lines[j], _msg)
}

# sys.setrecursionlimit raised past any sane depth.
_huge(v) if {
	regex.match(`^\d+$`, v)
	to_number(v) >= 50000
}

_huge(v) if {
	m := regex.find_all_string_submatch_n(`^10\*\*(\d+)$`, v, 1)
	to_number(m[0][1]) >= 5
}

_huge(v) if {
	m := regex.find_all_string_submatch_n(`^2\*\*(\d+)$`, v, 1)
	to_number(m[0][1]) >= 16
}

_huge(v) if {
	m := regex.find_all_string_submatch_n(`^int\((\d+(?:\.\d+)?)e(\d+)\)$`, v, 1)
	to_number(m[0][2]) >= 5
}

_huge(v) if v in {"sys.maxsize", "math.inf", "float('inf')", `float("inf")`}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "py"
	contains(content, "setrecursionlimit")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "setrecursionlimit")
	m := regex.find_all_string_submatch_n(`^\s*(sys\.)?setrecursionlimit\(\s*(.+?)\s*\)\s*(?:#.*)?$`, line, 1)
	_qualified(m[0][1], content)
	_huge(replace(_nows(m[0][2]), "_", ""))
	finding := _finding(path, i, line, "sys.setrecursionlimit() is raised so far that deeply nested input overflows the C stack and kills the process instead of raising RecursionError; keep the default and bound recursion depth explicitly")
}

_qualified("sys.", _)

_qualified("", content) if regex.match(`(?m)^\s*from\s+sys\s+import\s+.*\bsetrecursionlimit\b`, content)

# ── JavaScript / TypeScript ───────────────────────────────────────────────

_js_head := `^\s*(?:(?:public|private|protected|static|async|override|readonly)\s+)*`

_js_reserved := {"if", "for", "while", "switch", "catch", "function", "constructor", "return", "super", "with"}

# The body: the rest of the header line after `{`, else the next code line.
_js_body(lines, i, rest) := rest if trim_space(rest) != ""

_js_body(lines, i, rest) := lines[j] if {
	trim_space(rest) == ""
	j := helpers.next_code_index(lines, i, 3)
}

_js_line(lines, i, rest) := i if trim_space(rest) != ""

_js_line(lines, i, rest) := helpers.next_code_index(lines, i, 3) if trim_space(rest) == ""

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "js"
	contains(content, "this.")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "{")
	_js_hit(lines, i, line)
	k := _js_line(lines, i, _js_rest(line))
	finding := _finding(path, k, lines[k], _msg)
}

_js_rest(line) := r if {
	m := regex.find_all_string_submatch_n(`\{(.*)$`, line, 1)
	r := m[0][1]
}

_js_hit(lines, i, line) if {
	m := regex.find_all_string_submatch_n(concat("", [_js_head, `get\s+([A-Za-z_$][\w$]*)\s*\(\s*\)\s*(?::\s*[^{]+)?\{(.*)$`]), line, 1)
	body := _js_body(lines, i, m[0][2])
	regex.match(concat("", [`^\s*return\s+this\.`, m[0][1], `(?:\s*;|\s*\}|\s*$|\.)`]), body)
}

_js_hit(lines, i, line) if {
	m := regex.find_all_string_submatch_n(concat("", [_js_head, `set\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)[^)]*\)\s*\{(.*)$`]), line, 1)
	body := _js_body(lines, i, m[0][3])
	regex.match(concat("", [`^\s*this\.`, m[0][1], `\s*=[^=]`]), body)
}

_js_hit(lines, i, line) if {
	m := regex.find_all_string_submatch_n(concat("", [_js_head, `([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*(?::\s*[^{=]+)?\{(.*)$`]), line, 1)
	name := m[0][1]
	not name in _js_reserved
	not name in {"get", "set"}
	body := _js_body(lines, i, m[0][3])
	c := regex.find_all_string_submatch_n(concat("", [`^\s*return\s+(?:await\s+)?this\.`, name, `\(([^()]*)\)\s*;?\s*\}?\s*$`]), body, 1)
	_nows(c[0][1]) == _params("js", m[0][2])
}

# ── Java ──────────────────────────────────────────────────────────────────

_java_def := `^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|default)\s+)*(?:<[^>]*>\s+)?[\w<>\[\],.?]+\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)\s*(?:throws\s+[\w.,\s]+)?\{\s*$`

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "java"
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "{")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_java_def, line, 1)
	name := m[0][1]
	not name in {"if", "for", "while", "switch", "catch", "synchronized", "return", "new", "else"}
	not regex.match(`^\s*(?:return|new|else)\b`, line)
	j := helpers.next_code_index(lines, i, 3)
	c := regex.find_all_string_submatch_n(concat("", [`^\s*(?:return\s+)?(?:this\.)?`, name, `\(([^()]*)\)\s*;\s*$`]), lines[j], 1)
	_nows(c[0][1]) == _params("java", m[0][2])
	finding := _finding(path, j, lines[j], _msg)
}

# A one-line method: `public String getName() { return getName(); }`.
_java_inline := `^\s*(?:(?:public|private|protected|static|final|synchronized|default)\s+)*(?:<[^>]*>\s+)?[\w<>\[\],.?]+\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)\s*(?:throws\s+[\w.,\s]+)?\{\s*(?:return\s+)?(?:this\.)?([a-zA-Z_]\w*)\(([^()]*)\)\s*;\s*\}\s*$`

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "java"
	regex.match(`(?m)\{\s*(?:return\s+)?(?:this\.)?\w+\([^()]*\)\s*;\s*\}\s*$`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "}")
	m := regex.find_all_string_submatch_n(_java_inline, line, 1)
	m[0][1] == m[0][3]
	not m[0][1] in {"if", "for", "while", "switch", "catch", "synchronized", "return", "new", "else"}
	not regex.match(`^\s*(?:return|new|else)\b`, line)
	_nows(m[0][4]) == _params("java", m[0][2])
	finding := _finding(path, i, line, _msg)
}
