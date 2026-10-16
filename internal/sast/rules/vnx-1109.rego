# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1109

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1109",
	"name": "Use of Same Variable for Multiple Purposes",
	"description": "A nested loop that reuses the enclosing loop's own control variable, so the inner loop overwrites the counter or element the outer loop is still using. Reported: in Python, a 'for NAME in ...:' statement inside the body of an enclosing 'for' whose targets include NAME (tuple targets included); in C, C++ and Java, an inner 'for (i = ...)' that assigns the outer loop's variable without declaring a new one; in JavaScript/TypeScript, an inner 'for (var i ...)' or 'for (i ...)', since 'var' is function-scoped and is the same variable. Not reported: sibling loops, an inner loop that declares its own variable ('for (int i', 'for (let i'), an outer C-family loop whose body is a single statement on its own line, an inner loop inside a callback function defined in the outer loop (a JavaScript 'function' or arrow, a Python 'def' or 'class'), an inner loop followed within four lines by a return/goto/throw/raise/exit inside the outer body, or within six lines by a 'break' at the inner loop's level (a rollback or reset that abandons the outer loop), Python comprehensions (their own scope), the throwaway name '_', and loops more than 60 lines apart.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1109/",
	"languages": ["python", "javascript", "c", "cpp", "java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1109],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["variable-reuse", "nested-loop", "cwe-1109"],
}

_window := 60

# ── Python ──────────────────────────────────────────────────────────────

_py_ext(path) if endswith(path, ".py")

_py_ext(path) if endswith(path, ".pyw")

_py_for_re := `^([ \t]*)(?:async\s+)?for\s+([A-Za-z_][\w\s,()\[\]]*?)\s+in\s.*:\s*(?:#.*)?$`

_py_names(target) := {n | some n in regex.find_n(`[A-Za-z_]\w*`, target, -1); n != "_"}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_py_code(line) if {
	t := trim_space(line)
	t != ""
	not startswith(t, "#")
}

# a code line between the two loops at or left of the outer loop's indent ends its body
_py_closed(lines, j, i, oi) if {
	some k in helpers.span(j + 1, i - 1)
	k > j
	k < i
	_py_code(lines[k])
	_indent(lines[k]) <= oi
}

# a function or class defined inside the outer loop has its own scope
_py_new_scope(lines, j, i, oi, ii) if {
	some k in helpers.span(j + 1, i - 1)
	k > j
	k < i
	regex.match(`^[ \t]*(?:async\s+)?(?:def|class)\s`, lines[k])
	d := _indent(lines[k])
	d > oi
	d < ii
}

findings contains finding if {
	some path, content in input.file_contents
	_py_ext(path)
	contains(content, "for ")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "for ")
	m := regex.find_all_string_submatch_n(_py_for_re, line, 1)
	count(m) > 0
	ii := count(m[0][1])
	ii > 0
	inner := _py_names(m[0][2])
	count(inner) > 0
	some j in numbers.range(max([0, i - _window]), i - 1)
	j < i
	contains(lines[j], "for ")
	mo := regex.find_all_string_submatch_n(_py_for_re, lines[j], 1)
	count(mo) > 0
	oi := count(mo[0][1])
	oi < ii
	shared := inner & _py_names(mo[0][2])
	count(shared) > 0
	not _py_closed(lines, j, i, oi)
	not _py_new_scope(lines, j, i, oi, ii)
	not _abandons(lines, i, _indent(lines[j]))
	finding := _finding(path, i, line, shared)
}

# ── C, C++, Java, JavaScript ─────────────────────────────────────────────

_c_ext(path) if regex.match(`\.(c|h|cc|cpp|cxx|hpp|hh|java)$`, path)

_js_ext(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)

# inner loop assigning an existing variable: no type before the name
_inner_c_re := `^\s*for\s*\(\s*([A-Za-z_]\w*)\s*=[^=]`

# JavaScript: 'var' re-declares the same function-scoped variable
_inner_js_re := `^\s*for\s*\(\s*(?:var\s+)?([A-Za-z_]\w*)\s*(?:=[^=]|\s(?:in|of)\s)`

_outer_re := `^\s*for\s*\(\s*(?:[\w:<>\*&]+\s+)*?([A-Za-z_]\w*)\s*(?:=[^=]|\s(?:in|of)\s|:[^:])`

_inner_name(path, line) := n if {
	_c_ext(path)
	m := regex.find_all_string_submatch_n(_inner_c_re, line, 1)
	count(m) > 0
	n := m[0][1]
}

_inner_name(path, line) := n if {
	_js_ext(path)
	m := regex.find_all_string_submatch_n(_inner_js_re, line, 1)
	count(m) > 0
	n := m[0][1]
}

_delta(line) := count(indexof_n(line, "{")) - count(indexof_n(line, "}"))

_depth(lines, j, k) := sum([_delta(lines[m]) | some m in numbers.range(j, k)])

_opened(lines, j, k) if {
	some m in numbers.range(j, k)
	contains(lines[m], "{")
}

# the outer loop's block closed somewhere before the inner loop
_c_closed(lines, j, i) if {
	some k in numbers.range(j, i - 1)
	k < i
	_opened(lines, j, k)
	_depth(lines, j, k) <= 0
}

_c_nested(lines, j, i) if {
	_opens_block(lines, j)
	_depth(lines, j, i - 1) > 0
	not _c_closed(lines, j, i)
}

# braceless outer loop whose single statement is the inner loop
_c_nested(lines, j, i) if {
	not contains(lines[j], "{")
	not regex.match(`[;}]\s*$`, lines[j])
	not _code_between(lines, j, i)
}

_code_between(lines, j, i) if {
	some k in helpers.span(j + 1, i - 1)
	k > j
	k < i
	t := trim_space(lines[k])
	t != ""
	not startswith(t, "//")
}

findings contains finding if {
	some path, content in input.file_contents
	_c_or_js(path)
	regex.match(`for\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "for")
	name := _inner_name(path, line)
	some j in numbers.range(max([0, i - _window]), i - 1)
	j < i
	contains(lines[j], "for")
	mo := regex.find_all_string_submatch_n(_outer_re, lines[j], 1)
	count(mo) > 0
	mo[0][1] == name
	_c_nested(lines, j, i)
	not _new_function(lines, j, i)
	not _abandons(lines, i, _indent(lines[j]))
	finding := _finding(path, i, line, {name})
}

_c_or_js(path) if _c_ext(path)

_c_or_js(path) if _js_ext(path)

_finding(path, i, line, names) := {
	"rule_id": metadata.id,
	"message": sprintf("Nested loop reuses the enclosing loop's variable %s; the inner loop overwrites the value the outer loop is iterating with. Use a different name", [concat(", ", sort([n | some n in names]))]),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# the outer loop owns a block: its brace is on the 'for' line or opens the next line
_opens_block(lines, j) if regex.match(`for\s*\(.*\{`, lines[j])

_opens_block(lines, j) if {
	k := j + 1
	k < count(lines)
	startswith(trim_space(lines[k]), "{")
}

# a function or arrow body between the loops is a callback that runs later
_new_function(lines, j, i) if {
	some k in helpers.span(j + 1, i - 1)
	k > j
	k < i
	regex.match(`\bfunction\b|=>`, lines[k])
}

# the inner loop is a rollback on the way out: the outer loop is abandoned
_abandons(lines, i, oi) if {
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 4]))
	k > i
	regex.match(`^\s*(?:return\b|goto\s|throw\b|raise\b|exit\s*\(|abort\s*\(|[}]?\s*return\b)`, lines[k])
	_indent(lines[k]) > oi
}

# a 'break' after the inner loop, in the outer body, leaves the outer loop at once
_abandons(lines, i, oi) if {
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 6]))
	k > i
	regex.match(`^\s*break\s*;?\s*(?:#.*|//.*)?$`, lines[k])
	_indent(lines[k]) > oi
	_indent(lines[k]) <= _indent(lines[i])
}
