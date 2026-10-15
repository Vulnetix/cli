# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_229

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-229",
	"name": "Improper Handling of Values",
	"description": "A request value is converted to a number with no handling of a missing or malformed value. Python: int() or float() applied to a Flask/Django/DRF request value (request.args, form, values, GET, POST, json, get_json(), data, cookies, headers, query_params), inline or through a variable assigned from one in the eight lines above, outside any try block or with contextlib.suppress(...) block, so a missing or non-numeric value raises an unhandled TypeError/ValueError (a 500, and for float() the strings 'nan' and 'inf' are accepted as values). Node.js/TypeScript: parseInt(), parseFloat() or Number() of req.query or req.body (inline, through an assigned or destructured variable) whose NaN result is neither defaulted on the same line (|| or ??) nor tested with isNaN/Number.isNaN/isFinite/Number.isInteger in the next six lines. Not reported: Flask's get(..., type=int), a conversion inside try, a value guarded by isdigit()/isnumeric()/isdecimal() or a regex match just above, route parameters (req.params, which the route pattern constrains), constants and environment values, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-229/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [229],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["improper-handling-of-values", "cwe-229", "input-validation"],
}

_py_source := `\brequest\.(?:args|form|values|GET|POST|json|get_json|data|cookies|headers|query_params)\b`

_py_inline := `\b(?:int|float)\(\s*request\.(?:args|form|values|GET|POST|json|get_json|data|cookies|headers|query_params)\b`

_js_source := `\breq\.(?:query|body)\b`

_js_inline := `\b(?:parseInt|parseFloat|Number)\(\s*req\.(?:query|body)\b`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_blank_or_comment(line) if trim_space(line) == ""

_blank_or_comment(line) if helpers.is_comment_line(line)

# Line i sits inside a `try:` block opened in the 40 lines above.
_in_try(lines, i) if {
	ii := _indent(lines[i])
	some j in numbers.range(max([0, i - 40]), i - 1)
	j < i
	regex.match(`^\s*(?:try\s*:|with\s+(?:contextlib\.)?suppress\()`, lines[j])
	ij := _indent(lines[j])
	ij < ii
	not _dedented_between(lines, j, i, ij)
}

_dedented_between(lines, j, i, ij) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	not _blank_or_comment(lines[k])
	_indent(lines[k]) <= ij
}

_py_guarded(lines, i) if {
	w := helpers.code_window(lines, i, 6, 0)
	regex.match(`\.(?:isdigit|isnumeric|isdecimal)\(\)|\bre\.(?:fullmatch|match)\(`, w)
}

_py_hit(lines, i, line) if regex.match(_py_inline, line)

_py_hit(lines, i, line) if {
	some v in helpers.tainted_names(lines, i, 8, _py_source)
	regex.match(concat("", [`\b(?:int|float)\(\s*`, v, `\b`]), line)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "request.")
	regex.match(`\b(?:int|float)\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\b(?:int|float)\(\s*\w`, line)
	not helpers.is_comment_line(line)
	not regex.match(`^[^#]*["'][^"']*\b(?:int|float)\([^"']*["']`, line)
	_py_hit(lines, i, line)
	not _in_try(lines, i)
	not _py_guarded(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "A request value is converted with int()/float() outside a try block: a missing or malformed value raises an unhandled error. Use get(..., type=int), or catch ValueError/TypeError and return 400",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_js_ext(path) if regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx)$`, path)

# Names destructured from req.query / req.body above line i.
_js_destructured(lines, i) := {trim_space(n) |
	some j in numbers.range(max([0, i - 8]), i - 1)
	j < i
	m := regex.find_all_string_submatch_n(`\{([^}]*)\}\s*=\s*req\.(?:query|body)\b`, lines[j], 1)
	count(m) == 1
	some part in split(m[0][1], ",")
	n := regex.replace(part, `[:=].*$`, "")
	trim_space(n) != ""
}

_js_names(lines, i) := helpers.tainted_names(lines, i, 8, _js_source) | _js_destructured(lines, i)

_js_hit(lines, i, line) if regex.match(_js_inline, line)

_js_hit(lines, i, line) if {
	some v in _js_names(lines, i)
	regex.match(concat("", [`\b(?:parseInt|parseFloat|Number)\(\s*`, v, `\b`]), line)
}

_nan_check := `(?:\bisNaN|Number\.isNaN|\bisFinite|Number\.isFinite|Number\.isInteger|Number\.isSafeInteger)\(\s*`

_js_handled(_, _, line) if regex.match(`\|\||\?\?`, line)

_js_handled(_, _, line) if regex.match(_nan_check, line)

_js_handled(lines, i, line) if {
	v := helpers.assigned_first(line)
	w := helpers.code_window(lines, i, 0, 12)
	regex.match(concat("", [_nan_check, `!?\s*`, v, `\b`]), w)
}

# Line i sits inside a /* ... */ block opened in the 30 lines above (code
# commented out wholesale, such as a disabled alternative implementation).
_in_block_comment(lines, i) if {
	some j in numbers.range(max([0, i - 30]), i - 1)
	j < i
	regex.match(`/\*(?:[^*]|\*[^/])*$`, lines[j])
	not _closed_after(lines, j, i)
}

_closed_after(lines, j, i) if {
	some k in numbers.range(j + 1, i)
	k > j
	contains(lines[k], "*/")
}

findings contains finding if {
	some path, content in input.file_contents
	_js_ext(path)
	regex.match(`\breq\.(?:query|body)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\b(?:parseInt|parseFloat|Number)\(`, line)
	not helpers.is_comment_line(line)
	_js_hit(lines, i, line)
	not _in_block_comment(lines, i)
	not _js_handled(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "A request value is converted with parseInt/parseFloat/Number and its NaN result is never handled. Default it (|| fallback) or reject the request when Number.isNaN() is true",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
