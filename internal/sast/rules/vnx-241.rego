# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_241

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-241",
	"name": "Improper Handling of Unexpected Data Type",
	"description": "A value of a JSON request body, whose type the client chooses, is used as a str with no type check: a number, list, object or null there raises AttributeError (a crash or a 500) instead of being rejected. Reported in Python: a str method (lower/upper/strip/lstrip/rstrip/split/rsplit/startswith/endswith/replace/encode/casefold/title/capitalize) applied to a field of a JSON body (Flask request.json and request.get_json(), DRF request.data, json.loads(request.body/data/get_data())), directly, through the dict assigned from it in the 15 lines above, or through a variable assigned from one of its fields in the 10 lines above. Not reported: Flask request.args/form/headers (always strings), a value checked with isinstance()/type() or coerced with str() in the ten lines above, comments and string literals. The same weakness in JavaScript/TypeScript (a string method or .length on a req.query/req.body/ctx.query field) is reported by VNX-1287.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-241/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [241],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["unexpected-data-type", "cwe-241", "type-confusion", "input-validation"],
}

_strip(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), "`(\\\\.|[^`\\\\])*`", "``")

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "A JSON request body value is used as a str with no type check: JSON lets the client send a number, list, object or null instead, which raises AttributeError. Check isinstance(value, str) or validate the body with a schema",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# JavaScript/TypeScript request values used as strings are reported by
# VNX-1287, which owns that shape; this rule reads Python JSON bodies.

# ── Python ───────────────────────────────────────────────────────────────

_py_body := `(?:\brequest\.json\b|\brequest\.get_json\([^)]*\)|\brequest\.data\b|\bjson\.loads\(\s*request\.(?:body|data|get_data\(\))[^)]*\))`

_py_field := `(?:\[[^\]]+\]|\.get\([^)]*\))`

_py_method := `\.(?:lower|upper|strip|lstrip|rstrip|split|rsplit|startswith|endswith|replace|encode|casefold|title|capitalize)\(`

# Dicts assigned from a JSON body.
_py_dicts(lines, i) := {v |
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	contains(prev, "request")
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*([A-Za-z_]\w*)\s*(?::\s*[\w\[\], ]+)?=\s*`, _py_body, `\s*$`]), prev, 1)
	count(m) > 0
	v := m[0][1]
}

# Variables assigned from one field of such a dict, or of the body itself.
_py_fields(lines, i, dicts) := {v |
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	some d in _py_srcs(dicts)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*([A-Za-z_]\w*)\s*=\s*`, d, _py_field, `\s*$`]), prev, 1)
	count(m) > 0
	v := m[0][1]
}

_py_srcs(dicts) := {_py_body} | {concat("", [`\b`, d, `\b`]) | some d in dicts}

_py_guard(lines, i, v) if {
	w := helpers.code_window(lines, i, 10, 0)
	regex.match(concat("", [`isinstance\(\s*`, v, `\b|\b`, v, `\s*=\s*str\(|type\(\s*`, v, `\s*\)`]), w)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "request")
	regex.match(_py_method, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".")
	not helpers.is_comment_line(line)
	c := _strip(line)
	regex.match(_py_method, c)
	_py_sink(lines, i, c)
	finding := _finding(path, i, line)
}

_py_sink(lines, i, c) if {
	dicts := _py_dicts(lines, i)
	some d in _py_srcs(dicts)
	regex.match(concat("", [d, _py_field, _py_method]), c)
}

_py_sink(lines, i, c) if {
	dicts := _py_dicts(lines, i)
	some v in _py_fields(lines, i, dicts)
	regex.match(concat("", [`(?:^|[^\w.])`, v, _py_method]), c)
	not _py_guard(lines, i, v)
}
