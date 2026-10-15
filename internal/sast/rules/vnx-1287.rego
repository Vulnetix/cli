# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1287

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1287",
	"name": "Improper Validation of Specified Type of Input",
	"description": "A request value whose type the client chooses is used as a string without checking that it is one. A query-string parser turns ?q[]=a into an array and ?q[x]=1 into an object, and a JSON body field can be any JSON type, so a string method then throws (a crash or a 500) or, for length/includes/indexOf/startsWith checks, silently answers for an array and bypasses the check. Reported in JavaScript/TypeScript: a string method (toLowerCase/toUpperCase/trim/split/startsWith/endsWith/includes/indexOf/replace/match/slice/substring/charAt/padStart/normalize/localeCompare) or .length applied to a field of req.query/req.body/request.body/ctx.query/ctx.request.body, directly or through a variable or destructured name assigned from it in the 10 lines above. Reported in Python: a str method (lower/upper/strip/split/startswith/endswith/replace/encode/casefold) applied to a field of a JSON body (request.json, request.get_json(), DRF request.data, json.loads(request.body/data)), directly, through the dict assigned from it, or through a variable assigned from one of its fields. Not reported: Express/Koa route params and Flask form/args/headers (always strings), a value checked with typeof/Array.isArray/isinstance or coerced with String()/str() first, files that validate requests with express-validator, Joi, zod, yup, celebrate, ajv, class-validator or superstruct, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1287/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1287],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["input-validation-type", "cwe-1287"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_is_js(path) if {
	some e in _js_exts
	endswith(path, e)
}

_skip(path) if endswith(path, ".min.js")

_skip(path) if contains(path, "node_modules/")

_strip(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), "`(\\\\.|[^`\\\\])*`", "``")

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Request value of client-chosen type used as a string: an array or object here throws or slips past the check. Verify typeof value === 'string' (isinstance(value, str)) first",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── JavaScript / TypeScript ──────────────────────────────────────────────

_js_src := `(?:\b(?:req|request)\.(?:query|body)|\bctx\.(?:query|request\.body))`

_js_field := `(?:\.\w+|\[\s*''\s*\]|\[\s*""\s*\])`

_js_method := `(?:\??\.(?:toLowerCase|toUpperCase|toLocaleLowerCase|trim|trimStart|trimEnd|split|startsWith|endsWith|includes|indexOf|lastIndexOf|replace|replaceAll|match|slice|substring|substr|charAt|charCodeAt|padStart|padEnd|normalize|localeCompare)\(|\??\.length\b)`

_js_validator_re := `(?:require\(|from\s+)['"](?:express-validator|joi|@hapi/joi|zod|yup|celebrate|ajv|class-validator|superstruct|io-ts)`

_js_names(lines, i) := {v |
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := _strip(lines[j])
	contains(prev, "=")
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?=\s*`, _js_src, _js_field, `(?:\s*(?:\|\||\?\?)\s*(?:''|""))?(?:\s+as\s+\w+)?\s*;?\s*$`]), prev, 1)
	count(m) > 0
	v := m[0][1]
} | {v |
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := _strip(lines[j])
	contains(prev, "}")
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*(?::\s*[^=]+)?=\s*`, _js_src, `(?:\s+as\s+[^;]+)?\s*;?\s*$`]), prev, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	segs := split(split(part, "=")[0], ":")
	nm := trim_space(segs[count(segs) - 1])
	regex.match(`^[A-Za-z_$][\w$]*$`, nm)
	v := nm
}

_js_guard(lines, i, v) if {
	w := helpers.code_window(lines, i, 10, 0)
	regex.match(concat("", [`typeof\s+`, v, `\b|Array\.isArray\(\s*`, v, `\b|\bString\(\s*`, v, `\b|\bis(?:String|Array)\(\s*`, v, `\b|\b`, v, `\s*=\s*String\(|\b`, v, `\s+instanceof\b`]), w)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not _skip(path)
	regex.match(`\b(?:req|request|ctx)\.(?:query|body|request)`, content)
	not regex.match(_js_validator_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".")
	not helpers.is_comment_line(line)
	c := _strip(line)
	_js_sink(lines, i, c)
	finding := _finding(path, i, line)
}

_js_sink(lines, i, c) if {
	m := regex.find_all_string_submatch_n(concat("", [`(`, _js_src, _js_field, `)`, _js_method]), c, -1)
	some x in m
	not _js_expr_guard(lines, i, x[1])
}

# typeof/Array.isArray of the same request field on the line or the 10 above.
_js_expr_guard(lines, i, e) if {
	q := regex.replace(regex.replace(e, `([.\[\]$?])`, `\$1`), `\s+`, `\s*`)
	w := helpers.code_window(lines, i, 10, 0)
	regex.match(concat("", [`typeof\s*\(?\s*`, q, `|Array\.isArray\(\s*`, q, `|\bString\(\s*`, q]), w)
}

_js_sink(lines, i, c) if {
	regex.match(_js_method, c)
	some v in _js_names(lines, i)
	regex.match(concat("", [`(?:^|[^\w$.])`, v, _js_method]), c)
	not _js_guard(lines, i, v)
}

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
