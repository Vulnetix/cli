# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1286

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1286",
	"name": "Improper Validation of Syntactic Correctness of Input",
	"description": "Request data is converted by a parser that rejects malformed input, with nothing handling the rejection, so a malformed value crashes the handler (an unhandled exception, a 500 with a stack trace) or flows on as NaN. Reported in Python: int(), float(), Decimal(), json.loads(), uuid.UUID(), datetime/date fromisoformat() and strptime(), ipaddress.ip_address()/ip_network() whose argument is Flask/Django/DRF request data (request.args/form/values/GET/POST/data/body/json/cookies/headers/query_params/META), directly or through a variable assigned from it in the 10 lines above, when the call is not inside a try block and the variable was not checked with isdigit()/isdecimal()/isnumeric()/a regex match first. Reported in JavaScript/TypeScript: JSON.parse() of request data (req/request body/query/params/cookies/headers, ctx.query, ctx.request.body, Lambda event.body/queryStringParameters) outside a try block, and parseInt()/parseFloat()/Number() of request data with no NaN check (isNaN, Number.isNaN/isFinite/isInteger, a `|| default`, or a falsy test of the result) on the line or in the 6 lines after. Not reported: framework-typed access (request.args.get(name, type=int)), constants, environment variables, files, comments, block comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1286/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1286],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["input-validation-syntactic", "cwe-1286"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_is_js(path) if {
	some e in _js_exts
	endswith(path, e)
}

_skip(path) if endswith(path, ".min.js")

_skip(path) if contains(path, "node_modules/")

_strip(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), "`(\\\\.|[^`\\\\])*`", "``")

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Names a line assigns: the first simple target, or every destructured name.
_assigned(line) := {v |
	m := regex.find_all_string_submatch_n(`^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?=\s*[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
	not v in {"const", "let", "var", "_"}
} | {v |
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	nm := trim_space(split(split(part, "=")[0], ":")[count(split(split(part, "=")[0], ":")) - 1])
	regex.match(`^[A-Za-z_$][\w$]*$`, nm)
	v := nm
}

_tainted(lines, i, src_re) := {v |
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := lines[j]
	regex.match(src_re, prev)
	not helpers.is_comment_line(prev)
	some v in _assigned(prev)
}

# The argument text after the opening paren: rest of the line, or the next
# line when the call is split right after the paren.
_arg(lines, i, rest) := rest if trim_space(rest) != ""

_arg(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

_arg_is_input(arg, _, src_re) if regex.match(concat("", [`^\s*(?:`, src_re, `)`]), arg)

_arg_is_input(arg, names, _) if {
	some v in names
	regex.match(concat("", [`^\s*`, v, `\b\s*(?:\)|,|\s+as\b|\.\w+\s*\))`]), arg)
}

# ── Python ───────────────────────────────────────────────────────────────

_py_src := `\brequest\.(?:args|form|values|GET|POST|data|body|json|cookies|COOKIES|headers|query_params|query|META|get_data\b|get_json\b)|\bself\.request\.(?:get|arguments|body)\b`

_py_conv := `(?:^|[^\w.])(?:int|float|Decimal|Fraction|json\.loads|uuid\.UUID|UUID|(?:datetime|date|time)\.fromisoformat|(?:datetime\.)?strptime|ipaddress\.ip_(?:address|network|interface)|ip_address|ip_network)\(`

_py_in_try(lines, i) if {
	ii := _indent(lines[i])
	some j in numbers.range(max([0, i - 40]), i - 1)
	regex.match(`^\s*try\s*:`, lines[j])
	ij := _indent(lines[j])
	ij < ii
	not _py_closed(lines, j, i, ij)
}

_py_closed(lines, j, i, ij) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	trim_space(lines[k]) != ""
	not helpers.is_comment_line(lines[k])
	_indent(lines[k]) <= ij
}

_py_checked(lines, i, names) if {
	some v in names
	w := helpers.code_window(lines, i, 8, 0)
	regex.match(concat("", [`\b`, v, `\.(?:isdigit|isdecimal|isnumeric)\(|(?:fullmatch|match)\([^)]*\b`, v, `\b`]), w)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "request")
	regex.match(_py_conv, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	c := _strip(line)
	regex.match(_py_conv, c)
	names := _tainted(lines, i, _py_src)
	some rest in _call_rests(c, _py_conv)
	_arg_is_input(_arg(lines, i, rest), names, _py_src)
	not _py_in_try(lines, i)
	not _py_checked(lines, i, names)
	finding := _finding(path, i, line, "Request value is parsed with no handler for malformed input; a bad value raises and fails the request. Validate it or catch the parse error and answer 400")
}

_call_rests(c, conv_re) := {r |
	parts := regex.split(conv_re, c)
	count(parts) > 1
	some k in numbers.range(1, count(parts) - 1)
	r := parts[k]
}

# ── JavaScript / TypeScript ──────────────────────────────────────────────

_js_src := `\b(?:req|request)\.(?:body|query|params|cookies|headers|get\()|\bctx\.(?:query|params|request\.body)\b|\bevent\.(?:body|queryStringParameters|pathParameters)\b`

_in_block_comment(lines, i) if {
	some j in numbers.range(max([0, i - 30]), i - 1)
	contains(lines[j], "/*")
	s := _strip(lines[j])
	contains(s, "/*")
	not contains(substring(s, indexof(s, "/*"), -1), "*/")
	not _comment_closed(lines, j, i)
}

_comment_closed(lines, j, i) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	contains(lines[k], "*/")
}

_braces(line) := count(regex.find_all_string_submatch_n(`\{`, line, -1)) - count(regex.find_all_string_submatch_n(`\}`, line, -1))

_js_in_try(lines, i) if {
	some j in numbers.range(max([0, i - 30]), i - 1)
	regex.match(`\btry\s*\{`, lines[j])
	t := substring(lines[j], indexof(lines[j], "try"), -1)
	not _try_closed(lines, j, i, t)
}

_try_closed(lines, j, i, t) if {
	some m in numbers.range(j, i - 1)
	d := sum([_braces(x) | some k in numbers.range(j, m); x := _try_text(lines, j, k, t)])
	d < 1
}

_try_text(lines, j, j, t) := _strip(t)

_try_text(lines, j, k, _) := _strip(lines[k]) if k != j

_js_guarded(lines, i, line) if regex.match(`\)\s*(?:as\s+\w+\s*)?(?:\|\||\?\?)`, line)

_js_guarded(lines, i, _) if {
	w := helpers.code_window(lines, i, 0, 6)
	regex.match(`\bisNaN\(|Number\.is(?:NaN|Finite|Integer|SafeInteger)\(|\bisFinite\(`, w)
}

_js_guarded(lines, i, line) if {
	some v in _assigned(line)
	w := helpers.code_window(lines, i + 1, 0, 5)
	regex.match(concat("", [`!\s*`, v, `\b|\b`, v, `\s*(?:\|\||\?\?)`]), w)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not _skip(path)
	regex.match(`\b(?:req|request|ctx|event)\.`, content)
	regex.match(`JSON\.parse\(|parseInt\(|parseFloat\(|Number\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	c := _strip(line)
	some kind in _js_kinds(c)
	names := _tainted(lines, i, _js_src)
	some rest in _call_rests(c, _js_conv[kind])
	arg := _arg(lines, i, rest)
	_arg_is_input(arg, names, _js_src)
	not _js_validated(content, arg)
	not _in_block_comment(lines, i)
	_js_unhandled(kind, lines, i, line)
	finding := _finding(path, i, line, _js_msg[kind])
}

# An express-validator chain on the same field (query('limit').isInt()) has
# already rejected a malformed value before the handler runs.
_js_validated(content, arg) if {
	m := regex.find_all_string_submatch_n(`^\s*(?:req|request)\.(?:query|params|body)\.(\w+)`, arg, 1)
	count(m) > 0
	f := m[0][1]
	regex.match(concat("", [`\b(?:query|param|body|check)\(\s*['"]`, f, `['"]\s*\)\s*\.\s*(?:isInt|isFloat|isNumeric|isDecimal|toInt|toFloat|isJSON|isUUID)\(`]), content)
}

_js_conv := {
	"json": `\bJSON\.parse\(`,
	"num": `(?:^|[^\w.])(?:Number\.)?(?:parseInt|parseFloat)\(|(?:^|[^\w.$])Number\(`,
}

_js_msg := {
	"json": "JSON.parse() of request data outside a try block: malformed input throws and fails the request. Parse inside try/catch and answer 400",
	"num": "Request value converted to a number with no NaN check: malformed input flows on as NaN. Check Number.isNaN (or supply a default) before use",
}

_js_kinds(c) := {k | some k, re in _js_conv; regex.match(re, c)}

_js_unhandled("json", lines, i, _) if not _js_in_try(lines, i)

_js_unhandled("num", lines, i, line) if not _js_guarded(lines, i, line)

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
