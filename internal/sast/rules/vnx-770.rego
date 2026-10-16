# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_770

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-770",
	"name": "Allocation of Resources Without Limits or Throttling",
	"description": "Reports configuration that switches off, or raises out of reach, a limit a web framework applies to what one request may make the server allocate. Python: Django DATA_UPLOAD_MAX_MEMORY_SIZE, DATA_UPLOAD_MAX_NUMBER_FIELDS or DATA_UPLOAD_MAX_NUMBER_FILES set to None; Flask MAX_CONTENT_LENGTH assigned None (also inside app.config.update or from_mapping); Flask-Limiter turned off (RATELIMIT_ENABLED = False, Limiter(..., enabled=False)); sys.set_int_max_str_digits(0), which removes the guard against quadratic int/str conversion. Node: an express/body-parser json, urlencoded, raw or text parser, or a koa-body / koa-bodyparser call, with limit (jsonLimit, formLimit, textLimit) Infinity, a gigabyte limit or one of 50 MB and more (a string size, a byte count or a product such as 1024 * 1024 * 1024), or parameterLimit Infinity; multer() configured without a limits block (no file size or count limit); a socket.io maxHttpBufferSize of Infinity or 100 MB and more. Not reported: bounded values, the frameworks' own defaults tables (dict literals), these settings in a configuration class or settings module named for testing, development or local use (settings/dev.py, settings_local.py), comments, string literals and test files. Missing limits that are never configured at all (no body parser options, no rate limiter) are not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-770/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [770],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["resource-throttling", "cwe-770"],
}

_js(path) if regex.match(`\.(?:js|mjs|cjs|ts|mts|cts)$`, path)

_indent(line) := count(line) - count(trim_left(line, " \t"))

# ── Python ──────────────────────────────────────────────────────────────

_py_re := `^\s*(?:DATA_UPLOAD_MAX_(?:MEMORY_SIZE|NUMBER_FIELDS|NUMBER_FILES)\s*=\s*None\b|(?:[\w.]+\.config\[\s*['"]MAX_CONTENT_LENGTH['"]\s*\]|MAX_CONTENT_LENGTH)\s*=\s*None\b|(?:[\w.]+\.config\[\s*['"]RATELIMIT_ENABLED['"]\s*\]|RATELIMIT_ENABLED)\s*=\s*False\b|(?:sys\.)?set_int_max_str_digits\(\s*0\s*\)|[\w.]*\s*=?\s*Limiter\(.*\benabled\s*=\s*False\b|[\w.]+\.config\.(?:update|from_mapping)\(.*\bMAX_CONTENT_LENGTH\s*=\s*None\b)`

# A configuration class meant for tests or local development.
_dev_class(lines, i) if {
	_indent(lines[i]) > 0
	some k in numbers.range(max([0, i - 40]), i - 1)
	regex.match(`^class\s+\w*(?:Test|Testing|Dev|Development|Local|Debug)\w*\b`, lines[k])
	not _class_between(lines, k, i)
}

_class_between(lines, k, i) if {
	k + 1 <= i - 1
	some m in helpers.span(k + 1, i - 1)
	startswith(lines[m], "class ")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	not _dev_settings_file(path)
	regex.match(`DATA_UPLOAD_MAX_|MAX_CONTENT_LENGTH|RATELIMIT_ENABLED|set_int_max_str_digits|Limiter\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_py_re, line)
	not _dev_class(lines, i)
	finding := _finding(path, i, line, "A framework limit on request size, field count, rate or integer conversion is disabled; keep it bounded")
}

# ── Node ────────────────────────────────────────────────────────────────

_parser_re := `\b(?:express|bodyParser|bodyparser|koaBody|koaBodyParser)\.(?:json|urlencoded|raw|text)\s*\(|\b(?:koaBody|bodyParser|bodyparser|koaBodyParser)\s*\(\s*\{`

# limit (express/body-parser) and koa-body/koa-bodyparser's json/form/text limits
_key := `\b(?:limit|jsonLimit|formLimit|textLimit)`

# The option text of a call starting on line i: the line itself, or up to
# four further lines until one closes the call.
_opts(lines, i) := lines[i] if contains(lines[i], ")")

_opts(lines, i) := txt if {
	not contains(lines[i], ")")
	limit := min([count(lines) - 1, i + 4])
	ends := [k | some k in numbers.range(i + 1, limit); contains(lines[k], ")")]
	e := min(array.concat([limit], ends))
	txt := concat("\n", array.slice(lines, i, e + 1))
}

_unbounded_limit(txt) if regex.match(`\b(?:limit|jsonLimit|formLimit|textLimit|parameterLimit)\s*:\s*(?:Infinity|Number\.MAX_SAFE_INTEGER|Number\.POSITIVE_INFINITY)\b`, txt)

_unbounded_limit(txt) if regex.match(`\blimit\s*:\s*['"]\s*\d+(?:\.\d+)?\s*(?:gb|tb)\s*['"]`, lower(regex.replace(txt, `(?i)(json|form|text)limit`, "limit")))

_unbounded_limit(txt) if {
	m := regex.find_all_string_submatch_n(`\blimit\s*:\s*['"]\s*(\d+)(?:\.\d+)?\s*mb\s*['"]`, lower(regex.replace(txt, `(?i)(json|form|text)limit`, "limit")), 1)
	count(m) > 0
	to_number(m[0][1]) >= 50
}

# a byte count, written as a literal or a product (1024 * 1024 * 1024)
_unbounded_limit(txt) if {
	m := regex.find_all_string_submatch_n(concat("", [_key, `\s*:\s*(\d+(?:\s*\*\s*\d+)*)\s*[,}\n]`]), txt, 1)
	count(m) > 0
	factors := [to_number(trim_space(f)) | some f in split(m[0][1], "*")]
	product(factors) >= 52428800
}

findings contains finding if {
	some path, content in input.file_contents
	_js(path)
	not helpers.is_test_path(path)
	regex.match(_parser_re, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_parser_re, line)
	_unbounded_limit(_opts(lines, i))
	finding := _finding(path, i, line, "Request body parser limit is unbounded or set to a very large size; keep it to what the endpoint needs (express defaults to 100kb)")
}

# multer with no limits: no file size, file count or field limit
_multer_re := `\bmulter\s*\(\s*(?:\{|\))`

_multer_end(lines, i) := i if regex.match(`\bmulter\s*\(\s*(?:\)|\{.*\}\s*\))`, lines[i])

_multer_end(lines, i) := e if {
	not regex.match(`\bmulter\s*\(\s*(?:\)|\{.*\}\s*\))`, lines[i])
	ind := _indent(lines[i])
	limit := min([count(lines) - 1, i + 60])
	ends := [k |
		some k in numbers.range(i + 1, limit)
		_indent(lines[k]) == ind
		startswith(trim_space(lines[k]), "}")
	]
	count(ends) > 0
	e := min(ends)
}

findings contains finding if {
	some path, content in input.file_contents
	_js(path)
	not helpers.is_test_path(path)
	contains(content, "multer")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "multer")
	not helpers.is_comment_line(line)
	regex.match(_multer_re, line)
	e := _multer_end(lines, i)
	span := concat("\n", array.slice(lines, i, e + 1))
	not contains(span, "limits")
	finding := _finding(path, i, line, "multer is configured without limits, so one request can upload files of any size and number; set limits.fileSize and limits.files")
}

# socket.io message buffer
findings contains finding if {
	some path, content in input.file_contents
	_js(path)
	not helpers.is_test_path(path)
	contains(content, "maxHttpBufferSize")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "maxHttpBufferSize")
	not helpers.is_comment_line(line)
	_huge_buffer(regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|//.*$`, `""`))
	finding := _finding(path, i, line, "socket.io maxHttpBufferSize is unbounded or very large; keep it near the 1 MB default")
}

_huge_buffer(line) if regex.match(`maxHttpBufferSize\s*:\s*(?:Infinity|Number\.MAX_SAFE_INTEGER)\b`, line)

_huge_buffer(line) if {
	m := regex.find_all_string_submatch_n(`maxHttpBufferSize\s*:\s*(\d+(?:\.\d+)?(?:e\d+)?)\b`, line, 1)
	count(m) > 0
	to_number(m[0][1]) >= 100000000
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# A settings module for development or local use (settings/dev.py,
# settings_local.py, config/development.py).
_dev_settings_file(path) if regex.match(`(?i)(?:^|[/_])(?:dev|develop|development|local|debug)(?:_settings|_config)?\.py$`, path)
