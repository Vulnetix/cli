# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_237

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-237",
	"name": "Improper Handling of Structural Elements",
	"description": "A parser of untrusted form or query data is configured, or called, without a limit on its structural elements (field count, nesting depth, array length), so one request can make it build millions of keys or deeply nested objects. Node.js/TypeScript: an option of express.urlencoded()/bodyParser.urlencoded(), qs.parse() or querystring.parse() (the call within the eight lines above) set to Infinity, Number.MAX_SAFE_INTEGER/MAX_VALUE/POSITIVE_INFINITY, or a number far past the library default: parameterLimit >= 100000, arrayLimit >= 10000, depth >= 50, and querystring's maxKeys: 0 (unlimited). Python: Django's DATA_UPLOAD_MAX_NUMBER_FIELDS or DATA_UPLOAD_MAX_NUMBER_FILES, Werkzeug's max_form_parts or Flask's MAX_FORM_PARTS set to None; and urllib.parse.parse_qs()/parse_qsl() of a raw request body (self.rfile.read(), request.body, request.get_data(), request.stream.read(), environ['wsgi.input'].read(), inline or through a variable assigned in the eight lines above) without max_num_fields. Not reported: limits at or near the defaults, a depth option of an unrelated API (util.inspect, a tree walker), parse_qs of a URL's query string, comments, string values and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-237/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [237],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["structural-elements", "cwe-237", "resource-limits", "denial-of-service"],
}

# ── Node.js ──────────────────────────────────────────────────────────────

_js_ext(path) if regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx)$`, path)

_opt_re := `\b(parameterLimit|arrayLimit|depth|maxKeys)\s*:\s*([A-Za-z0-9_\.]+)`

_parser_call := `(?:\burlencoded|\b[qQ]s\.parse|\bquerystring\.parse|\(\s*["']querystring["']\s*\)\.parse)\s*\(`

_unbounded(_, v) if v in {"Infinity", "Number.MAX_SAFE_INTEGER", "Number.MAX_VALUE", "Number.POSITIVE_INFINITY"}

_unbounded(opt, v) if {
	regex.match(`^\d[\d_]*$`, v)
	n := to_number(replace(v, "_", ""))
	_too_big(opt, n)
}

_too_big("parameterLimit", n) if n >= 100000

_too_big("arrayLimit", n) if n >= 10000

_too_big("depth", n) if n >= 50

_too_big("maxKeys", 0)

findings contains finding if {
	some path, content in input.file_contents
	_js_ext(path)
	regex.match(`urlencoded|qs\.parse|querystring`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:parameterLimit|arrayLimit|depth|maxKeys)\s*:`, line)
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_opt_re, line, -1)
	_unbounded(m[1], m[2])
	regex.match(_parser_call, helpers.code_window(lines, i, 8, 0))
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Request parser option %s: %s removes the limit on fields, nesting or array size; one request can make the parser build a huge object. Keep the default or a small bound", [m[1], m[2]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Python ───────────────────────────────────────────────────────────────

_py_none_re := `\b(?:DATA_UPLOAD_MAX_NUMBER_FIELDS|DATA_UPLOAD_MAX_NUMBER_FILES|max_form_parts|MAX_FORM_PARTS)(?:["']\s*\])?\s*=\s*None\b`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`DATA_UPLOAD_MAX_NUMBER_|max_form_parts|MAX_FORM_PARTS`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_py_none_re, line)
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": "Setting this limit to None lets one request submit an unlimited number of form fields or parts. Keep a numeric bound",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_body_src := `(?:\bself\.rfile\.read|\brequest\.body\b|\brequest\.get_data|\brequest\.stream\.read|\benviron\s*\[\s*["']wsgi\.input["']\s*\]\.read)`

_qs_hit(_, _, line) if regex.match(concat("", [`\bparse_qsl?\(\s*`, _body_src]), line)

_qs_hit(lines, i, line) if {
	some v in helpers.tainted_names(lines, i, 8, _body_src)
	regex.match(concat("", [`\bparse_qsl?\(\s*`, v, `\b`]), line)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "parse_qs")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "parse_qs")
	not startswith(trim_space(line), "#")
	not contains(line, "max_num_fields")
	_qs_hit(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "parse_qs()/parse_qsl() of a raw request body without max_num_fields: one request can submit an unlimited number of fields. Pass max_num_fields",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
