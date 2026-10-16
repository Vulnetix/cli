# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_392

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-392",
	"name": "Missing Report of Error Condition",
	"description": "A Python web handler catches an exception and answers with an error body but no error status, so the client receives HTTP 200 OK for a failed request. Reported: inside an except block, a return of jsonify(...), JsonResponse(...), JSONResponse(...), HttpResponse(...), Response(...) or make_response(...), Sanic json(...) (in a module importing sanic), or (in a Flask, FastAPI, Django or Starlette module) a dict literal, whose content says the request failed (error, fail, invalid, not found, denied, unauthorized, forbidden, exception, missing, went wrong, unable to, could not, cannot, a success or ok key set to False, or str(e)/the exception variable), with no error status: no status=/status_code= argument and no (body, 4xx/5xx) or HTTPStatus tuple, or one that explicitly gives 200/2xx/HTTPStatus.OK, spanning a call broken across lines. Not reported: a response that sets a status, abort()/raise, a re-rendered HTML template (render/render_template, a form shown again with its error), a dict returned from a module that is not a web handler, test files, comments and strings. An 'error' key in a JSON body with status 200 is the exact failure this reports, including a 'status': '500' written into the body.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-392/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [392],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["error-handling", "cwe-392"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_web_module(content) if regex.match(`(?m)^\s*(?:from|import)\s+(?:flask|fastapi|django|starlette|rest_framework|quart|sanic)\b`, content)

_resp_call_re := `^\s*return\s+(?:[\w.]+\.)?(?:jsonify|JsonResponse|JSONResponse|HttpResponse|Response|make_response|PlainTextResponse)\s*\(`

_dict_re := `^\s*return\s+\{`

# Sanic's response helper is a bare json(...) (from sanic.response import json).
_returns_response(stmt, content) if {
	regex.match(`^\s*return\s+(?:response\.)?json\s*\(`, stmt)
	regex.match(`(?m)^\s*(?:from|import)\s+sanic\b`, content)
}

_returns_response(stmt, _) if regex.match(_resp_call_re, stmt)

_returns_response(stmt, content) if {
	regex.match(_dict_re, stmt)
	_web_module(content)
}

_error_text(stmt, _) if regex.match(`(?i)error|fail|invalid|not[ _]found|denied|unauthori[sz]ed|forbidden|exception|missing|went wrong|unable to|could\s*(?:not|n't)|cannot|can't|["'](?:success|ok)["']\s*:\s*False|\b(?:success|ok)\s*=\s*False|\bstr\(\s*(?:e|ex|exc|err|error|exception)\s*\)`, stmt)

_error_text(stmt, v) if {
	v != ""
	regex.match(concat("", [`\b`, v, `\b`]), stmt)
}

# A status is given: a keyword argument, or a (body, code) tuple.
_has_status(stmt) if {
	regex.match(`\bstatus(?:_code)?\s*=`, stmt)
	not _ok_status(stmt)
}

_has_status(stmt) if {
	regex.match(`[\)\}]\s*,\s*(?:[1-5]\d\d\b|(?:http\.)?HTTPStatus\.|status\.HTTP_|codes\.)`, stmt)
	not _ok_status(stmt)
}

# An explicit success status given to an error body is no status at all.
_ok_status(stmt) if regex.match(`(?:\bstatus(?:_code)?\s*=\s*|[\)\}]\s*,\s*)(?:2\d\d\b|(?:http\.)?HTTPStatus\.OK\b|status\.HTTP_2\d\d|codes\.ok\b)`, stmt)

# The return statement, joined with its continuation lines (deeper indent).
_statement(lines, r) := concat(" ", [lines[k] |
	some k in numbers.range(r, min([count(lines) - 1, r + 5]))
	_continues(lines, r, k)
])

_continues(_, r, k) if k == r

_continues(lines, r, k) if {
	k > r
	every m in numbers.range(r + 1, k) {
		_indent(lines[m]) > _indent(lines[r])
	}
}

_exc_var(line) := v if {
	m := regex.find_all_string_submatch_n(`\bas\s+(\w+)\s*:`, line, 1)
	count(m) > 0
	v := m[0][1]
} else := ""

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "except")
	contains(content, "return")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*except\b[^:]*:\s*(?:#.*)?$`, line)
	ie := _indent(line)
	v := _exc_var(line)

	# the except body: the deeper-indented lines that follow it
	some r in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
	startswith(trim_space(lines[r]), "return")
	_indent(lines[r]) > ie
	not _left_block(lines, i, r, ie)
	stmt := _statement(lines, r)
	_returns_response(stmt, content)
	_error_text(stmt, v)
	not _has_status(stmt)
	finding := {
		"rule_id": metadata.id,
		"message": "Error response returned without an error status: the client receives 200 OK for a request that failed. Return a 4xx/5xx status with the error body",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r + 1,
		"snippet": lines[r],
	}
}

# A line between the except and r at the except's indent or shallower ends
# the except body.
_left_block(lines, i, r, ie) if {
	some m in helpers.span(i + 1, r - 1)
	m > i
	m < r
	trim_space(lines[m]) != ""
	_indent(lines[m]) <= ie
}
