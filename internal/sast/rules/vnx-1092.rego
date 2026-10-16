# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1092

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1092",
	"name": "Use of Same Invokable Control Element in Multiple Architectural Layers",
	"description": "A Python data-layer module (models.py, a models/, repositories/, repository/, dao/ or dal/ package, repository.py, dao.py) uses the web layer's request or response machinery: it imports request, session, render_template, redirect, make_response, flash or abort from Flask (including a parenthesised multi-line import, reported at its first line), anything from django.http or django.shortcuts, Request from fastapi/starlette or rest_framework.request, or reads the request object (request.args, request.form, request.GET, request.POST, request.json, request.cookies, session[...] when session is imported from Flask, or the same attributes on a parameter annotated : Request). The same control element then runs in both the presentation and the data layer, so data access depends on whichever HTTP request happens to be active and input validation done in the view can be bypassed or duplicated. Reported: the import or the request read. Not reported: flask.g and current_app (the documented way to share a connection), django.urls.reverse (get_absolute_url), view, route and service modules, test files, comments, and mentions inside docstrings or other triple-quoted strings. Layering that is expressed through names other than these file paths is not inferred.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1092/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1092],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["architecture", "layering", "maintainability", "cwe-1092"],
}

_data_layer(path) if regex.match(`(^|/)(models|repository|repositories|dao|dal)\.py$`, path)

_data_layer(path) if regex.match(`(^|/)(models|repository|repositories|dao|daos|dal)/[^/]+\.py$`, path)

_web_names := `(request|session|render_template|render_template_string|redirect|make_response|flash|abort|Response|Request)`

# from flask import a, b, (c ...) naming one of the web-layer objects.
_web_import(line) if {
	m := regex.find_all_string_submatch_n(`^\s*from\s+(flask|quart)\s+import\s+\(?\s*([^#)]+)`, line, 1)
	count(m) > 0
	some n in split(m[0][2], ",")
	regex.match(concat("", [`^\s*`, _web_names, `(\s+as\s+\w+)?\s*$`]), n)
}

_web_import(line) if regex.match(`^\s*from\s+django\.(http|shortcuts)(\.\w+)?\s+import\s+`, line)

_web_import(line) if regex.match(`^\s*import\s+django\.(http|shortcuts)\b`, line)

_web_import(line) if regex.match(`^\s*from\s+(fastapi|starlette\.requests|rest_framework\.request)\s+import\s+.*\bRequest\b`, line)

_web_import(line) if regex.match(`^\s*from\s+flask\s+import\s+request\b`, line)

# Reading the active request inside the data layer.
_request_read(line) if regex.match(`\b(?:flask\.)?request\.(args|form|values|json|get_json|files|cookies|headers|GET|POST|FILES|COOKIES|META|data|query_params)\b`, regex.replace(line, `'[^']*'|"[^"]*"`, `""`))

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	_data_layer(path)
	regex.match(`(flask|quart|django\.(http|shortcuts)|fastapi|starlette|rest_framework|request\.)`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	_any_hit(content, lines, i, line)
	not _in_docstring(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Data-layer module uses the web layer's request/response objects; pass plain values from the view instead so the model does not depend on the active HTTP request",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_any_hit(_, lines, i, line) if _hit(lines, i, line)

# Flask's session read as a mapping: session["user_id"], when the module
# imports session from flask.
_any_hit(content, _, _, line) if {
	contains(line, "session[")
	_flask_session(content)
	regex.match(`\bsession\[`, line)
}

_flask_session(content) if regex.match(`(?m)^\s*from\s+(flask|quart)\s+import\s+\(?[^#\n]*\bsession\b`, content)

# A parameter annotated as a web Request (req: Request) read like request.
_any_hit(content, _, _, line) if {
	contains(content, ": Request")
	some n in _request_params(content)
	contains(line, n)
	regex.match(concat("", [`\b`, n, `\.(args|form|values|json|get_json|files|cookies|headers|query_params|data)\b`]), line)
}

_request_params(content) := {m[1] |
	regex.match(`(?m)^\s*from\s+(fastapi|starlette\.requests|rest_framework\.request)\s+import\s+.*\bRequest\b`, content)
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*:\s*Request\b`, content, -1)
	m[1] != "request"
}

_hit(_, _, line) if _web_import(line)

_hit(_, _, line) if _request_read(line)

# from flask import (
#     request,
# )
_hit(lines, i, line) if {
	regex.match(`^\s*from\s+(flask|quart)\s+import\s*\(\s*$`, line)
	end := min([count(lines) - 1, i + 15])
	i + 1 <= end
	closes := [k | some k in numbers.range(i + 1, end); contains(lines[k], ")")]
	e := min(array.concat([end], closes))
	names := concat(",", [regex.replace(lines[k], `#.*$|\)`, "") | some k in numbers.range(i + 1, e)])
	some n in split(names, ",")
	regex.match(concat("", [`^\s*`, _web_names, `(\s+as\s+\w+)?\s*$`]), n)
}

# Line i sits inside a triple-quoted string (a docstring that mentions
# request.args is prose, not a read): an odd number of triple quotes above it.
_in_docstring(lines, i) if {
	i > 0
	n := sum([count(regex.find_all_string_submatch_n(`"""|'''`, lines[k], -1)) | some k in numbers.range(0, i - 1); _has_triple(lines[k])])
	n % 2 == 1
}

_has_triple(l) if contains(l, `"""`)

_has_triple(l) if contains(l, `'''`)
