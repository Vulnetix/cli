# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_400

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-400",
	"name": "Uncontrolled Resource Consumption from a request-supplied size",
	"description": "A number read from the HTTP request decides how much work or memory a Python handler spends, with no upper bound, so one request can exhaust CPU, memory or a worker. Reported: a Flask/Django/DRF request value (request.args/form/values/json/GET/POST/data/query_params/headers/cookies), used directly or through a variable assigned from it in the 10 lines above, or a FastAPI route parameter typed int or float on a single-line def with no le=/lt= bound, as the count of range(...), the duration of time.sleep(...), the size of bytearray()/bytes()/os.urandom()/secrets.token_bytes()/token_hex()/token_urlsafe()/.read()/.recv()/numpy zeros/ones/empty/full/arange, the width of str.zfill/ljust/rjust/center, the multiplier of a string or list repetition (\"=\" * n, [x] * n), or the exponent of **. Not reported: a value bounded first (min(...), an if comparing the variable with a limit other than 0 or 1, a max/min clamp reassignment; a lower-bound-only check such as n <= 0 does not count), a FastAPI parameter declared with Query(le=...), constants, environment and settings values, len() of the input, test files, comments and strings. The rule is line-oriented: a limit enforced in another function or by a schema validator is not seen, and unbounded loops or queries driven by other sources are out of scope.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-400/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [400],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["resource-consumption", "cwe-400"],
}

_source_re := `\brequest\s*\.\s*(?:args|form|values|json|GET|POST|data|query_params|headers|cookies|get_json)\b`

_cast := `(?:(?:int|float|abs)\s*\(\s*)?`

_tok := `([A-Za-z_]\w*(?:\s*\.\s*\w+)*)`

# Each pattern captures the first token of the size/count argument.
_sink_res := [
	concat("", [`\b(?:range|sleep|bytearray|bytes|urandom|token_bytes|token_hex|token_urlsafe)\s*\(\s*`, _cast, _tok]),
	concat("", [`\.(?:zfill|ljust|rjust|center)\s*\(\s*`, _cast, _tok]),
	concat("", [`\b(?:np|numpy)\s*\.\s*(?:zeros|ones|empty|full|arange)\s*\(\s*\(?\s*`, _cast, _tok]),
	concat("", [`\brange\s*\(\s*[^,()]+,\s*`, _cast, _tok]),
	concat("", [`\.(?:read|recv)\s*\(\s*`, _cast, _tok]),
	concat("", [`(?:["'\]]|\])\s*\*\s*`, _cast, _tok]),
	concat("", [`\*\*\s*`, _cast, _tok]),
]

# the token before a repetition: n * "x"
_rev_sink_re := `\b([A-Za-z_]\w*)\s*\*\s*["'\[]`

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_sink_tokens(line) := {t |
	some re in _sink_res
	some m in regex.find_all_string_submatch_n(re, line, -1)
	t := m[1]
} | {t |
	some m in regex.find_all_string_submatch_n(_rev_sink_re, line, -1)
	t := m[1]
}

# the request value is the argument itself
_tainted_tok(t, _) if regex.match(`^request\s*\.\s*(?:args|form|values|json|GET|POST|data|query_params|headers|cookies|get_json)\b`, t)

_tainted_tok(t, names) if t in names

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "request")
	regex.match(_source_re, content)
	regex.match(`(?m)(?:\b(?:range|sleep|bytearray|bytes|urandom|token_bytes|token_hex|token_urlsafe|read|recv|zfill|ljust|rjust|center|zeros|ones|empty|full|arange)\s*\(|\*)`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _strip_strings(line)
	toks := _sink_tokens(code)
	count(toks) > 0
	names := helpers.tainted_names(lines, i, 10, _source_re)
	some t in toks
	_tainted_tok(t, names)
	not _bounded(lines, i, t)
	not _bounded_at_source(lines, i, t)
	finding := {
		"rule_id": metadata.id,
		"message": "A request-supplied number sets a loop count, sleep, allocation, repetition or exponent with no upper bound: one request can exhaust CPU, memory or the worker. Clamp it (min(value, LIMIT)) or reject large values first",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── FastAPI: a route parameter typed int/float with no le=/lt= bound ──────

_fastapi_route_re := `^\s*@\w+\s*\.\s*(?:get|post|put|patch|delete|api_route)\s*\(`

# The parameters of the route function enclosing line i: the nearest def
# above (within 30 lines) whose previous non-blank line is a route decorator,
# with every int/float parameter that carries no upper bound.
_fastapi_params(lines, i) := names if {
	defs := [j |
		some j in numbers.range(max([1, i - 30]), i - 1)
		regex.match(`^\s*(?:async\s+)?def\s+\w+\s*\(`, lines[j])
	]
	count(defs) > 0
	d := defs[count(defs) - 1]
	regex.match(_fastapi_route_re, lines[d - 1])
	names := {m[1] |
		some m in regex.find_all_string_submatch_n(`\b(\w+)\s*:\s*(?:int|float)\b\s*(=\s*(?:\w+\s*\([^()]*\)|[^,()]*))?`, lines[d], -1)
		not regex.match(`\b(?:le|lt)\s*=`, m[2])
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "fastapi")
	regex.match(`(?m)^\s*(?:from|import)\s+fastapi\b`, content)
	regex.match(concat("", ["(?m)", _fastapi_route_re]), content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	toks := _sink_tokens(_strip_strings(line))
	count(toks) > 0
	names := _fastapi_params(lines, i)
	some t in toks
	t in names
	not _bounded(lines, i, t)
	finding := {
		"rule_id": metadata.id,
		"message": "A request-supplied number sets a loop count, sleep, allocation, repetition or exponent with no upper bound: one request can exhaust CPU, memory or the worker. Bound the parameter (Query(le=...)) or clamp it first",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A bound on the variable in the lines between: an if comparison, min(), or
# a clamp reassignment.
_bounded(lines, i, v) if {
	not startswith(v, "request")
	some k in numbers.range(max([0, i - 10]), i - 1)
	k < i
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(concat("", [`\b(?:if|elif|while|assert)\b.*(?:\b`, v, `\b[^<>]*[<>]=?\s*(?:[A-Za-z_(]|\d{2,}|[2-9])|(?:\w{2,}|[2-9]|\))\s*[<>]=?[^<>]*\b`, v, `\b)|\bmin\s*\([^)]*\b`, v, `\b|\b`, v, `\s*=\s*(?:max|min|clamp)\w*\s*\(`]), l)
}

# The source line itself clamps: n = min(request.args.get(...), MAX)
_bounded_at_source(lines, i, v) if {
	not startswith(v, "request")
	some k in numbers.range(max([0, i - 10]), i - 1)
	k < i
	l := lines[k]
	regex.match(_source_re, l)
	helpers.assigned_first(l) == v
	regex.match(`=\s*min\s*\(`, l)
}
