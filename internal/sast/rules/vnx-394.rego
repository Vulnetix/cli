# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_394

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-394",
	"name": "Unexpected Status Code or Return Value",
	"description": "Python code consumes a result without checking the status that says whether it is the result it expects. Reported: the body of an HTTP response from requests, httpx, an alias (import requests as rq), a session (also self.session) or, in a module importing httpx, a *client (.get/.post/.put/.patch/.delete/.head/.request) read with .json(), .text or .content, either chained on the call or from the variable it was assigned to (or bound by with ... as resp:) within the next 12 lines, when no line in between checks raise_for_status(), status_code, .ok or .status, or tests the response itself; an error page or a 4xx/5xx JSON body is then processed as data. Also reported: a slice indexed directly by str.find()/rfind() of the same string (s[s.find(':') + 1:], s[:s.find('-')]), which silently returns the wrong substring when find returns -1. Not reported: a checked response, a SQLAlchemy session.get(Model, pk) lookup, a module whose session installs a raise_for_status response hook, s[s.rfind(sep) + 1:] (the after-last-separator idiom, correct when -1), a cache or dict .get(), soup.find(), a find() result tested before use or guarded by an 'in' test on the line above, test files, comments and docstrings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-394/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [394],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["status-code", "cwe-394"],
}

_http_methods := `\s*\.\s*(?:get|post|put|patch|delete|head|request)\s*\(`

# Receivers of an HTTP call: requests, httpx, a *session, an alias from
# "import requests as rq", and (in a module importing httpx) a *client.
_aliases(content) := [m[1] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+(?:requests|httpx)\s+as\s+(\w+)`, content, -1)
]

_clients(content) := [`\w*client`] if regex.match(`(?m)^\s*(?:import|from)\s+httpx\b`, content)

else := []

_http_call(content) := concat("", [
	`\b(?:`,
	concat("|", array.concat(array.concat(["requests", "httpx", `\w*session`], _aliases(content)), _clients(content))),
	`)`,
	_http_methods,
])

# A session-wide hook that raises on every error response checks them all.
_raising_hook(content) if regex.match(`hooks[^\n]*raise_for_status`, content)

_in_docstring(lines, i) if {
	above := concat("\n", array.slice(lines, 0, i))
	n := count(indexof_n(above, `"""`)) + count(indexof_n(above, "'''"))
	n % 2 == 1
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

_msg_http := "HTTP response body used without checking its status: an error page or error JSON is processed as data. Call raise_for_status() or check status_code/ok first"

# ── response assigned, then consumed unchecked ─────────────────────────

# resp = requests.get(...)
_resp_var(line, call) := helpers.assigned_first(line) if {
	regex.match(concat("", [`^\s*\w+\s*=\s*(?:await\s+)?(?:\w+\.)*`, call]), line)
}

# with requests.get(..., stream=True) as resp:
_resp_var(line, call) := m[0][1] if {
	not regex.match(concat("", [`^\s*\w+\s*=\s*(?:await\s+)?(?:\w+\.)*`, call]), line)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:async\s+)?with\s+(?:await\s+)?(?:\w+\.)*`, call, `.*\bas\s+(\w+)\s*:\s*$`]), line, 1)
	count(m) > 0
}

# SQLAlchemy Session.get(Model, pk) is a database lookup, not an HTTP call.
_orm_get(line) if regex.match(`session\s*\.\s*get\s*\(\s*[A-Z][a-z]\w*\s*,`, line)

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`requests|httpx`, content)
	call := _http_call(content)
	regex.match(concat("", ["(?m)", call]), content)
	not _raising_hook(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	v := _resp_var(line, call)
	not _orm_get(line)
	not _in_docstring(lines, i)
	use_re := concat("", [`\b`, v, `\s*\.\s*(?:json\s*\(|text\b|content\b)`])
	uses := [k |
		some k in numbers.range(i + 1, min([count(lines) - 1, i + 12]))
		k > i
		not helpers.is_comment_line(lines[k])
		regex.match(use_re, lines[k])
	]
	count(uses) > 0
	u := uses[0]
	not _checked(lines, i, u, v)
	f := _finding(path, u, lines[u], _msg_http)
}

# A status check, a test of the response, or a reassignment between the call
# and the use.
_checked(lines, i, u, v) if {
	some k in numbers.range(i, u)
	not helpers.is_comment_line(lines[k])
	regex.match(concat("", [`\b`, v, `\s*\.\s*(?:raise_for_status|status_code|ok\b|status\b|is_success|is_error)|\b(?:if|elif|assert|while)\s+(?:not\s+)?`, v, `\b|\bif\s+.*\b`, v, `\s*(?:is\s+None|==|!=)`]), lines[k])
}

_checked(lines, i, u, v) if {
	some k in numbers.range(i + 1, u)
	k < u
	regex.match(concat("", [`^\s*`, v, `\s*=[^=]`]), lines[k])
}

# ── chained: requests.get(...).json() ──────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`requests|httpx`, content)
	call := _http_call(content)
	regex.match(concat("", ["(?m)", call]), content)
	not _raising_hook(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(concat("", [call, `[^\n]*\)\s*\.\s*(?:json\s*\(|text\b|content\b)`]), line)
	not helpers.is_comment_line(line)
	not regex.match(`raise_for_status`, line)
	not _orm_get(line)
	not _in_docstring(lines, i)
	f := _finding(path, i, line, _msg_http)
}

# ── s[s.find(x) ...] ───────────────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "find(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "find(")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(`(\w+)\s*\[\s*(?::\s*)?(\w+)\s*\.\s*(r?find)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*(\+\s*1\s*:)?`, line, -1)
	m[1] == m[2]

	# s[s.rfind("/") + 1:] is the idiom for "after the last separator, or
	# the whole string": -1 + 1 is 0, which is the intended answer.
	not _rfind_plus_one(m)
	not _membership_guard(lines, i, m[1])
	not _in_docstring(lines, i)
	f := _finding(path, i, line, "str.find()/rfind() result used directly as a slice index: when the substring is absent it returns -1 and the slice silently yields the wrong text. Check for -1 (or use index()/partition()) first")
}

_membership_guard(lines, i, s) if {
	some k in numbers.range(max([0, i - 3]), i)
	regex.match(concat("", [`\bif\s+.*\bin\s+`, s, `\b`]), lines[k])
}

_rfind_plus_one(m) if {
	m[3] == "rfind"
	m[5] != ""
}
