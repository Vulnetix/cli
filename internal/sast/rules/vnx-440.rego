# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_440

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-440",
	"name": "Expected Behavior Violation",
	"description": "A Python check that the code relies on is written as an assert statement in production code, and assert does not behave as expected there: python -O and PYTHONOPTIMIZE strip every assert, so the check silently stops running. Reported, outside test files: an assert whose condition is an authentication, authorisation or integrity decision (is_authenticated, is_admin, is_superuser, is_staff, is_active, has_perm/has_permission/has_role, is_owner, can_*, check_password, verify*/is_valid*, compare_digest, or a name containing authorized, allowed, permission, csrf, signature or password, or a qualified token name such as api_token, auth_token, access_token or session_token, in the condition itself, not in the message; a parenthesised condition spread over the following lines is read up to its closing parenthesis); and assert False / assert 0 / assert None used to stop an unreachable or forbidden branch, which under -O falls through and carries on. Not reported: asserts in test files (tests/, test_*.py, *_test.py, conftest.py), type-narrowing asserts (an isinstance(...) call is ignored, so assert isinstance(u, User) alone is quiet but assert isinstance(u, User) and u.is_admin is reported), inspect.signature() checks, parser asserts on bare token/tokens, other asserts, the words appearing only in the assert message or a comment, raise AssertionError(...). An assert on request data is VNX-617.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-440/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [440],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["unexpected-behavior", "assert", "python-optimize", "cwe-440"],
}

_test_file(path) if helpers.is_test_path(path)

_test_file(path) if regex.match(`(^|/)conftest\.py$`, path)

_test_file(path) if regex.match(`(^|/)tests?[^/]*\.py$`, path)


# The assert's condition text: the rest of the line, or, for `assert (` with
# the condition on the following lines, those lines up to the closing `)`.
_raw_condition(lines, i) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*assert(?:\s+|\s*(?:\())(.*)$`, lines[i], 1)
	count(m) > 0
	not regex.match(`^\s*assert\s*\(\s*(?:#.*)?$`, lines[i])
}

_raw_condition(lines, i) := concat(" ", [lines[k] | some k in numbers.range(i + 1, close - 1)]) if {
	regex.match(`^\s*assert\s*\(\s*(?:#.*)?$`, lines[i])
	closes := [k | some k in numbers.range(i + 1, min([count(lines) - 1, i + 8])); regex.match(`^\s*\)`, lines[k])]
	count(closes) > 0
	close := closes[0]
}

# String literals blanked, comments dropped, the message (a string after the
# last comma, possibly %-formatted) removed, and calls that only look like
# security words (isinstance(...), inspect.signature(...)) taken out.
_condition(lines, i) := c if {
	raw := _raw_condition(lines, i)
	s := regex.replace(raw, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, `""`)
	s2 := regex.replace(s, `\s*#[^\n]*`, "")
	s3 := regex.replace(s2, `,\s*[frbuFRBU]*""(?:\s*(?:%|\.format\().*)?\s*\\?$`, "")
	s4 := regex.replace(s3, `\bisinstance\s*\([^()]*\)`, " ")
	c := regex.replace(s4, `(?:\binspect\s*\.\s*|(?:^|[^\w.]))signature\s*\(`, " (")
}

_security_re := `(?i)(?:\b(?:is_authenticated|is_anonymous|is_admin|is_superuser|is_staff|is_active|has_perms?|has_permission|has_role|is_owner|check_password|compare_digest)\b|\bcan_\w+|\bverify\w*|\bis_valid\w*|authori[sz]ed|allowed|permission|csrf|xsrf|signature|(?:api|auth|access|refresh|bearer|session|secret|reset|jwt|id)_?tokens?\b|password)`

_reason(1, lines, i) := "This assert is an authentication or authorisation check: python -O and PYTHONOPTIMIZE remove it, and the code proceeds as if it had passed. Raise an exception (PermissionDenied, abort(403)) instead" if {
	c := _condition(lines, i)
	regex.match(_security_re, c)
}

_reason(2, lines, i) := "assert False stops this branch only when assertions are enabled: under python -O it is removed and execution falls through into code that was meant to be unreachable. Raise an exception (raise RuntimeError/AssertionError(...)) instead" if regex.match(`^\s*assert\s+(?:False|0|None)\s*(?:,|#|$)`, lines[i])

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not _test_file(path)
	contains(content, "assert")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "assert")
	regex.match(`^\s*assert(?:\s|\()`, line)
	some k in [1, 2]
	msg := _reason(k, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
