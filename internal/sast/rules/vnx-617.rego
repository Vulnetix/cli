# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_617

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-617",
	"name": "Reachable Assertion",
	"description": "Reports a Python assert statement in application code that validates request data or enforces an access decision: the asserted expression reads the request (request.form/args/values/json/data/GET/POST/FILES/headers/cookies/user/META/query_params/session/method, Flask, Django, FastAPI and Starlette alike), a variable assigned from one in the 10 lines above, a FastAPI parameter bound with Header/Query/Cookie/Form/Body/Path/File(...) or Annotated[..., Header()] in the 10 lines above, or a permission predicate (.is_authenticated, .is_superuser, .is_staff, .is_admin, .has_perm(s), .has_permission, .has_role, check_password/verify_password, can_<view|edit|delete|access|manage|...>(...) or any can_*(user|request|current_user, ...), is_authorized/is_allowed/check_permission/verify_token). A caller can reach the assertion and crash the request with AssertionError, and under python -O the check is removed entirely, so the validation or authorisation silently disappears. Multi-line assert ( ... ) expressions are read. Not reported: can_* helpers that are not about a user (can_connect(host), can_retry(n)), test files and conftest.py (assert is how tests check), internal invariants (isinstance(request, ...), x is not None, len(x) > 0), checks that raise an exception, assert text inside comments, strings and docstrings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-617/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [617],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["assertion", "cwe-617"],
}

_req := `\brequest\.(?:form|args|values|json|data|GET|POST|FILES|headers|cookies|COOKIES|user|META|query_params|path_params|session|get_json|method|body|content_length|remote_addr|params|match_info)\b`

_perm := `\.(?:is_authenticated|is_superuser|is_staff|is_admin|has_perms?|has_permission|has_role|is_owner)\b|\b(?:check_password|verify_password|is_authorized|is_allowed|check_permission|verify_token|validate_token)\s*\(|\bcan_(?:view|edit|delete|access|read|write|modify|manage|create|update|admin|approve|see|publish|change|add|remove|download|upload|invite|transfer)\w*\s*\(|\bcan_[a-z]\w*\s*\(\s*(?:self\.)?(?:request\.user|current_user|g\.user|user|request)\b`

_strip(s) := regex.replace(regex.replace(s, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`)

# The asserted expression: the line, plus its continuation lines when it opens
# a parenthesis it does not close.
_expr(lines, i) := _strip(lines[i]) if not regex.match(`\(\s*$`, lines[i])

_expr(lines, i) := e if {
	regex.match(`\(\s*$`, lines[i])
	end := min([count(lines) - 1, i + 5])
	e := _strip(concat(" ", array.slice(lines, i, end + 1)))
}

_in_docstring(lines, i) if {
	prefix := concat("\n", array.slice(lines, 0, i))
	n := count(regex.find_all_string_submatch_n(`"""|'''`, prefix, -1))
	n % 2 == 1
}

_validates(lines, i, e) if regex.match(_req, e)

_validates(lines, i, e) if regex.match(_perm, e)

_validates(lines, i, e) if {
	some v in helpers.tainted_names(lines, i, 10, _req)
	regex.match(concat("", [`\b`, v, `\b`]), e)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	not endswith(path, "conftest.py")
	regex.match(`(?m)^\s*assert[\s(]`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "assert")
	regex.match(`^\s*assert[\s(]`, line)
	e := _expr(lines, i)
	not regex.match(`^\s*assert\s+\(?\s*[A-Za-z_][\w.]*\s+is\s+not\s+None\s*\)?\s*(?:,|$)`, e)
	_validates(lines, i, e)
	not _in_docstring(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "assert used to validate request data or enforce access: a caller can trigger AssertionError, and python -O removes the check. Raise an explicit exception (PermissionDenied, ValueError, abort(403)) instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# FastAPI parameters bound from the request (x: str = Header(...),
# x: Annotated[int, Query()]) in the 10 lines above.
_param_re := `\b([a-z_]\w*)\s*:\s*(?:[\w.]+(?:\[[^\]=]*\])?\s*=\s*(?:fastapi\.)?(?:Header|Query|Cookie|Form|Body|Path|File)\s*\(|Annotated\[[^\]]*\b(?:Header|Query|Cookie|Form|Body|Path|File)\s*\()`

_validates(lines, i, e) if {
	some k in numbers.range(max([0, i - 10]), i - 1)
	regex.match(`\b(?:Header|Query|Cookie|Form|Body|Path|File)\s*\(`, lines[k])
	some m in regex.find_all_string_submatch_n(_param_re, lines[k], -1)
	regex.match(concat("", [`\b`, m[1], `\b`]), e)
}
