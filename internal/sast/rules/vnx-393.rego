# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_393

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-393",
	"name": "Return of Wrong Status Code",
	"description": "A Java catch block reports success for an operation that just failed. Reported, inside the body of a catch: an HTTP success response (return ResponseEntity.ok(...), ResponseEntity.status(HttpStatus.OK), new ResponseEntity<>(..., HttpStatus.OK), JAX-RS Response.ok(...) or Response.status(Response.Status.OK), or HttpServletResponse.setStatus(200 / SC_OK)), and return true; in a boolean or Boolean method whose name makes a security or validity decision (verify*, validate*, authenticate*, authorize*, checkPermission/Access/Signature/Token/Password*, hasPermission/hasAccess/canAccess, isValid/isAuthorized/isAuthenticated/isAllowed/isPermitted/isTrusted/isVerified/isSecure/isSafe*, and is*Valid/is*Authorized/is*Allowed/is*Verified names such as isTokenValid), which fails open. A return broken after ResponseEntity or Response (return ResponseEntity\n.ok()) is joined. Not reported: a catch that returns an error status (badRequest, status(INTERNAL_SERVER_ERROR), sendError, 4xx/5xx), return false, return true from a method whose name is not such a decision (isRetryable, deleteQuietly) or is negated (isNotAllowed, which fails closed), success statuses outside a catch, test files and comments. Exceptions whose success answer is intended (an idempotent delete returning 204/200) need a review rather than a rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-393/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [393],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["error-handling", "cwe-393"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_success_http_re := `(?:\breturn\s+ResponseEntity\s*\.\s*ok\s*\(|\bResponseEntity\s*\.\s*status\s*\(\s*(?:HttpStatus\.OK|200)\s*\)|\bnew\s+ResponseEntity\s*<[^>]*>\s*\((?:[^;]*,\s*)?HttpStatus\.OK\s*\)|\breturn\s+(?:javax\.ws\.rs\.core\.|jakarta\.ws\.rs\.core\.)?Response\s*\.\s*(?:ok\s*\(|status\s*\(\s*(?:(?:javax\.ws\.rs\.core\.|jakarta\.ws\.rs\.core\.)?Response\.Status\.OK|Status\.OK|200)\s*\))|\.setStatus\s*\(\s*(?:200|(?:HttpServletResponse\.)?SC_OK|HttpStatus\.OK\.value\(\))\s*\))`

_decision_name_re := `^(?:is\w*(?:Valid|Authori[sz]ed|Authenticated|Allowed|Permitted|Trusted|Verified)|(?:is|has|can)(?:Valid|Authori[sz]ed|Authenticated|Allowed|Permitted|Trusted|Verified|Secure|Safe)\w*|verify\w*|validate\w*|authenticate\w*|authori[sz]e\w*|check(?:Permission|Access|Signature|Token|Auth|Password|Credential)\w*|hasPermission\w*|hasAccess\w*|canAccess\w*)$`

# The enclosing method's name: the nearest boolean method declaration above.
_method_name(lines, i) := name if {
	decls := [j |
		some j in numbers.range(max([0, i - 80]), i)
		regex.match(`^\s*(?:(?:public|protected|private|static|final|synchronized)\s+)*(?:boolean|Boolean)\s+\w+\s*\(`, lines[j])
	]
	count(decls) > 0
	d := decls[count(decls) - 1]
	m := regex.find_all_string_submatch_n(`\b(?:boolean|Boolean)\s+(\w+)\s*\(`, lines[d], 1)
	name := m[0][1]
}

_success(line, _, _) if regex.match(_success_http_re, line)

# A return statement broken across lines: return ResponseEntity\n  .ok()
_success(line, lines, i) if {
	regex.match(`^\s*return\s+[\w.]*(?:ResponseEntity|Response)\s*$`, line)
	nxt := concat(" ", [line, lines[i + 1]])
	regex.match(_success_http_re, nxt)
}

_success(line, lines, i) if {
	regex.match(`^\s*return\s+true\s*;`, line)
	name := _method_name(lines, i)
	regex.match(_decision_name_re, name)

	# isNotAllowed returning true fails closed
	not regex.match(`^(?:is|has|can)(?:Not|Never)[A-Z]`, name)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "catch")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "catch")
	regex.match(`^\s*(?:\}\s*)?catch\s*\(`, line)
	ic := _indent(line)
	ends := [k |
		some k in numbers.range(i + 1, min([count(lines) - 1, i + 15]))
		k > i
		_indent(lines[k]) <= ic
		startswith(trim_space(lines[k]), "}")
	]
	count(ends) > 0
	some j in numbers.range(i + 1, ends[0] - 1)
	j > i
	j < ends[0]
	body := lines[j]
	not helpers.is_comment_line(body)
	_success(body, lines, j)
	finding := {
		"rule_id": metadata.id,
		"message": "A catch block reports success for an operation that failed: the caller (or HTTP client) cannot tell the error happened. Return an error status or false, or rethrow",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": body,
	}
}
