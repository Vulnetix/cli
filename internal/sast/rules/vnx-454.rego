# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_454

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-454",
	"name": "External Initialization of Trusted Variables or Data Stores",
	"description": "Python (Flask, Django, Starlette) code initialises authorisation state from values the client controls. Reported: a request cookie or header whose key names a privilege or authentication state (admin, is_admin, is_staff, superuser, authenticated, logged_in, verified, trusted, role, user_role, access_level, permissions, including X-/HTTP_X_ header spellings) read anywhere; a query/form parameter with such a flag key tested in an if/elif condition; a session key of that kind (is_admin, role, permissions...) assigned from request data, directly or through a variable assigned from it in the 8 lines above; and a variable or attribute named as a trust flag (is_admin, g.authenticated, staff, verified...) assigned from a request cookie, header or query parameter, directly or through such a variable. Not reported: server-side state (request.user, current_user, session.get, a database user), a privileged form field stored by an admin view, lookalike keys (admin_email), settings read from os.environ, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-454/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [454],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["external-initialization", "cwe-454", "access-control"],
}

# Trust words: boolean authorisation flags, and the role/permission words.
_flag := `(?:is[-_]?|has[-_]?)?(?:admin|administrator|superuser|super[-_]?user|staff|privileged|authenticated|authorized|authorised|logged[-_]?in|loggedin|verified|trusted|authed)`

_role := `(?:user[-_]?)?(?:roles?|access[-_]?level|privileges?|permissions?|perms)`

_get := `(?:\.get\(\s*|\[\s*)`

# Client-held request state: cookies and headers.
_client := `request\.(?:cookies|COOKIES|headers|META)`

# Request parameters: query string and body.
_param := `request\.(?:args|form|values|GET|POST|REQUEST|query_params|json|data)`

_any_request := `request\.(?:cookies|COOKIES|headers|META|args|form|values|GET|POST|REQUEST|query_params|json|data|get_json\(|params)`

# A cookie or header whose key is a trust word.
_client_key_re := concat("", [_client, _get, `["'](?i:(?:http_)?(?:x[-_])?(?:`, _flag, `|`, _role, `))["']`])

# A query/form parameter whose key is a boolean trust flag.
_param_flag_re := concat("", [_param, _get, `["'](?i:(?:x[-_])?`, _flag, `)["']`])

_session_key_re := concat("", [`\bsession\[\s*["'](?i:`, _flag, `|`, _role, `)["']\s*\]\s*=[^=]`])

_flag_var_re := concat("", [`^\s*(?:(?:self|g|flask\.g|request\.state)\.)?(?i:`, _flag, `)\s*(?::\s*bool\s*)?=[^=]`])

_flag_source := `request\.(?:cookies|COOKIES|headers|META|args|GET|query_params)`

_report(_, line) if regex.match(_client_key_re, line)

_report(ctx, line) if {
	regex.match(`^\s*(?:el)?if\b`, line)
	regex.match(_param_flag_re, line)
	not _filters_listing(ctx)
}

# `if request.GET.get("verified"): qs = qs.filter(...)` narrows a listing; the
# parameter is a search filter, not an access decision.
_filters_listing(ctx) if {
	lines := ctx[0]
	k := helpers.next_code_index(lines, ctx[1], 3)
	regex.match(`\.(?:filter|exclude|filter_by|where|order_by)\s*\(`, lines[k])
}

# The request access sits only inside a string literal (a message, a note).
_only_in_string(line) if {
	contains(line, "request.")
	not contains(regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`), "request.")
}

_report(_, line) if {
	regex.match(_session_key_re, line)
	regex.match(_any_request, _rhs(line))
}

_report(ctx, line) if {
	regex.match(_session_key_re, line)
	_tainted_rhs(ctx, line, _any_request)
}

_report(_, line) if {
	regex.match(_flag_var_re, line)
	regex.match(_flag_source, _rhs(line))
}

_report(ctx, line) if {
	regex.match(_flag_var_re, line)
	_tainted_rhs(ctx, line, _flag_source)
}

_rhs(line) := substring(line, indexof(line, "=") + 1, -1)

# A name assigned from a request source in the 8 lines above, read on the
# right-hand side of this assignment.
_tainted_rhs(ctx, line, src) if {
	lines := ctx[0]
	i := ctx[1]
	i > 0
	rhs := _rhs(line)
	some j in numbers.range(max([0, i - 8]), i - 1)
	prev := lines[j]
	contains(prev, "request")
	regex.match(src, prev)
	not helpers.is_comment_line(prev)

	# a flag assigned from the request is reported where it is assigned
	not regex.match(_flag_var_re, prev)
	m :=regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*=[^=]`, prev, 1)
	count(m) > 0
	regex.match(concat("", [`\b`, m[0][1], `\b`]), rhs)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "request")
	regex.match(`(?i)admin|staff|superuser|authenticated|authori[sz]ed|logged|verified|trusted|authed|role|access.?level|privilege|permission|perms`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`request\.|=`, line)
	not helpers.is_comment_line(line)
	not _only_in_string(line)
	_report([lines, i], line)
	finding := {
		"rule_id": metadata.id,
		"message": "Authorisation state is initialised from a value the client controls (cookie, header or request parameter); derive privileges from server-side state such as the authenticated user record",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
