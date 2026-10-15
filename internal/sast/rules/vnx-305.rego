# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_305

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-305",
	"name": "Authentication Bypass by Primary Weakness",
	"description": "An authentication check that only tests whether a credential is present and then lets the request through: a Node/Express middleware, a Python decorator, view or DRF permission, or a Java servlet filter or Spring interceptor reads a token, API key, Authorization header or session cookie from the request and grants access (next(), return f(*args), call_next, chain.doFilter(...), return True/true from an auth or permission method, or such a method returning the presence test itself, as in return bool(request.headers.get(\"Authorization\")) or return token != null) when the value is merely non-empty, or as the very next statement after rejecting an empty one, without verifying, decoding, comparing or looking it up. Any value then authenticates. Not reported: a check whose condition or intervening lines call verify/validate/decode/authenticate/lookup/compare, a token compared against an expected value, a variable assigned from a verification call, a value held in the server-side session store (req.session.user, session.getAttribute), client-side route guards (canActivate), test files and comments. Deeper flows (verification in another function between the read and the grant) are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-305/",
	"languages": ["java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [305],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["auth-bypass", "cwe-305"],
}

_exts := {".py", ".js", ".ts", ".mjs", ".cjs", ".java"}

_ext_ok(path) if {
	some e in _exts
	endswith(path, e)
}

_grant_gate := `(?m)(\bnext\(\s*\)|\bdoFilter\s*\(|\breturn\s+(await\s+)?(f|fn|func|view|view_func|wrapped|handler|get_response|call_next)\s*\(|\breturn\s+(True|true)\b)`

# A statement that lets the request continue.
_grant_re := `^\s*(?:return\s+)?(?:await\s+)?(?:next\(\s*\)|[\w.]*\.doFilter\s*\(|(?:f|fn|func|view|view_func|wrapped|handler|get_response|call_next)\s*\()`

_bool_grant_re := `^\s*return\s+(True|true)\s*;?\s*$`

# The subject of the condition: a name or a request accessor.
_subj := `[A-Za-z_$][\w$]*(?:\??\.[\w$]+|\[['"][\w-]+['"]\])*(?:\(\s*['"][\w-]+['"]\s*(?:,\s*['"][^'"]*['"]\s*)?\))?`

_extra := `(?:\s*(?:&&|and)\s*!?\s*[\w$.?]+\.(?:startsWith|startswith|isEmpty|isBlank|length|trim|strip)\b(?:\([^()]*\))?(?:\s*[<>=!]=?\s*\d+)?)?`

# if (token) / if (token != null) / if token: / if token is not None:
_pos_cond := concat("", [`^\s*(?:\}\s*else\s+)?(?:else\s+)?if\s*\(\s*(?:!!\s*)?(`, _subj, `)\s*(?:(?:!==?|!=)\s*(?:null|undefined|''|""))?`, _extra, `\s*\)\s*(\{?.*)$`])

_pos_cond_py := concat("", [`^\s*(?:el)?if\s+(`, _subj, `)\s*(?:is\s+not\s+None|!=\s*None|!=\s*['"]{2})?`, _extra, `\s*:\s*(.*)$`])

# if (!token) / if (token == null) / if not token: / if token is None:
_neg_cond := concat("", [`^\s*if\s*\(\s*(?:!\s*(`, _subj, `)|(`, _subj, `)\s*===?\s*(?:null|undefined|''|""))\s*\)`])

_neg_cond_py := concat("", [`^\s*if\s+(?:not\s+(`, _subj, `)|(`, _subj, `)\s*(?:is\s+None|==\s*None))\s*:`])

# The credential: a token, key, Authorization header or session cookie.
_credish := `(?i)(token|jwt|bearer|authorization|auth_?header|api[-_]?key|x-api-key|session|credential)`

_req_src := `(req|request|ctx|httpRequest|servletRequest)\.|getHeader\(|getCookies\(|getParameter\(|\bheaders\b|\bcookies\b|COOKIES|\bMETA\b`

# Anything that actually checks the credential.
_checks := `(?i)(verify|validat|decode|authenticat|introspect|lookup|compare|find\w*\(|\bcheck\w*\(|\.get\(\s*\w*token|matches\(|\.equals\(|===|==\s*[\w'"]|\bin\s+[\w.]*(tokens|sessions|keys|users)\b|parse\w*\(|jwt\.|jose|cache|redis|db\.|query\()`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_is_code(line) if {
	trim_space(line) != ""
	not helpers.is_comment_line(line)
}

# The subject is a credential read from the request: directly, or via a name
# assigned from the request within eight lines above, without verification.
_cred_subject(lines, i, subj) if {
	regex.match(_credish, subj)
	regex.match(_req_src, subj)
	not _server_session(subj)
}

_cred_subject(lines, i, subj) if {
	regex.match(`^[A-Za-z_$][\w$]*$`, subj)
	some j in numbers.range(max([0, i - 8]), i - 1)
	a := lines[j]
	regex.match(concat("", [`^\s*(?:(?:const|let|var|final|String|Optional<String>)\s+)?`, subj, `\s*=[^=]`]), a)
	_credish_read(subj, a)
	regex.match(_req_src, a)
	not regex.match(_checks, a)
	not _server_session(a)
}

# The name says it is a credential, or the read names a credential header,
# cookie or parameter (key = request.headers.get("X-API-Key")).
_credish_read(subj, a) if regex.match(_credish, subj)

_credish_read(subj, a) if regex.match(`(?i)((get|header|cookie|param)\w*\(\s*['"][\w-]*(token|jwt|authorization|api[-_]?key|auth)[\w-]*['"]|\[\s*['"][\w-]*(token|jwt|authorization|api[-_]?key|auth)[\w-]*['"]\s*\])`, a)

# A value held in the server-side session store (req.session.user,
# request.session["uid"], session.getAttribute) was put there by the server at
# login; testing that it exists is how session authentication works.
_server_session(s) if regex.match(`(?i)(\bsession\s*(\.|\[|\?\.)\s*['"]?\w|getSession\(|getAttribute\()`, s)

# `return true` is a grant only in an auth or permission method (DRF
# has_permission, Spring preHandle), not in a client-side route guard.
_grant(lines, k, i) if regex.match(_grant_re, lines[k])

_grant(lines, k, i) if {
	regex.match(_bool_grant_re, lines[k])
	_in_auth_method(lines, i)
}

_in_auth_method(lines, i) if {
	hdrs := [j |
		some j in numbers.range(max([0, i - 20]), i)
		regex.match(`^\s*(?:(?:public|private|protected|static|async|override|final)\s+)*(?:def\s+|boolean\s+|bool\s+|function\s+)?\w+\s*\([^;]*$`, lines[j])
		not regex.match(`^\s*(if|for|while|switch|catch|return|elif)\b`, trim_space(lines[j]))
	]
	count(hdrs) > 0
	h := lines[max(hdrs)]
	regex.match(`(?i)(def|boolean|bool)\s+\w*(auth|permission|prehandle|access|allowed)\w*\s*\(`, h)
}

# Positive form, grant on the same line: if (token) return next();
_pos_grant(lines, i, rest) := i if {
	r := trim_left(trim_space(rest), "{ ")
	r != ""
	regex.match(_grant_re, r)
}

# Positive form, grant as the first statement of the block.
_pos_grant(lines, i, rest) := k if {
	trim_left(trim_space(rest), "{ ") == ""
	k := helpers.next_code_index(lines, i, 3)
	_indent(lines[k]) > _indent(lines[i])
	_grant(lines, k, i)
}

# Negative form: the first statement after the rejecting block grants.
_neg_grant(lines, i) := k if {
	ind := _indent(lines[i])
	end := min([count(lines) - 1, i + 10])
	after := [j |
		some j in numbers.range(i + 1, end)
		_is_code(lines[j])
		_indent(lines[j]) <= ind
		not regex.match(`^\s*[\}\)]`, lines[j])
	]
	count(after) > 0
	k := after[0]
	not regex.match(`^\s*(else|elif|except|catch|finally)\b`, lines[k])
	_grant(lines, k, i)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Credential only checked for presence before access is granted: verify the token or key, do not just test that it exists",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_candidates(path, content) := lines if {
	_ext_ok(path)
	not helpers.is_test_path(path)
	regex.match(_grant_gate, content)
	lines := split(content, "\n")
}

findings contains finding if {
	some path, content in input.file_contents
	not endswith(path, ".py")
	lines := _candidates(path, content)
	some i, line in lines
	contains(line, "if")
	m := regex.find_all_string_submatch_n(_pos_cond, line, 1)
	count(m) > 0
	_cred_subject(lines, i, m[0][1])
	k := _pos_grant(lines, i, m[0][2])
	_unchecked_after(lines, i, k)
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	lines := _candidates(path, content)
	some i, line in lines
	contains(line, "if")
	m := regex.find_all_string_submatch_n(_pos_cond_py, line, 1)
	count(m) > 0
	_cred_subject(lines, i, m[0][1])
	k := _pos_grant(lines, i, m[0][2])
	_unchecked_after(lines, i, k)
	finding := _finding(path, i, line)
}

# An auth or permission method that returns the presence test itself:
# return bool(request.headers.get("Authorization")) / return token != null;
_ret_presence := concat("", [`^\s*return\s+(?:bool\(\s*(`, _subj, `)\s*\)|(`, _subj, `)\s*(?:is\s+not\s+None|!==?\s*(?:null|None|undefined)))\s*;?\s*$`])

findings contains finding if {
	some path, content in input.file_contents
	_ext_ok(path)
	not helpers.is_test_path(path)
	regex.match(`(?m)^\s*return\s+(bool\(|[\w.$]+\s*(!=|is\s+not))`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "return")
	m := regex.find_all_string_submatch_n(_ret_presence, line, 1)
	count(m) > 0
	subj := concat("", [m[0][1], m[0][2]])
	_cred_subject(lines, i, subj)
	_in_auth_method(lines, i)
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	lines := _candidates(path, content)
	some i, line in lines
	contains(line, "if")
	m := _neg_match(path, line)
	subj := concat("", [m[1], m[2]])
	_cred_subject(lines, i, subj)
	k := _neg_grant(lines, i)
	_unchecked_after(lines, i + 1, k)
	finding := _finding(path, k, lines[k])
}

_neg_match(path, line) := m[0] if {
	endswith(path, ".py")
	m := regex.find_all_string_submatch_n(_neg_cond_py, line, 1)
	count(m) > 0
}

_neg_match(path, line) := m[0] if {
	not endswith(path, ".py")
	m := regex.find_all_string_submatch_n(_neg_cond, line, 1)
	count(m) > 0
}

# No checking between the condition (exclusive of its own subject read) and
# the grant. The condition line itself is matched by the presence-only regex,
# so only the lines after it are inspected.
_unchecked_after(lines, i, k) if k <= i

_unchecked_after(lines, i, k) if {
	k > i
	not _checked_in(lines, i + 1, k)
}

_checked_in(lines, a, b) if {
	some j in numbers.range(a, b)
	_is_code(lines[j])
	regex.match(_checks, lines[j])
}
