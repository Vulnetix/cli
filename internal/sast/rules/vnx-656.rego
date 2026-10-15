# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_656

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-656",
	"name": "Reliance on Security Through Obscurity",
	"description": "A hidden request parameter, header or cookie with a hard-coded magic value unlocks privileges (CWE-656): an if/elif condition that compares a request value, request.args/form/values/GET/POST/cookies/COOKIES/headers/query_params/json in Python or req.query/body/params/cookies/signedCookies/headers, req.get()/header()/param() in JavaScript/TypeScript, directly or through a variable assigned from one a few lines above, with == or === to a non-empty string literal, and whose branch grants access directly: return next(), next() or await next(), login()/login_user(), a session admin/user/role/authenticated flag set, an is_admin/authenticated = True assignment, return True, or a decorator returning the wrapped view. Also reported without looking at the branch: the same literal comparison on a parameter, header or cookie whose name is itself a privilege (admin, is_admin, role, user_role, superuser, root, backdoor, bypass, override, god_mode, staff, privileged, optionally X-prefixed), because the client is then telling the server what it is allowed to do; that form is skipped when the condition also consults the server-side identity (req.user, request.user, current_user, session) or is negated, and when the branch rejects the request (403/401, abort, raise, throw) or only narrows a query filter (?role=admin in a user listing). The value is protected only by nobody knowing it, and it ships in the source. Not reported: a comparison whose branch only changes presentation (sort, format, language), a grant that follows a nested check (password hash, signature, timingSafeEqual), secrets read from configuration or the environment, != comparisons, client-address and Referer/X-Forwarded-For checks (VNX-654), test files, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-656/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [656],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["security-by-obscurity", "backdoor", "hidden-parameter", "cwe-656"],
}

_py_src := `\brequest\.(?:args|form|values|GET|POST|cookies|COOKIES|headers|query_params|json)\s*(?:\.get\(|\[)`

_js_src := `\breq(?:uest)?\.(?:query|body|params|cookies|signedCookies|headers)(?:\.\w+|\[\s*['"][^'"]+['"]\s*\])|\breq(?:uest)?\.(?:get|header|param)\(\s*['"]`

# Client-origin headers are VNX-654's subject.
_origin := `(?i)x-forwarded-for|x-real-ip|x-client-ip|true-client-ip|referr?er|remote_addr`

_src(path) := _py_src if endswith(path, ".py")

_src(path) := _js_src if not endswith(path, ".py")

_exts := {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".jsx", ".tsx"}

_cond := `^\s*(?:\}\s*else\s+)?(?:if|elif)\b`

_literal_eq := `===?\s*["'][^"'\s][^"']*["']|["'][^"'\s][^"']*["']\s*===?`

_grant := `return\s+(?:await\s+)?next\(\)|^\s*(?:await\s+)?next\(\)|\blogin(?:_user)?\s*\(|\bsession\[\s*["'](?:is_?admin|admin|authenticated|logged_?in|user(?:_id)?|role)["']\s*\]\s*=[^=]|\bsession\.(?:is_?admin|isAdmin|admin|authenticated|loggedIn|user|role)\s*=[^=]|\b(?:is_?admin|isAdmin|authenticated|authorized|logged_?in|loggedIn)\s*=\s*(?:True|true)\b|return\s+(?:True|true)\b|return\s+(?:f|func|fn|view|view_func|handler)\s*\(`

_verify := `(?i)check_password|verify|authenticate\s*\(|bcrypt|argon|compare|timingsafeequal|compare_digest|hmac`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_reads_param(path, lines, i, line) if regex.match(_src(path), line)

_reads_param(path, lines, i, line) if {
	some v in helpers.tainted_names(lines, i, 6, _src(path))
	regex.match(concat("", [`\b`, v, `\b`]), line)
}

_grants(lines, i, line) if regex.match(_grant, substring(line, indexof(line, "if"), -1))

# A grant directly in the branch: deeper than the condition, with no
# dedent, nested condition or verification between them.
_grants(lines, i, line) if {
	ind := _indent(line)
	end := min([count(lines) - 1, i + 4])
	some j in numbers.range(i + 1, end)
	trim_space(lines[j]) != ""
	not helpers.is_comment_line(lines[j])
	_indent(lines[j]) > ind
	regex.match(_grant, lines[j])
	not _interrupted(lines, i, j, ind)
}

_interrupted(lines, i, j, ind) if {
	i + 1 <= j - 1
	some k in numbers.range(i + 1, j - 1)
	trim_space(lines[k]) != ""
	_indent(lines[k]) <= ind
}

_interrupted(lines, i, j, _) if {
	i + 1 <= j - 1
	some k in numbers.range(i + 1, j - 1)
	regex.match(`^\s*(?:if|elif|for|while)\b`, lines[k])
}

_interrupted(lines, i, j, _) if {
	some k in numbers.range(i + 1, j)
	regex.match(_verify, lines[k])
}

_decides(path, lines, i, line) if {
	_reads_param(path, lines, i, line)
	_grants(lines, i, line)
}

# The parameter, header or cookie is itself named for a privilege, compared
# to a literal on the condition line: the client says who it is.
_decides(path, lines, i, line) if {
	some key in _keys(path, line)
	regex.match(_priv_key, key)
	not regex.match(_server_identity, line)
	not _branch_denies_or_filters(lines, i, line)
}

# The condition also asks the server who the caller is (a create-user form
# that refuses role=admin to non-admins): the parameter is data, not a key.
_server_identity := `(?i)\breq\.user\b|\brequest\.user\b|current_user|is_superuser|is_staff|\bsession\b|\bnot\s|!\s*[\w.(]`

# The branch rejects the request, or only narrows a query (?role=admin in a
# user listing).
_deny_or_filter := `(?i)\b(?:40[13]|forbidden|unauthori[sz]ed|abort\s*\(|raise\b|throw\b|permissiondenied)|^\s*\w*(?:filter|where|query|criteria|conditions|params)\w*(?:\.\w+|\[[^\]]+\])\s*=[^=]`

_branch_denies_or_filters(lines, i, line) if {
	regex.match(_deny_or_filter, substring(line, indexof(line, "if"), -1))
}

_branch_denies_or_filters(lines, i, line) if {
	j := helpers.next_code_index(lines, i, 3)
	_indent(lines[j]) > _indent(line)
	regex.match(_deny_or_filter, lines[j])
}

_priv_key := `(?i)^(?:x-)?(?:is_?admin|admin|role|user_?role|superuser|root|backdoor|bypass|override|god_?mode|staff(?:_mode)?|privileged?)$`

_key_re(path) := `\brequest\.(?:args|form|values|GET|POST|cookies|COOKIES|headers|query_params|json)\s*(?:\.get\(\s*|\[\s*)["']([^"']+)["']()` if endswith(path, ".py")

_key_re(path) := `\breq(?:uest)?\.(?:query|body|params|cookies|signedCookies|headers)(?:\.([A-Za-z_]\w*)|\[\s*['"]([^'"]+)['"]\s*\])` if not endswith(path, ".py")

_keys(path, line) := {k |
	some m in regex.find_all_string_submatch_n(_key_re(path), line, -1)
	some k in [m[1], m[2]]
	k != ""
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not helpers.is_test_path(path)
	regex.match(_src(path), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_cond, line)
	not helpers.is_comment_line(line)
	regex.match(_literal_eq, line)
	not regex.match(`!==?`, line)
	not regex.match(_origin, line)
	not regex.match(_verify, line)
	_decides(path, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "A hidden request parameter, header or cookie with a hard-coded value grants access: security through obscurity. Anyone who reads the code, a log or a proxy capture has the key; authenticate the caller instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
