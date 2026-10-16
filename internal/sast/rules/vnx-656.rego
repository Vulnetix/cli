# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_656

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-656",
	"name": "Reliance on Security Through Obscurity",
	"description": "A hidden request parameter, header or cookie with a hard-coded magic value unlocks privileges (CWE-656): an if/elif condition that compares a request value, request.args/form/values/GET/POST/cookies/COOKIES/headers/query_params/json in Python or req.query/body/params/cookies/signedCookies/headers, req.get()/header()/param() in JavaScript/TypeScript, directly or through a variable assigned from one a few lines above, with == or === to a non-empty string literal, and whose branch grants access directly: return next(), next() or await next(), login()/login_user(), a session admin/user/role/authenticated flag set, an is_admin/authenticated = True assignment, return True, or a decorator returning the wrapped view. Also reported without looking at the branch: the same literal comparison on a parameter, header or cookie whose name is itself a privilege (admin, is_admin, role, user_role, superuser, root, backdoor, bypass, override, god_mode, staff, privileged, optionally X-prefixed), because the client is then telling the server what it is allowed to do; that form is skipped when the condition also consults the server-side identity (req.user, request.user, current_user, session) or is negated, and when the branch rejects the request (403/401, abort, raise, throw) or only narrows a query filter (?role=admin in a user listing). The value is protected only by nobody knowing it, and it ships in the source. Not reported: a comparison whose branch only changes presentation (sort, format, language), a grant that follows a nested check (password hash, signature, timingSafeEqual), secrets read from configuration or the environment, != comparisons, client-address and Referer/X-Forwarded-For checks (VNX-654), test files, comments and string literals. A cookie named for a privilege or login state compared on its line, or through a variable assigned from it, is reported by VNX-784 (a security decision on a cookie) and not here.",
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
	some k in helpers.span(i + 1, j - 1)
	trim_space(lines[k]) != ""
	_indent(lines[k]) <= ind
}

_interrupted(lines, i, j, _) if {
	i + 1 <= j - 1
	some k in helpers.span(i + 1, j - 1)
	regex.match(`^\s*(?:if|elif|for|while)\b`, lines[k])
}

_interrupted(lines, i, j, _) if {
	some k in numbers.range(i + 1, j)
	regex.match(_verify, lines[k])
}

_decides(path, lines, i, line) if {
	_reads_param(path, lines, i, line)
	not regex.match(_server_session, line)
	_grants(lines, i, line)
}

# A condition joined with a check of the server-side user or session is a
# check of who the caller is, not a hidden key.
_server_session := `(?i)(?:&&|\band\b|\|\|\s*)\s*!*\(?\s*(?:(?:req|request)\.(?:user|session)\b|current_user)|(?:req|request)\.(?:user|session)\b[^\n]*(?:&&|\band\b)\s*[\w.]*(?:==|===)|current_user\.\w+\s*(?:&&|\band\b)`

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
_deny_or_filter := `(?i)\b(?:40[13]|forbidden|unauthori[sz]ed|abort\s*\(|raise\b|throw\b|permissiondenied)|^\s*\w+\s*=\s*[\w.]+\.(?:filter|filter_by|where|exclude|find|order_by)\w*\(|^\s*\w*(?:filter|where|query|criteria|conditions|params)\w*(?:\.\w+|\[[^\]]+\])\s*=[^=]`

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
	not _c784_owned(path, lines, i, line)
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

# ── Lines VNX-784 reports ───────────────────────────────────────────────
# A raw read of a cookie named for a privilege or login state that is
# compared or tested on its line, or assigned to a variable a condition uses
# within the next 15 lines, is a security decision on a cookie: VNX-784
# (CWE-784) reports it, so this rule leaves the line to it. This mirrors
# VNX-784's Python, JavaScript/TypeScript and PHP reads.
_c784_lang(path) := "py" if endswith(path, ".py")

_c784_lang(path) := "js" if regex.match(`\.(?:js|mjs|cjs|jsx|ts|tsx|mts|cts)$`, path)

_c784_lang(path) := "php" if endswith(path, ".php")

_c784_priv := {
	"admin", "isadmin", "adminmode", "role", "roles", "userrole", "staff", "isstaff",
	"superuser", "issuperuser", "isroot", "privilege", "privileges", "accesslevel",
	"userlevel", "authlevel", "usertype", "accounttype", "usergroup", "loggedin",
	"isloggedin", "authenticated", "isauthenticated", "authorized", "isauthorized",
	"permission", "permissions",
}

_c784_reads := {
	"py": [
		`\b\w*request\.(?:COOKIES|cookies)(?:\.get\(\s*["']([\w-]+)["']|\[\s*["']([\w-]+)["']\s*\])`,
		`\.get_cookie\(\s*["']([\w-]+)["']`,
		`["']([\w-]+)["']\s+(?:not\s+)?in\s+\w*request\.(?:COOKIES|cookies)\b`,
	],
	"js": [
		`\b(?:req|request|ctx|ctx\.request)\.cookies(?:\.get\(\s*["']([\w-]+)["']|\[\s*["']([\w-]+)["']\s*\]|\.([A-Za-z_$][\w$]*)\b)`,
		`\bcookies\(\)\.get\(\s*["']([\w-]+)["']`,
	],
	"php": [
		`\$_COOKIE\[\s*["']([\w-]+)["']\s*\]`,
		`\bfilter_input\(\s*INPUT_COOKIE\s*,\s*["']([\w-]+)["']`,
	],
}

_c784_owned(path, lines, i, line) if {
	lang := _c784_lang(path)
	contains(lower(line), "cookie")
	not helpers.is_comment_line(line)
	not regex.match(`\bsigned\s*:\s*true\b|\bsecret\s*=`, line)
	some re in _c784_reads[lang]
	some m in regex.find_all_string_submatch_n(re, line, -1)
	ns := [g | some j, g in m; j > 0; g != ""]
	count(ns) > 0
	regex.replace(lower(ns[0]), `[_-]`, "") in _c784_priv
	idx := indexof(line, m[0])
	prefix := substring(line, 0, idx)
	not _c784_in_string(prefix)
	_c784_report(lines, i, line, prefix, substring(line, idx + count(m[0]), -1))
}

_c784_in_string(prefix) if {
	some q in {`"`, "'", "`"}
	n := count(indexof_n(prefix, q)) - count(indexof_n(prefix, concat("", [`\`, q])))
	n % 2 == 1
}

_c784_report(_, _, _, prefix, suffix) if _c784_decides(prefix, suffix)

_c784_report(lines, i, line, prefix, suffix) if {
	not _c784_decides(prefix, suffix)
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:var|let|const|final|my)\s+|[A-Za-z_][\w<>\[\]*.]*\s+)?(\$?[A-Za-z_]\w*)\s*(?:,\s*\w+\s*)*(?::\s*\w+\s*)?(?::=|=)[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
	end := min([count(lines) - 1, i + 15])
	end >= i + 1
	ve := replace(v, "$", `\$`)
	some k in numbers.range(i + 1, end)
	l := lines[k]
	not helpers.is_comment_line(l)
	contains(l, trim_left(v, "$"))
	regex.match(concat("", [
		`(?:^|[\s(])(?:if|elif|elsif|unless|while|when|case|switch)\b[^\n]*(?:^|[^\w$])`, ve, `\b`,
		`|(?:^|[^\w$])`, ve, `\b(?:\.Value)?\s*(?:===?|!==?)`,
		`|(?:===?|!==?|\.equals\()\s*`, ve, `\b`,
	]), l)
}

_c784_decides(prefix, suffix) if {
	regex.match(`^\s*(?:\)\s*)?(?:===?|!==?|>=?|<=?|\.equals\(|\?[^?.])`, suffix)
	not regex.match(`\b(?:isset|empty|array_key_exists)\s*\(\s*$`, prefix)
}

_c784_decides(prefix, _) if regex.match(`(?:===?|!==?|\.equals\(|\bin_array\()\s*$`, prefix)

_c784_decides(prefix, _) if regex.match(`(?:(?:^|[\s(])(?:if|elif|elsif|unless|while|and|or|not)|&&|\|\|)\s*\(?\s*!?\s*$`, prefix)
