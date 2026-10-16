# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_863

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-863",
	"name": "Incorrect Authorization",
	"description": "An authorization decision that is made the wrong way. Reported in Python and JavaScript/TypeScript: (1) a condition (if/elif, ternary, &&/||) that grants or denies by a value the client controls, a request header, cookie or Django META entry (request.COOKIES.get('admin') == \"1\", req.headers['x-role'] === 'admin', request.META.get('HTTP_X_IS_STAFF')), or a query parameter whose name says admin/role/staff/permission (req.query.admin ? ...), directly or through a variable assigned from it within the 15 lines above; a header or cookie value compared with an administrative literal ('admin', 'superuser', 'owner' ...) counts whatever its name; (2) a role checked as a substring: 'admin' in user.role, role.startswith('admin'), user.role.includes('admin'), role.indexOf('superuser') !== -1, /moderator/.test(user.role), so 'not-admin' passes; (3) a Python assert used as the authorization check (assert request.user.is_staff, assert user.has_role(...)), which python -O removes; (4) a JavaScript if whose condition assigns instead of compares (if (user.role = 'admin'), if (req.user.isAdmin = true)), which is always true. Not reported: roles read from the server-side user or session (req.user.role, req.session.role, user.roles lists), the Authorization header, content-type and other non-privilege headers, a query value compared with 'admin' for navigation, a condition that rejects a request claiming the privilege (if req.query.role === 'admin' then 403, abort, throw, raise), which refuses an escalation attempt; a negated guard that rejects when the claim is absent (if request.cookies.get('role') != 'admin': abort(403), if not staff: abort(401)) trusts the client and is reported, asserts in tests, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-863/",
	"languages": ["node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [863],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["incorrect-authorization", "cwe-863", "access-control"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

# String literals containing whitespace are prose or embedded code, never a
# role name or a header key: blanking them keeps a help text from matching.
_code(line) := regex.replace(regex.replace(regex.replace(line, "`[^`]*`", "``"), `("[^"\s]*")|"[^"\n]*"`, "${1}"), `('[^'\s]*')|'[^'\n]*'`, "${1}")

_priv_lit := `(?i:admin|administrator|superuser|super_?admin|root|staff|owner|moderator|manager)`

_priv_key := `(?i)admin|role|staff|superuser|privilege|permission|access_?level|is_?auth|user_?type|moderator|owner`

# ── (1) Client-controlled authorization ──────────────────────────────────

# [class, key] for each request header/cookie ("hc") or query ("q") read on
# the line; the key is the header, cookie or parameter name.
_refs(c, "js") := {["hc", k] |
	some m in regex.find_all_string_submatch_n(`\b(?:req|request|ctx\.request|ctx)\.(?:headers|cookies)(?:\??\.(\w+)|\[\s*['"]([^'"]+)['"]\s*\])`, c, -1)
	k := concat("", [m[1], m[2]])
} | {["hc", m[1]] |
	some m in regex.find_all_string_submatch_n(`\b(?:req|ctx)\.(?:header|get|cookies\.get)\(\s*['"]([^'"]+)['"]`, c, -1)
} | {["q", k] |
	some m in regex.find_all_string_submatch_n(`\b(?:req|ctx|ctx\.request)\.query(?:\??\.(\w+)|\[\s*['"]([^'"]+)['"]\s*\])`, c, -1)
	k := concat("", [m[1], m[2]])
}

_refs(c, "py") := {[cls, k] |
	some m in regex.find_all_string_submatch_n(`\b\w*request\.(headers|cookies|COOKIES|META|args|GET|query_params|values)(?:\.get\(\s*['"]([^'"]+)['"]|\[\s*['"]([^'"]+)['"]\s*\])`, c, -1)
	cls := _py_cls(m[1])
	k := concat("", [m[2], m[3]])
}

_py_cls(s) := "hc" if s in {"headers", "cookies", "COOKIES", "META"}

_py_cls(s) := "q" if s in {"args", "GET", "query_params", "values"}

_decides(refs, c) if {
	some [_, k] in refs
	regex.match(_priv_key, k)
}

_decides(refs, c) if {
	some ["hc", _] in refs
	_compares_priv(c)
}

_compares_priv(c) if regex.match(concat("", [`[=!]==?\s*['"]`, _priv_lit, `['"]|['"]`, _priv_lit, `['"]\s*[=!]==?`]), c)

_condition(c, "py") if regex.match(`^\s*(?:if|elif|while)\b|\bif\b.+\belse\b`, c)

_condition(c, "js") if regex.match(`\bif\s*\(|\s\?\s[^:]*:|&&|\|\|`, c)

# The branch rejects the request: the condition is a guard, not a grant.
_rejects(lines, i) if {
	w := helpers.code_window(lines, i, 0, 1)
	regex.match(`(?i)\b40[13]\b|\bthrow\b|\babort\(|\braise\b|\breject|forbidden|PermissionDenied|PermissionError|\bdeny|unauthori[sz]ed`, w)
}

_cheap := {"js": "req", "py": "request."}

_src_gate := {
	"js": `\b(?:req|ctx)\.(?:headers|cookies|query|header|get)\b`,
	"py": `\brequest\.(?:headers|cookies|COOKIES|META|args|GET|query_params|values)\b`,
}

# Variables assigned from a header/cookie/query read in the 15 lines above,
# with the refs of the assignment.
_tainted(lines, i, lang) := {[v, refs] |
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_src_gate[lang], l)
	c := _code(l)
	refs := _refs(c, lang)
	count(refs) > 0
	v := helpers.assigned_first(c)
}

_client_decision(lines, i, c, lang) if _decides(_refs(c, lang), c)

_client_decision(lines, i, c, lang) if {
	some [v, refs] in _tainted(lines, i, lang)
	regex.match(concat("", [`\b`, v, `\b`]), c)
	not regex.match(concat("", [`^\s*(?:const|let|var)?\s*`, v, `\s*=[^=]`]), c)
	_decides(refs, c)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, _cheap[lang])
	regex.match(_src_gate[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	c := _code(line)
	_condition(c, lang)
	_client_decision(lines, i, c, lang)
	not _refuses_claim(lines, i, c)
	not _c784_owned(path, lines, i, line)
	not _c807_owned(path, content, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Authorization is decided by a header, cookie or query value the client sends, so any caller can claim the role or flag it checks. Decide from the authenticated server-side identity (the session or a verified token) and its stored roles",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── (2) Role compared as a substring ─────────────────────────────────────

_role_field := `(?:role|user_role|user_type|account_type|userRole|userType|accountType)`

_substring_res := {
	"py": [
		concat("", [`['"]`, _priv_lit, `['"]\s+(?:not\s+)?in\s+(?:[\w.]*\.)?`, _role_field, `\s*(?:[:)\]]|$|\band\b|\bor\b|\bif\b|\belse\b)`]),
		concat("", [`\b`, _role_field, `\.(?:startswith|endswith|find|index|rfind|count|__contains__)\(\s*['"]`, _priv_lit]),
		concat("", [`\bre\.(?:search|match)\(\s*r?['"][^'"]*`, _priv_lit, `[^'"]*['"]\s*,\s*(?:[\w.]*\.)?`, _role_field, `\s*\)`]),
	],
	"js": [
		concat("", [`\b`, _role_field, `\??\.(?:includes|indexOf|startsWith|endsWith|match|search|lastIndexOf)\(\s*(?:['"]|/)[^'"/]*`, _priv_lit]),
		concat("", [`/[^/\s]*`, _priv_lit, `[^/\s]*/[gimsuy]*\.test\(\s*(?:[\w.?]*\.)?`, _role_field, `\s*\)`]),
	],
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(`(?i)role|user_?type|account_?type`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)role|user_?type|account_?type`, line)
	not helpers.is_comment_line(line)
	c := _code(line)
	some re in _substring_res[lang]
	regex.match(re, c)
	finding := {
		"rule_id": metadata.id,
		"message": "The role is checked as a substring, so any role whose name contains the privileged one ('not-admin', 'admin-requested', 'guest_owner') passes the check. Compare the role for equality, or test membership in a list of roles",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── (3) Python assert as the authorization check ─────────────────────────

_assert_re := `^\s*assert\s+(?:not\s+)?[\w.\[\]'"]*(?:\b(?:is_admin|is_staff|is_superuser|is_authenticated|is_owner|is_moderator)\b|\.(?:has_perms?|has_role|has_permission|has_access|can_\w+|is_allowed)\s*\(|\.role\s*(?:==|in\b))`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "assert ")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "assert ")
	regex.match(_assert_re, line)
	finding := {
		"rule_id": metadata.id,
		"message": "An assert statement is the authorization check: Python removes asserts under -O (PYTHONOPTIMIZE), and the check disappears with them. Raise PermissionDenied/abort(403) explicitly",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── (4) Assignment where a comparison was meant ──────────────────────────

_assign_cond := `\bif\s*\(\s*!?\s*(?:[\w$]+\??\.)*(?:role|userRole|isAdmin|is_admin|admin|isAuthenticated|authenticated|isAuthorized|authorized|isStaff|isSuperuser|isSuperUser|isOwner|permission|permissions|accessLevel)\s*=\s*[^=>]`

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "js"
	contains(content, "if")
	regex.match(`(?m)\bif\s*\(\s*!?\s*[\w$.?]*\s*=\s*[^=>]`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	c := _code(line)
	regex.match(_assign_cond, c)
	finding := {
		"rule_id": metadata.id,
		"message": "The authorization condition assigns instead of compares (=, not ===), so it is always true and grants every caller the role it names. Use === and keep roles read-only in checks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A branch that rejects the request when the client CLAIMS the privilege
# (`if req.query.role === 'admin': 403`) refuses an escalation attempt. A
# negated condition that rejects when the claim is ABSENT (`!= 'admin'`,
# `if not staff`) is the client-trusting guard itself and is still reported.
_refuses_claim(lines, i, c) if {
	_rejects(lines, i)
	not regex.match(`!==?|\bnot\b|\bif\s*\(\s*!`, c)
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

# ── Lines VNX-807 reports ───────────────────────────────────────────────
# An if/elif/while/switch (or a boolean assignment with a comparison) that
# decides on a request cookie named for a privilege, or compares a cookie
# value with a privileged literal ('admin', 'root', 'staff'...), directly or
# through a variable assigned from the cookie in the 15 lines above, is
# reported by VNX-807 (CWE-807, untrusted input in a security decision); this
# rule leaves the line to it. This mirrors VNX-807's JavaScript and Python
# cookie reads; header and query decisions are not handed over.
_c807_scope(path) if {
	some e in {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".py"}
	endswith(path, e)
	not endswith(path, ".min.js")
	not helpers.is_test_path(path)
}

_c807_src_res := [
	`\b(?:req|request)\.cookies\s*(?:\??\.\s*([\w$]+)|(?:\?\.)?\[\s*['"\x60]([^'"\x60]+)['"\x60]\s*\])`,
	`\brequest\.(?:COOKIES|cookies)\s*(?:\.\s*get\s*\(\s*['"]([^'"]+)['"]|\[\s*['"]([^'"]+)['"]\s*\])`,
]

_c807_src_any := `\b(?:req|request)\.(?:cookies|COOKIES)\b`

_c807_priv_name := `(?i)(admin|role|root|superuser|staff|privilege|permission|access_?level|authenticated|authori[sz]ed|auth_?level|logged_?in|is_?auth)`

_c807_lits := `(?:admin\w*|administrator|root|superuser|super_?admin|staff|owner|moderator|auditor|privileged)`

_c807_priv_literal := concat("", [`(?i)(?:===?|!==?|\.equals(?:IgnoreCase)?\s*\(|\bin\s*[\(\[\{])\s*['"]`, _c807_lits, `['"]|['"]`, _c807_lits, `['"]\s*(?:===?|!==?|\.equals)`])

_c807_not_trust := `(?i)^(?:http_)?(?:referer|referrer|user-agent|user_agent)$`

_c807_server_side := `\b(?:req\.(?:user|session|signedCookies)|request\.(?:user|session)|session\s*\[|getSession\s*\(|getUserPrincipal\s*\(|isUserInRole\s*\(|hasRole\s*\(|hasAuthority\s*\(|current_user\b|g\.user\b)`

_c807_decision(line) if regex.match(`^\s*(?:\}\s*)?(?:if|elif|else\s+if|while|switch)\b`, line)

_c807_decision(line) if {
	regex.match(`^\s*(?:const|let|var|final|boolean|bool|[A-Za-z_]\w*)?\s*[A-Za-z_]\w*\s*(?::\s*\w+\s*)?=\s*!?\(?\s*\w`, line)
	regex.match(`===?|!==?|\.equals(?:IgnoreCase)?\s*\(`, line)
	regex.match(_c807_src_any, line)
}

_c807_owned(path, content, lines, i, line) if {
	_c807_scope(path)
	regex.match(_c807_src_any, content)
	_c807_decision(line)
	not regex.match(`(?i)passw|\bpwd\b`, line)
	not regex.match(_c807_server_side, line)
	_c807_hit(lines, i, line)
}

# The decision reads the input directly.
_c807_hit(_, _, line) if {
	some re in _c807_src_res
	some m in regex.find_all_string_submatch_n(re, line, -1)
	n := concat("", [m[1], m[2]])
	n != ""
	not regex.match(_c807_not_trust, n)
	_c807_priv(n, line)
}

# The decision reads a variable assigned from the input in the 15 lines above.
_c807_hit(lines, i, line) if {
	some j in numbers.range(max([0, i - 15]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_c807_src_any, l)
	regex.match(concat("", [`[^=!<>]=\s*(?:await\s+)?\(?\s*(?:`, _c807_src_any, `)`]), l)
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:const|let|var|final)\s+)?(?:[A-Za-z_][\w<>\[\]]*\s+)?([A-Za-z_]\w*)\s*(?::\s*[\w<>\[\]|]+\s*)?=[^=]`, l, 1)
	count(m) > 0
	v := m[0][1]
	not regex.match(_c807_not_trust, v)
	regex.match(concat("", [`(?:^|[^\w.$])`, v, `\b`]), line)
	_c807_priv(v, line)
}

_c807_priv(n, _) if regex.match(_c807_priv_name, n)

_c807_priv(_, line) if regex.match(_c807_priv_literal, line)
