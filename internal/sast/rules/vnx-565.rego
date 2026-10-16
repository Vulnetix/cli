# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_565

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-565",
	"name": "Reliance on Cookies without Validation and Integrity Checking",
	"description": "A security decision is taken on a plain cookie, which the client can set to anything. Reported in JavaScript/TypeScript (Express req.cookies, Koa ctx.cookies.get without signed, Next.js cookies().get and NextRequest request.cookies.get), Python (Flask request.cookies, Django request.COOKIES) and PHP ($_COOKIE, filter_input(INPUT_COOKIE, ...)): a read of a cookie whose name says it carries identity or privilege (role, admin, isAdmin, is_staff, superuser, user_id, userId, uid, username, user, email, login, logged_in, authenticated, authorized, access_level, level, privilege, permission, group, user_type, account_id...) that is compared, tested in a condition or ternary, checked with isset, or used in a lookup (find/filter/get/query/where/objects/SQL), on the same line or through a variable assigned from it and so used in the next 10 lines; and writing such a privilege, user-id or username cookie without signing it (Express res.cookie without signed: true, Flask/Django set_cookie, PHP setcookie). Not reported: signed cookies (req.signedCookies, ctx.cookies.get(name, {signed: true}), Django get_signed_cookie/set_signed_cookie), a value verified on the same or next two lines (jwt.verify, itsdangerous loads/unsign, an HMAC check), session-id and CSRF-token cookies, preference cookies (theme, language), a cookie that is only displayed, destructuring (const { role } = req.cookies), test files, comments and string literals. JavaScript privilege fields read from req.cookies are also reported by VNX-472. A cookie named for a privilege or login state (admin, role, is_staff, logged_in, access_level...) that is compared or tested on its line, or assigned to a variable a condition uses within 15 lines, is reported by VNX-784 (a security decision on a cookie), and an Express res.cookie() or Python set_cookie() of a cookie whose whole name is a privilege flag or role is reported by VNX-642 (authorization state in a client-controlled cookie); both are left to those rules. This rule keeps lookups, identity cookies (user_id, uid, username, email, level), PHP setcookie() and the other shapes.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-565/",
	"languages": ["node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [565],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cookie-auth", "cwe-565"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_trust_key := `(?i)^(?:roles?|user_?roles?|is_?admin|admin|is_?staff|staff|is_?superuser|superuser|user_?id|userid|uid|user|username|user_?name|login|logged_?in|is_?logged_?in|authenticated|is_?authenticated|authori[sz]ed|is_?authori[sz]ed|auth_?level|access_?level|level|privileges?|permissions?|groups?|user_?type|account_?type|account_?id|email)$`

_priv_key := `(?i)^(?:roles?|user_?roles?|is_?admin|admin|is_?staff|staff|is_?superuser|superuser|user_?id|userid|uid|logged_?in|is_?logged_?in|authenticated|is_?authenticated|authori[sz]ed|is_?authori[sz]ed|auth_?level|access_?level|level|privileges?|permissions?|user_?type|account_?type|account_?id)$`

# Cookies whose write is reported: privilege fields, user ids and the login name.
_write_name(n) if regex.match(_priv_key, n)

_write_name(n) if regex.match(`(?i)^(?:user_?name|login_?name)$`, n)

_read_res := {
	"js": [
		`\b(?:req|request)\.cookies(?:\?\.|\.)([A-Za-z_$][\w$]*)`,
		"\\b(?:req|request)\\.cookies(?:\\?\\.)?\\[\\s*[\"'`]([^\"'`]+)[\"'`]\\s*\\]",
		`\bctx\.cookies\.get\(\s*["']([^"']+)["']\s*\)`,
		# Next.js: cookies() from next/headers and NextRequest.cookies.
		"(?:\\bcookies\\(\\s*\\)\\s*\\)?|\\b(?:req|request)\\.cookies|\\bcookieStore)\\.get\\(\\s*[\"'`]([^\"'`]+)[\"'`]\\s*\\)",
	],
	"py": [
		`\brequest\.(?:cookies|COOKIES)\.get\(\s*["']([^"']+)["']`,
		`\brequest\.(?:cookies|COOKIES)\[\s*["']([^"']+)["']\s*\]`,
	],
	"php": [
		`\$_COOKIE\s*\[\s*["']([^"']+)["']\s*\]`,
		`\bfilter_input\(\s*INPUT_COOKIE\s*,\s*["']([^"']+)["']`,
	],
}

_set_res := {
	"js": ["\\bres\\.cookie\\(\\s*[\"'`]([^\"'`]+)[\"'`]"],
	"py": [`\.set_cookie\(\s*["']([^"']+)["']`],
	"php": [`\bsetcookie\(\s*["']([^"']+)["']`],
}

_has(s) if contains(s, "cookie")

_has(s) if contains(s, "COOKIE")

_needle_set := {"js": "res.cookie(", "py": ".set_cookie(", "php": "setcookie("}

_decision := `===?|!==?|\s\?\s|\bif\b|\belif\b|\bunless\b|&&|\|\||\band\b|\bor\b|\bnot\b|\bisset\s*\(|\.(?:find\w*|filter\w*|get|query|where|load\w*|select|fetch\w*|lookup)\s*\(|\bobjects\.|\bquery\s*\(|\bSELECT\b|\bWHERE\b|findByPk|findById|findOne`

_verified := `(?i)verify|unsign|signer|\.loads\(|jwt|hmac|check_?signature|decrypt`

_strip(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_trusted_reads(lang, line) := {[m[0], m[1]] |
	some re in _read_res[lang]
	some m in regex.find_all_string_submatch_n(re, line, -1)
	regex.match(_trust_key, m[1])
}

_verified_near(lines, i) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 2]))
	regex.match(_verified, lines[k])
}

# The read itself is a decision or lookup.
_decides(lines, i, line, expr, _) if {
	rest := _strip(replace(line, expr, " COOKIE "))
	regex.match(_decision, rest)
}

# Assigned to a variable that a later line decides on or looks up.
_decides(lines, i, line, _, lang) if {
	v := _assigned(lang, line)
	re := _use_re(lang, v)
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 10]))
	not helpers.is_comment_line(lines[k])
	regex.match(re, lines[k])
	regex.match(_decision, _strip(lines[k]))
}

# Bound into a prepared statement whose SQL (SELECT/WHERE) is on one of the
# three lines above the execute/bind call: a lookup keyed by the cookie.
_decides(lines, i, line, _, lang) if {
	v := _assigned(lang, line)
	re := _use_re(lang, v)
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 10]))
	not helpers.is_comment_line(lines[k])
	regex.match(re, lines[k])
	regex.match(`(?:->|\.)(?:execute\w*|bind_?[Pp]aram|bind_?[Vv]alue|bind_?[Pp]aram)\s*\(`, lines[k])
	some q in numbers.range(max([i + 1, k - 3]), k)
	regex.match(`\b(?:SELECT|WHERE|select|where)\b`, lines[q])
}

_assigned(lang, line) := v if {
	lang != "php"
	v := helpers.assigned_first(line)
}

_assigned("php", line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*=[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_use_re(lang, v) := concat("", [`\b`, v, `\b`]) if lang != "php"

_use_re("php", v) := concat("", [`\$`, v, `\b`])

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has(line)
	not helpers.is_comment_line(line)
	not contains(line, "signedCookies")
	some r in _trusted_reads(lang, line)
	not _in_string(line, r[0])
	not _verified_near(lines, i)
	_decides(lines, i, line, r[0], lang)
	not _c784_owned(path, lines, i, line)
	finding :=_finding(path, i, line, sprintf("Security decision taken on the unsigned cookie '%s', which the client controls; keep identity and privilege in a server-side session or a signed/verified token", [r[1]]))
}

# The match sits inside a string literal on this line.
_in_string(line, expr) if not contains(_strip(replace(line, expr, "__CK__")), "__CK__")

# Writing a privilege cookie without a signature.
_signed_call(lines, i) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 4]))
	regex.match(`signed\s*:\s*true`, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, _needle_set[lang])
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, _needle_set[lang])
	not helpers.is_comment_line(line)
	some re in _set_res[lang]
	some m in regex.find_all_string_submatch_n(re, line, -1)
	_write_name(m[1])
	not _signed_call(lines, i)
	not _c642_owned(lines, i, line, lang, m[1])
	finding :=_finding(path, i, line, sprintf("The privilege or identity cookie '%s' is written unsigned, so the client can change it; sign it (signed: true, set_signed_cookie) or keep it in the server-side session", [m[1]]))
}

# ── Writes VNX-642 reports ───────────────────────────────────────────────
# An Express res.cookie() or Python set_cookie() of a cookie whose whole name
# is a privilege flag or role (admin, is_staff, role, permissions,
# access_level...) is authorization state handed to the client: VNX-642
# (CWE-642) reports it, so this rule leaves it to it. Identity cookies
# (user_id, uid), a bare "level" and PHP setcookie() stay here.
_c642_name(n) if regex.match(`(?i)^(?:is[_-]?|has[_-]?)?(?:admin|administrator|staff|superuser|super[_-]?user|root|privileged|authenticated|authorized|authorised|logged[_-]?in|premium|paid|vip|admin[_-]?access)$`, n)

_c642_name(n) if regex.match(`(?i)^(?:user[_-]?|account[_-]?)?(?:roles?|privileges?|permissions?|perms)$`, n)

_c642_name(n) if regex.match(`(?i)^(?:user|account|access|auth|member)[_-]?(?:type|level|group|tier)$`, n)

_c642_owned(_, _, line, "js", n) if _c642_name(n)

_c642_owned(lines, i, line, "py", n) if {
	_c642_name(n)
	not regex.match(`^\s*[rbuf]?("""|'''|"|')`, line)
	not _c642_in_docstring(lines, i)
}

_c642_in_docstring(lines, i) if {
	n := sum([count(regex.find_all_string_submatch_n(`"""|'''`, lines[j], -1)) | some j in numbers.range(0, i - 1)])
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
