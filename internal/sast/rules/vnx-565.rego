# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_565

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-565",
	"name": "Reliance on Cookies without Validation and Integrity Checking",
	"description": "A security decision is taken on a plain cookie, which the client can set to anything. Reported in JavaScript/TypeScript (Express req.cookies, Koa ctx.cookies.get without signed, Next.js cookies().get and NextRequest request.cookies.get), Python (Flask request.cookies, Django request.COOKIES) and PHP ($_COOKIE, filter_input(INPUT_COOKIE, ...)): a read of a cookie whose name says it carries identity or privilege (role, admin, isAdmin, is_staff, superuser, user_id, userId, uid, username, user, email, login, logged_in, authenticated, authorized, access_level, level, privilege, permission, group, user_type, account_id...) that is compared, tested in a condition or ternary, checked with isset, or used in a lookup (find/filter/get/query/where/objects/SQL), on the same line or through a variable assigned from it and so used in the next 10 lines; and writing such a privilege or user-id cookie without signing it (Express res.cookie without signed: true, Flask/Django set_cookie, PHP setcookie). Not reported: signed cookies (req.signedCookies, ctx.cookies.get(name, {signed: true}), Django get_signed_cookie/set_signed_cookie), a value verified on the same or next two lines (jwt.verify, itsdangerous loads/unsign, an HMAC check), session-id and CSRF-token cookies, preference cookies (theme, language), a cookie that is only displayed, destructuring (const { role } = req.cookies), test files, comments and string literals. JavaScript privilege fields read from req.cookies are also reported by VNX-472.",
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
	finding := _finding(path, i, line, sprintf("Security decision taken on the unsigned cookie '%s', which the client controls; keep identity and privilege in a server-side session or a signed/verified token", [r[1]]))
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
	regex.match(_priv_key, m[1])
	not _signed_call(lines, i)
	finding := _finding(path, i, line, sprintf("The privilege or identity cookie '%s' is written unsigned, so the client can change it; sign it (signed: true, set_signed_cookie) or keep it in the server-side session", [m[1]]))
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
