# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_642

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-642",
	"name": "Authorization state kept in a client-controlled cookie",
	"description": "Critical state data (whether the user is an administrator, their role, permissions, access level or logged-in flag) is stored in, or read back from, a plain cookie, which the client can edit freely (CWE-642, external control of critical state data). Reported in JavaScript/TypeScript, Python, Java and Kotlin: a cookie whose whole name is a privilege flag or role (admin, isAdmin, is_admin, role, user_role, permissions, access_level, isLoggedIn and similar) set with Express res.cookie() without signed: true (also with the name on the line after res.cookie( ), document.cookie, Flask/Django/Starlette set_cookie(), new Cookie(...) or Kotlin Cookie(...), or Spring ResponseCookie.from(...); or read with req.cookies.x, req.cookies?.x, req.cookies['x'], const { x } = req.cookies, request.cookies.get()/request.COOKIES[...], Tornado self.get_cookie(), c.getName().equals(\"x\") or @CookieValue(\"x\"). Not reported: signed cookies (signed: true, req.signedCookies, set_signed_cookie/get_signed_cookie, Tornado set_secure_cookie), server-side session storage, cookies with other names (session ids, opaque tokens such as auth_token, preferences, names that merely contain a privilege word such as admin_theme), comments and string literals. Whether a signed value is also bound to the user is not judged. A read of such a cookie that is compared or tested on its line, or assigned to a variable a condition uses within 15 lines, is reported by VNX-784 (a security decision on a cookie) and not here; writes, and reads that decide nothing on the spot, stay with this rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-642/",
	"languages": ["java", "kotlin", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [642],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["external-control-state", "cookie", "authorization", "cwe-642"],
}

# A cookie name that carries authorisation state, as the whole name (not a
# substring: admin_theme and auth_token are other things).
_priv_name(n) if regex.match(`(?i)^(?:is[_-]?|has[_-]?)?(?:admin|administrator|staff|superuser|super[_-]?user|root|privileged|authenticated|authorized|authorised|logged[_-]?in|premium|paid|vip|admin[_-]?access)$`, n)

_priv_name(n) if regex.match(`(?i)^(?:user[_-]?|account[_-]?)?(?:roles?|privileges?|permissions?|perms)$`, n)

_priv_name(n) if regex.match(`(?i)^(?:user|account|access|auth|member)[_-]?(?:type|level|group|tier)$`, n)

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "java" if endswith(path, ".kt")

_gate("js", c) if regex.match(`res(?:ponse)?\.cookie\(|document\.cookie\s*=|req(?:uest)?\.cookies\b`, c)

_gate("py", c) if regex.match(`set_cookie\(|\.cookies\b|get_cookie\(`, c)

_gate("py", c) if contains(c, "COOKIES")

_line_gate("js", line) if contains(line, "cookie")

_line_gate("py", line) if contains(line, "ookie")

_line_gate("py", line) if contains(line, "COOKIES")

_line_gate("java", line) if contains(line, "Cookie")

_line_gate("java", line) if contains(line, "getName()")

_gate("java", c) if regex.match(`Cookie\(|ResponseCookie|@CookieValue`, c)

# ── name extractors, the cookie name in group 1 ──────────────────────────

_js_set := [
	`\bres(?:ponse)?\.cookie\(\s*['"\x60]([\w-]+)['"\x60]`,
	`\bdocument\.cookie\s*=\s*['"\x60]\s*([\w-]+)=`,
]

_js_get := [
	`\breq(?:uest)?\.cookies\??\.([A-Za-z_$][\w$]*)`,
	`\breq(?:uest)?\.cookies(?:\?\.)?\[\s*['"\x60]([\w-]+)['"\x60]\s*\]`,
]

_py_pat := [
	`\.set_cookie\(\s*(?:key\s*=\s*)?['"]([\w-]+)['"]`,
	`\b(?:request|req|self\.request)\.(?:cookies|COOKIES)\.get\(\s*['"]([\w-]+)['"]`,
	`\b(?:request|req|self\.request)\.(?:cookies|COOKIES)\[\s*['"]([\w-]+)['"]\s*\]`,
	`\bself\.get_cookie\(\s*['"]([\w-]+)['"]`,
]

_java_pat := [
	`\bnew\s+(?:[\w.]+\.)?Cookie\(\s*"([\w-]+)"`,
	`(?:=|\breturn|\()\s*(?:[\w.]+\.)?Cookie\(\s*"([\w-]+)"`,
	`\bResponseCookie\.from\(\s*"([\w-]+)"`,
	`\.getName\(\)\s*\.equals(?:IgnoreCase)?\(\s*"([\w-]+)"\s*\)`,
	`"([\w-]+)"\s*\.equals(?:IgnoreCase)?\(\s*[\w.]+\.getName\(\)\s*\)`,
	`@CookieValue\(\s*(?:(?:value|name)\s*=\s*)?"([\w-]+)"`,
]

# A Python line that starts inside a docstring is prose: reject lines whose
# match sits after an opening quote that begins the statement.
_py_prose(line) if regex.match(`^\s*[rbuf]?("""|'''|"|')`, line)

_name_on(line, pats) := {n |
	some re in pats
	some m in regex.find_all_string_submatch_n(re, line, -1)
	n := m[1]
	_priv_name(n)
}

# Express res.cookie(name, value, { signed: true }) over up to four lines.
_signed_js(lines, i) if {
	w := concat("\n", array.slice(lines, i, i + 4))
	regex.match(`signed\s*:\s*true`, w)
}

_destructured(line) := {n |
	m := regex.find_all_string_submatch_n(`\{([^}]*)\}\s*=\s*req(?:uest)?\.cookies\b`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	n := trim_space(split(part, ":")[0])
	_priv_name(n)
}

_names(lines, i, line, "js") := ((_name_on(line, _js_set) | _name_on(line, _js_get)) | _destructured(line)) | _next_line_name(lines, i, line)

# res.cookie( with the cookie name on the next line.
_next_line_name(lines, i, line) := {n |
	regex.match(`\bres(?:ponse)?\.cookie\(\s*$`, line)
	m := regex.find_all_string_submatch_n(`^\s*['"\x60]([\w-]+)['"\x60]`, lines[i + 1], 1)
	count(m) > 0
	n := m[0][1]
	_priv_name(n)
}

_names(_, _, line, "py") := _name_on(line, _py_pat)

_names(_, _, line, "java") := _name_on(line, _java_pat)

# Context checks run only on a line that already names a privilege cookie.
_suppressed(lines, i, line, "js") if {
	not contains(line, "cookies")
	_signed_js(lines, i)
}

_suppressed(_, _, line, "py") if _py_prose(line)

_suppressed(lines, i, _, "py") if _in_docstring(lines, i)

# String literals that contain whitespace are prose (a help text naming the
# API); a cookie name never does. They are blanked, as is a trailing comment.
_code(line) := c if {
	lits := [l |
		some l in regex.find_all_string_submatch_n(`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, line, -1)
		regex.match(`\s`, l[0])
	]
	c0 := strings.replace_n({l[0]: `""` | some l in lits}, line)
	c := regex.replace(c0, `(?:^|\s)(?:#|//).*$`, "")
}

# Inside a Python triple-quoted block: an odd number of delimiters above.
_in_docstring(lines, i) if {
	n := sum([count(regex.find_all_string_submatch_n(`"""|'''`, lines[j], -1)) | some j in numbers.range(0, i - 1)])
	n % 2 == 1
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	_line_gate(lang, line)
	not helpers.is_comment_line(line)
	count(_names(lines, i, line, lang)) > 0
	names := _names(lines, i, _code(line), lang)
	not _suppressed(lines, i, line, lang)
	count(names) > 0
	not _c784_owned(path, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Authorization state is kept in a client-controlled cookie (%s): the user can edit it to raise their own privilege. Keep roles and flags in the server-side session, or sign the cookie", [concat(", ", sort(names))]),
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
