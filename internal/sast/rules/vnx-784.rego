# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_784

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-784",
	"name": "Reliance on Cookies without Validation and Integrity Checking in a Security Decision",
	"description": "An authorization or authentication decision is taken from a plain cookie the browser controls, so a user grants themselves a role by editing it (`admin=1`). Reported: a raw read of a cookie whose name says it carries a privilege or login state (admin, is_admin, role, user_role, staff, superuser, privilege, access_level, user_type, logged_in, authenticated, authorized, permissions and the like) that is compared, tested in a condition or ternary on the same line, or assigned to a variable that a condition or comparison uses within the next 15 lines. Raw reads: Python request.COOKIES / request.cookies (Django, Flask) and a membership test (\"logged_in\" not in request.COOKIES) and get_cookie() without secret= (Bottle, Tornado); JavaScript/TypeScript req.cookies.x, req.cookies['x'], destructuring from req.cookies, ctx.cookies.get() without signed: true (Koa) and cookies().get() (Next.js); PHP $_COOKIE[...] and filter_input(INPUT_COOKIE, ...), including an if (!isset($_COOKIE[...])) gate; Ruby cookies[...] and request.cookies[...]; Java Spring @CookieValue and Cookie getName().equals() with getValue() read alongside; Go r.Cookie(\"x\") whose .Value is then tested (also in the same if statement); C# Request.Cookies[\"x\"]. Not reported: signed or encrypted cookie APIs (req.signedCookies, Rails cookies.signed/encrypted, Django get_signed_cookie, Tornado get_secure_cookie, Koa signed: true, Bottle secret=), server-side sessions, cookies about preferences, consent or a session id, a role cookie that is only displayed, an isset() check whose block only sets the cookie, writing cookies, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-784/",
	"languages": ["python", "node", "php", "ruby", "java", "go", "csharp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [784],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cookie-auth-decision", "cwe-784"],
}

_msg := "A security decision is taken from a cookie the client controls: anyone can set it. Keep roles and login state server-side (session) or in a signed/encrypted cookie that is verified"

_ext_lang := {
	"py": "py",
	"js": "js", "mjs": "js", "cjs": "js", "jsx": "js", "ts": "js", "tsx": "js", "mts": "js", "cts": "js",
	"php": "php",
	"rb": "rb", "erb": "rb",
	"java": "java", "kt": "java",
	"go": "go",
	"cs": "cs",
}

_lang(path) := _ext_lang[regex.replace(path, `^.*\.`, "")]

# Cookie names that carry a privilege or a login state.
_priv := {
	"admin", "isadmin", "adminmode", "role", "roles", "userrole", "staff", "isstaff",
	"superuser", "issuperuser", "isroot", "privilege", "privileges", "accesslevel",
	"userlevel", "authlevel", "usertype", "accounttype", "usergroup", "loggedin",
	"isloggedin", "authenticated", "isauthenticated", "authorized", "isauthorized",
	"permission", "permissions",
}

_is_priv(name) if regex.replace(lower(name), `[_-]`, "") in _priv

_file_needle := {
	"py": {"cookie", "COOKIES"},
	"js": {"cookies"},
	"php": {"COOKIE"},
	"rb": {"cookies"},
	"java": {"Cookie"},
	"go": {".Cookie("},
	"cs": {"Cookies["},
}

# Raw (unsigned) reads; the cookie name is the first non-empty group.
_reads := {
	"py": [
		`\b\w*request\.(?:COOKIES|cookies)(?:\.get\(\s*["']([\w-]+)["']|\[\s*["']([\w-]+)["']\s*\])`,
		`\.get_cookie\(\s*["']([\w-]+)["']`,
		# if "logged_in" not in request.COOKIES:
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
	"rb": [`(?:^|[^.\w])(?:request\.)?cookies\[\s*(?::(\w+)|["']([\w-]+)["'])\s*\]`],
	"go": [`\.Cookie\(\s*"([\w-]+)"\s*\)`],
	"cs": [`\bRequest\.Cookies\[\s*"([\w-]+)"\s*\]`],
	"java": [
		`\.getName\(\)\s*\.equals(?:IgnoreCase)?\(\s*"([\w-]+)"\s*\)`,
		`"([\w-]+)"\s*\.equals(?:IgnoreCase)?\(\s*\w+\.getName\(\)\s*\)`,
	],
}

_name(m) := n if {
	ns := [g | some j, g in m; j > 0; g != ""]
	count(ns) > 0
	n := ns[0]
}

# A call quoted inside a string literal on its line.
_in_string(prefix) if {
	some q in {`"`, "'", "`"}
	n := count(indexof_n(prefix, q)) - count(indexof_n(prefix, concat("", [`\`, q])))
	n % 2 == 1
}

# A signed read through an API that also has an unsigned form.
_signed(line) if regex.match(`\bsigned\s*:\s*true\b|\bsecret\s*=`, line)

# The read itself is the decision: compared, or tested by a condition.
_decides(prefix, suffix) if {
	regex.match(`^\s*(?:\)\s*)?(?:===?|!==?|>=?|<=?|\.equals\(|\?[^?.])`, suffix)
	not _existence_check(prefix)
}

_decides(prefix, _) if regex.match(`(?:===?|!==?|\.equals\(|\bin_array\()\s*$`, prefix)

_decides(prefix, _) if regex.match(`(?:(?:^|[\s(])(?:if|elif|elsif|unless|while|and|or|not)|&&|\|\|)\s*\(?\s*!?\s*$`, prefix)

# isset($_COOKIE['role']) ? ... : default only asks whether it exists.
_existence_check(prefix) if regex.match(`\b(?:isset|empty|array_key_exists)\s*\(\s*$`, prefix)

# Java's getName().equals("role") is itself the condition; the value read
# beside it is required separately.
_decides_lang("java", _, _)

_decides_lang(lang, prefix, suffix) if {
	lang != "java"
	_decides(prefix, suffix)
}

# The variable a read is assigned to.
_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:var|let|const|final|my)\s+|[A-Za-z_][\w<>\[\]*.]*\s+)?(\$?[A-Za-z_]\w*)\s*(?:,\s*\w+\s*)*(?::\s*\w+\s*)?(?::=|=)[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
}

_used_in_decision(lines, i, v) if {
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

_report(lang, lines, i, line, prefix, suffix) if _decides_lang(lang, prefix, suffix)

_report(lang, lines, i, line, prefix, suffix) if {
	not _decides_lang(lang, prefix, suffix)
	v := _assigned(line)
	_used_in_decision(lines, i, v)
}

# Go `if c, err := r.Cookie("x"); err == nil && c.Value == "y"`: the value is
# tested in the same statement.
_report(lang, _, _, line, prefix, suffix) if {
	not _decides_lang(lang, prefix, suffix)
	v := _assigned(line)
	regex.match(concat("", [`(?:^|[^\w$])`, replace(v, "$", `\$`), `(?:\.Value)?\s*(?:===?|!==?)`]), suffix)
}

# PHP `if (!isset($_COOKIE['logged_in'])) { redirect }`: the cookie's mere
# presence grants access. A block that only initialises the cookie is not a
# decision.
_report("php", lines, i, _, prefix, _) if {
	regex.match(`\b(?:if|elseif)\s*\(\s*!?\s*(?:isset|empty|array_key_exists)\s*\(\s*$`, prefix)
	not regex.match(`\bsetcookie\s*\(`, helpers.code_window(lines, i, 0, 3))
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_needle(content, _file_needle[lang])
	lines := split(content, "\n")
	some i, line in lines
	_line_needle(lang, line)
	not helpers.is_comment_line(line)
	not _signed(line)
	some re in _reads[lang]
	some m in regex.find_all_string_submatch_n(re, line, -1)
	_is_priv(_name(m))
	idx := indexof(line, m[0])
	prefix := substring(line, 0, idx)
	not _in_string(prefix)
	suffix := substring(line, idx + count(m[0]), -1)
	_java_value_read(lang, lines, i)
	_report(lang, lines, i, line, prefix, suffix)
	f := _finding(path, i, line)
}

# Java getName() matching only matters when the value is read alongside.
_java_value_read(lang, _, _) if lang != "java"

_java_value_read("java", lines, i) if contains(helpers.code_window(lines, i, 0, 3), ".getValue()")

# JavaScript destructuring: const { role, isAdmin: admin } = req.cookies;
findings contains f if {
	some path, content in input.file_contents
	_lang(path) == "js"
	contains(content, "cookies")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "cookies")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(`\{([^}]*)\}\s*=\s*(?:req|request|ctx\.request)\.cookies\b`, line, 1)
	some part in split(m[1], ",")
	pm := regex.find_all_string_submatch_n(`^\s*([\w$]+)(?:\s*:\s*([\w$]+))?\s*(?:=[^,]*)?$`, part, 1)
	count(pm) > 0
	_is_priv(pm[0][1])
	v := _alias_or(pm[0][2], pm[0][1])
	_used_in_decision(lines, i, v)
	f := _finding(path, i, line)
}

_alias_or(a, d) := a if a != ""

_alias_or(a, d) := d if a == ""

# Spring: a privilege cookie bound straight into a handler parameter.
findings contains f if {
	some path, content in input.file_contents
	_lang(path) == "java"
	contains(content, "@CookieValue")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "@CookieValue")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(`@CookieValue\(\s*(?:(?:value|name)\s*=\s*)?"([\w-]+)"`, line, -1)
	_is_priv(m[1])
	f := _finding(path, i, line)
}

_line_needle(lang, line) if {
	lang != "java"
	contains(lower(line), "cookie")
}

_line_needle("java", line) if contains(line, "getName()")

_has_needle(content, needles) if {
	some nd in needles
	contains(content, nd)
}
