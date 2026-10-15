# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_539

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-539",
	"name": "Use of Persistent Cookies Containing Sensitive Information",
	"description": "A cookie that carries sensitive information is made persistent, so it is written to the browser's disk and outlives the session. Reported: a cookie named for a credential or personal secret (password, passwd, pwd, secret, ssn, credit card, cvv, api key, private key) whose value is not a constant, set with any positive lifetime or an expiry that cannot be read statically (Express res.cookie and Koa ctx.cookies.set maxAge/expires, Python set_cookie max_age/expires, Java Cookie.setMaxAge and Spring ResponseCookie.from(...).maxAge(n or Duration.ofDays(n)), PHP setcookie expiry, Rails cookies.permanent[...] = v and cookies[...] = { value:, expires: N.days.from_now }); and a session or authentication cookie (session, sid, auth, token, jwt, userid) or the framework session cookie (express-session/cookie-session cookie.maxAge, Django SESSION_COOKIE_AGE, Flask PERMANENT_SESSION_LIFETIME) given a literal lifetime longer than 31 days. Not reported: cookies without a lifetime (browser-session cookies), deletions (maxAge 0, a past expiry), constant values, preference cookies (theme, lang), session lifetimes of 31 days or less (Flask's and Django's defaults), session lifetimes computed at run time, remember-me cookies, comments, string literals and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-539/",
	"languages": ["node", "python", "java", "php", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [539],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cookie-persistent", "cwe-539"],
}

_lang(path) := "js" if {
	some ext in {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "rb" if endswith(path, ".rb")

_month := 2678400 # 31 days, in seconds

_credential_name := `(?i)pass(word|wd)|pwd|secret|ssn|social_?security|credit_?card|card_?(no|num)|cvv|api_?key|private_?key`

_session_name := `(?i)sess|^sid$|_sid$|auth|token|jwt|user_?id`

_cookie_class(name) := "credential" if regex.match(_credential_name, name)

_cookie_class(name) := "session" if {
	not regex.match(_credential_name, name)
	regex.match(_session_name, name)
	not regex.match(`(?i)remember`, name)
}

# A constant value (string or number literal, true/false/null) is not information.
_constant(v) if regex.match(`^\s*(['"\x60]|-?\d|true\b|false\b|null\b|None\b)`, v)

# The product of a literal expression such as `365 * 24 * 60 * 60 * 1000`.
_product(expr) := n if {
	e := trim_space(expr)
	regex.match(`^\d[\d_]*(\s*\*\s*\d[\d_]*)*$`, e)
	n := product([to_number(replace(trim_space(x), "_", "")) | some x in split(e, "*")])
}

_timedelta(t) := n if {
	m := regex.find_all_string_submatch_n(`timedelta\(\s*(weeks|days|hours|minutes|seconds)\s*=\s*(\d+)\s*\)`, t, 1)
	count(m) > 0
	unit := {"weeks": 604800, "days": 86400, "hours": 3600, "minutes": 60, "seconds": 1}
	n := to_number(m[0][2]) * unit[m[0][1]]
}

# The call text: the line and continuation lines until its parentheses balance
# (at most four more), so the next statement is never read as an option.
_call_text(lines, i) := t if {
	last := min([count(lines) - 1, i + 4])
	ends := [k |
		some k in numbers.range(i, last)
		seg := concat(" ", array.slice(lines, i, k + 1))
		strings.count(seg, "(") <= strings.count(seg, ")")
	]
	e := min(array.concat(ends, [last]))
	t := concat("", [concat(" ", array.slice(lines, i, e + 1)), " "])
}

# ── Lifetime, in seconds; "unknown" when present but not literal ─────────

_js_life(t) := n if {
	m := regex.find_all_string_submatch_n(`\bmaxAge\s*:\s*([\d_\s\*]+)[,}\s]`, t, 1)
	count(m) > 0
	n := _product(m[0][1]) / 1000
} else := n if {
	m := regex.find_all_string_submatch_n(`\bexpires\s*:\s*new\s+Date\s*\(\s*Date\.now\(\)\s*\+\s*([\d_\s\*]+)\)`, t, 1)
	count(m) > 0
	n := _product(m[0][1]) / 1000
} else := "unknown" if {
	regex.match(`\b(maxAge|expires)\s*:`, t)
}

_py_life(t) := n if {
	m := regex.find_all_string_submatch_n(`\bmax_age\s*=\s*([\d_\s\*]+)[,)\s]`, t, 1)
	count(m) > 0
	n := _product(m[0][1])
} else := n if {
	regex.match(`\b(max_age|expires)\s*=`, t)
	n := _timedelta(t)
} else := "unknown" if {
	regex.match(`\b(max_age|expires)\s*=\s*[^\s,)]`, t)
	not regex.match(`\b(max_age|expires)\s*=\s*None\b`, t)
}

_php_life(t) := n if {
	m := regex.find_all_string_submatch_n(`\btime\(\)\s*\+\s*([\d_\s\*]+)$`, t, 1)
	count(m) > 0
	n := _product(m[0][1])
} else := n if {
	m := regex.find_all_string_submatch_n(`strtotime\(\s*['"]\+\s*(\d+)\s*(day|week|month|year)`, t, 1)
	count(m) > 0
	unit := {"day": 86400, "week": 604800, "month": 2592000, "year": 31536000}
	n := to_number(m[0][1]) * unit[m[0][2]]
} else := -1 if {
	regex.match(`\btime\(\)\s*-`, t)
} else := 0 if {
	regex.match(`^\s*0\s*$`, t)
} else := "unknown" if {
	trim_space(t) != ""
}

_report("credential", "unknown") := true

_report("credential", n) if {
	is_number(n)
	n > 0
}

_report("session", n) if {
	is_number(n)
	n > _month
}

# ── Express: res.cookie(name, value, { maxAge | expires }) ───────────────

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "js"
	regex.match(`\.cookie\(|\.cookies\.set\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".cookie")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^[^'"\x60]*\.(?:cookie|cookies\.set)\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]\s*,\s*([^,)]+)`, line, 1)
	count(m) > 0
	not _constant(m[0][2])
	class := _cookie_class(m[0][1])
	_report(class, _js_life(_call_text(lines, i)))
	finding := _finding(path, i, line, class)
}

# express-session / cookie-session: a long cookie.maxAge.
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "js"
	contains(content, "maxAge")
	regex.match(`(?i)session\s*\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "maxAge")
	not helpers.is_comment_line(line)
	not regex.match(`\.cookie\(|\.cookies\.set\(`, line)
	_in_session_config(lines, i, line)
	n := _js_life(concat("", [line, " "]))
	_report("session", n)
	finding := _finding(path, i, line, "session")
}

_in_session_config(_, _, line) if regex.match(`^[^'"\x60]*(?i:session)\s*\(`, line)

_in_session_config(lines, i, line) if {
	regex.match(`^\s*maxAge\s*:`, line)
	some j in numbers.range(max([0, i - 10]), i - 1)
	regex.match(`^[^'"\x60]*(?i:session)\s*\(\s*\{?\s*$|^[^'"\x60]*(?i:session)\s*\(\s*\{`, lines[j])
}

# ── Python: set_cookie(name, value, max_age | expires) ───────────────────

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "py"
	contains(content, "set_cookie")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "set_cookie")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^[^'"]*\.set_cookie\s*\(\s*(?:key\s*=\s*)?['"]([^'"]+)['"]\s*,\s*(?:value\s*=\s*)?([^,)]+)`, line, 1)
	count(m) > 0
	not _constant(m[0][2])
	class := _cookie_class(m[0][1])
	_report(class, _py_life(_call_text(lines, i)))
	finding := _finding(path, i, line, class)
}

# Django SESSION_COOKIE_AGE and Flask PERMANENT_SESSION_LIFETIME.
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "py"
	regex.match(`SESSION_COOKIE_AGE|PERMANENT_SESSION_LIFETIME`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`^\s*(?:[\w.\[\]'"]*)?(SESSION_COOKIE_AGE|PERMANENT_SESSION_LIFETIME)['"]?\]?\s*=\s*(.+?)\s*(#.*)?$`, line, 1)
	count(m) > 0
	n := _py_setting_life(m[0][2])
	_report("session", n)
	finding := _finding(path, i, line, "session")
}

_py_setting_life(v) := _product(v)

_py_setting_life(v) := _timedelta(v) if not _product(v)

# ── Java: Cookie c = new Cookie(name, value); c.setMaxAge(n) ─────────────

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "java"
	contains(content, "setMaxAge")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "new Cookie")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`(\w+)\s*=\s*new\s+(?:javax\.servlet\.http\.|jakarta\.servlet\.http\.)?Cookie\s*\(\s*"([^"]+)"\s*,\s*([^)]+)\)`, line, 1)
	count(m) > 0
	not _constant(m[0][3])
	class := _cookie_class(m[0][2])
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
	s := regex.find_all_string_submatch_n(concat("", [`\b`, m[0][1], `\.setMaxAge\s*\(\s*([^)]*)\)`]), lines[k], 1)
	count(s) > 0
	_report(class, _java_life(s[0][1]))
	finding := _finding(path, k, lines[k], class)
}

_java_life(v) := _product(v)

_java_life(v) := -1 if regex.match(`^\s*-`, v)

_java_life(v) := "unknown" if {
	not _product(v)
	not regex.match(`^\s*-`, v)
}

# Spring ResponseCookie.from(name, value)...maxAge(n | Duration.ofX(n)).
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "java"
	contains(content, "ResponseCookie")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ResponseCookie")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`ResponseCookie\s*\.\s*from\s*\(\s*"([^"]+)"\s*,\s*([^)]+)\)`, line, 1)
	count(m) > 0
	not _constant(m[0][2])
	class := _cookie_class(m[0][1])
	some k in numbers.range(i, min([count(lines) - 1, i + 8]))
	s := regex.find_all_string_submatch_n(`\.maxAge\s*\(\s*((?:[^()]|\([^()]*\))*)\)`, lines[k], 1)
	count(s) > 0
	not _statement_ends_before(lines, i, k)
	_report(class, _spring_life(s[0][1]))
	finding := _finding(path, i, line, class)
}

_statement_ends_before(lines, i, k) if {
	some j in numbers.range(i, k - 1)
	contains(lines[j], ";")
}

_spring_life(v) := n if {
	m := regex.find_all_string_submatch_n(`Duration\s*\.\s*of(Days|Hours|Minutes|Seconds)\s*\(\s*([\d_]+)L?\s*\)`, v, 1)
	count(m) > 0
	unit := {"Days": 86400, "Hours": 3600, "Minutes": 60, "Seconds": 1}
	n := to_number(replace(m[0][2], "_", "")) * unit[m[0][1]]
} else := n if {
	n := _product(replace(v, "L", ""))
} else := -1 if {
	regex.match(`^\s*-`, v)
} else := "unknown"

# ── Rails: cookies.permanent[:name] = value (a 20-year cookie), or
# cookies[:name] = { value: v, expires: N.days/months/years.from_now } ────

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "rb"
	contains(content, "cookies")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "cookies")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^[^'"#]*\bcookies\.permanent(?:\.signed|\.encrypted)?\[\s*:?['"]?(\w+)['"]?\s*\]\s*=\s*(.+)$`, line, 1)
	count(m) > 0
	not _constant(m[0][2])
	class := _cookie_class(m[0][1])
	_report(class, 630720000)
	finding := _finding(path, i, line, class)
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "rb"
	contains(content, "from_now")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "cookies")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^[^'"#]*\bcookies(?:\.signed|\.encrypted)?\[\s*:?['"]?(\w+)['"]?\s*\]\s*=\s*\{(.*)$`, line, 1)
	count(m) > 0
	class := _cookie_class(m[0][1])
	t := concat(" ", array.slice(lines, i, min([count(lines), i + 4])))
	v := regex.find_all_string_submatch_n(`\bvalue\s*(?::|=>)\s*([^,}]+)`, t, 1)
	count(v) > 0
	not _constant(v[0][1])
	e := regex.find_all_string_submatch_n(`\bexpires\s*(?::|=>)\s*(\d+)\.(days?|weeks?|months?|years?)\.from_now`, t, 1)
	count(e) > 0
	unit := {"day": 86400, "week": 604800, "month": 2592000, "year": 31536000}
	_report(class, to_number(e[0][1]) * unit[trim_suffix(e[0][2], "s")])
	finding := _finding(path, i, line, class)
}

# ── PHP: setcookie(name, value, expiry) ──────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "php"
	contains(content, "setcookie")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "setcookie")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^[^'"]*\bsetcookie\s*\(\s*['"]([^'"]+)['"]\s*,\s*([^,]+?)\s*,\s*((?:[^,()]|\([^)]*\))+)`, line, 1)
	count(m) > 0
	not _constant(m[0][2])
	class := _cookie_class(m[0][1])
	_report(class, _php_life(m[0][3]))
	finding := _finding(path, i, line, class)
}

_finding(path, i, line, class) := {
	"rule_id": metadata.id,
	"message": _message[class],
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_message := {
	"credential": "A cookie carrying a credential or personal secret is made persistent: it is written to the browser's disk and survives the session, where other users of the machine, malware and backups can read it. Do not store such values in cookies; keep them server-side and reference them by an opaque session id",
	"session": "A session or authentication cookie is given a lifetime of more than 31 days, so a stolen or forgotten browser keeps the account signed in for that long. Use a browser-session cookie or a short lifetime, and a separate, revocable remember-me token if long sign-ins are needed",
}
