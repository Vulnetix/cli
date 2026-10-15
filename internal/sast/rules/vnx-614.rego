# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_614

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-614",
	"name": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
	"description": "Reports a cookie that the browser will also send over plain HTTP. Python: Django/Flask SESSION_COOKIE_SECURE, CSRF_COOKIE_SECURE or REMEMBER_COOKIE_SECURE set to False (assignment, app.config[...] = False, config.update(...=False)); set_cookie(..., secure=False); and set_cookie() of a session, token, JWT, auth, remember-me, login, user-id or CSRF cookie with no secure= argument (Flask and Django default to insecure). JavaScript/TypeScript: secure: false in cookie or session options (express-session, cookie-session, res.cookie options); res.cookie()/ctx.cookies.set()/Fastify reply.setCookie()/Next.js cookies().set()/cookie.serialize() of such a sensitive cookie whose options are absent or an object literal without secure; document.cookie = \"token=...\" without ; Secure. Java: Cookie.setSecure(false); new Cookie(\"<sensitive name>\" or a same-file String constant holding one, ...) whose variable gets no setSecure(...) call in the next 15 lines; Spring ResponseCookie.from(\"<sensitive name>\", ...) built without .secure(true) or with .secure(false); server.servlet.session.cookie.secure=false in a .properties file. Not reported: a cookie being cleared (empty, null or None value, max_age=0, setMaxAge(0), maxAge(0)), secure taken from a variable, setting or environment, options passed as a variable or spread (they may set secure), non-sensitive cookies left at defaults (theme, lang) and number/boolean flag values (res.cookie('remember', 1)),Flask's default-config dict, development settings files (settings/local.py, dev.py, development.py, test settings), secure: false away from any cookie (SMTP), tests, comments and string literals. VNX-SEC-013 also reports secure/httponly switched off explicitly.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-614/",
	"languages": ["java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [614],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["session", "secure-flag", "cwe-614"],
}

_js_exts := {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

_is_js(path) if {
	some ext in _js_exts
	endswith(path, ext)
}

_sensitive := `(?i)(?:sess|\bsid\b|sid$|token|jwt|auth|remember|login|user_?id|\buid\b|credential|csrf|xsrf)`

_dev_settings(path) if regex.match(`(?i)(?:^|/)(?:settings[_/])?(?:dev|develop|development|local|test|testing|ci)(?:_settings)?\.py$`, path)

_strip(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`)

_opens(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1))

_closes(s) := count(regex.find_all_string_submatch_n(`\)`, s, -1))

# The call starting on line i, up to the line its parentheses close on (at
# most six lines).
_call(lines, i) := txt if {
	end := min([count(lines) - 1, i + 6])
	ks := [k |
		some k in numbers.range(i, end)
		s := _strip(concat("\n", array.slice(lines, i, k + 1)))
		_opens(s) <= _closes(s)
	]
	k := min(array.concat(ks, [end]))
	txt := concat("\n", array.slice(lines, i, k + 1))
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

_flag_re := `\b(?:SESSION|CSRF|REMEMBER)_COOKIE_SECURE["']?\s*\]?\s*=\s*False\b`

# Python: framework setting turned off.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "_COOKIE_SECURE")
	not helpers.is_test_path(path)
	not _dev_settings(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "_COOKIE_SECURE")
	not helpers.is_comment_line(line)
	regex.match(_flag_re, line)
	not regex.match(`^\s*["'][A-Z_]+["']\s*:`, line)
	finding := _finding(path, i, line, "Session/CSRF cookie Secure flag disabled: the cookie is sent over plain HTTP and can be captured. Set it to True")
}

# Python: set_cookie(..., secure=False), or a sensitive cookie with no secure=.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "set_cookie")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "set_cookie")
	not helpers.is_comment_line(line)
	regex.match(`\.set_cookie\s*\(`, _strip(line))
	call := _call(lines, i)
	_py_insecure(call)
	finding := _finding(path, i, line, "Cookie set without the Secure attribute: it is also sent over plain HTTP. Pass secure=True")
}

_py_insecure(call) if regex.match(`\bsecure\s*=\s*False\b`, call)

_py_insecure(call) if {
	m := regex.find_all_string_submatch_n(`\.set_cookie\s*\(\s*(?:key\s*=\s*)?["']([^"']+)["']`, call, 1)
	count(m) > 0
	regex.match(_sensitive, m[0][1])
	not regex.match(`\bsecure\s*=`, call)
	not contains(call, "**")
	not _py_clears(call)
}

# A logout clearing the cookie: empty value or immediate expiry.
_py_clears(call) if regex.match(`\.set_cookie\s*\(\s*(?:key\s*=\s*)?["'][^"']+["']\s*,\s*(?:value\s*=\s*)?(?:""|''|None)\s*[,)]`, call)

_py_clears(call) if regex.match(`\b(?:max_age|expires)\s*=\s*0\b`, call)

# JavaScript: res.cookie / ctx.cookies.set of a sensitive cookie without secure.
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`\.cookies?(?:\.set)?\s*\(|\.setCookie\s*\(|\bcookies?\.serialize\s*\(|\bcookies\(\)\.set\s*\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ookie")
	not helpers.is_comment_line(line)
	regex.match(concat("", [`\b(?:res|resp|response|reply|ctx)\.(?:cookie|cookies\.set|setCookie)\s*\(|`, _js_setter_alt]), _strip(line))
	call := _call(lines, i)
	m := regex.find_all_string_submatch_n(concat("", [_js_setter, `\s*\(\s*["'\x60]([^"'\x60]+)["'\x60]`]), call, 1)
	count(m) > 0
	regex.match(_sensitive, m[0][1])
	not regex.match(`\bsecure\b`, call)
	not contains(call, "...")
	not _options_variable(call)
	not _constant_value(call)
	finding := _finding(path, i, line, "Session/auth cookie set without secure: true: it is also sent over plain HTTP. Add secure: true to the cookie options")
}

# Cookie setters: Express res.cookie, Koa ctx.cookies.set, Fastify
# reply.setCookie, Next.js cookies().set / response.cookies.set, and the
# cookie package's cookie.serialize.
_js_setter := `(?:\.(?:cookie|cookies\.set|setCookie)|\bcookies?\.serialize|\bcookies\(\)\.set)`

_js_setter_alt := `\bcookies?\.serialize\s*\(|\bcookies\(\)\.set\s*\(`

# The value is a number or boolean literal (a flag, not a credential) or the
# empty string (a logout clearing the cookie).
_constant_value(call) if regex.match(concat("", [_js_setter, `\s*\(\s*["'\x60][^"'\x60]+["'\x60]\s*,\s*(?:\d+|true|false|""|''|\x60\x60)\s*[,)]`]), call)

# A third argument that is a plain identifier (options defined elsewhere).
_options_variable(call) if {
	s := _strip(call)
	count(regex.find_all_string_submatch_n(`,`, s, -1)) >= 2
	regex.match(`,\s*[A-Za-z_$][\w$]*(?:\.[\w$]+)*\s*\)\s*;?\s*$`, s)
}

# JavaScript: secure: false in cookie or session options.
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "secure")
	regex.match(`(?i)cookie|session`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "secure")
	not helpers.is_comment_line(line)
	regex.match(`\bsecure\s*:\s*false\b`, _strip(line))
	win := helpers.code_window(lines, i, 8, 0)
	regex.match(`(?i)\bcookie|\bsession\s*\(|cookieSession\s*\(`, win)
	finding := _finding(path, i, line, "Cookie options set secure: false: the cookie is sent over plain HTTP. Use secure: true")
}

# Java: cookie.setSecure(false).
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "setSecure")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "setSecure")
	not helpers.is_comment_line(line)
	regex.match(`\.setSecure\s*\(\s*(?:false|Boolean\.FALSE)\s*\)`, _strip(line))
	finding := _finding(path, i, line, "Cookie.setSecure(false): the cookie is sent over plain HTTP. Call setSecure(true)")
}

# Java: new Cookie("<session/token name>", ...) never given setSecure(true).
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "Cookie(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Cookie(")
	not helpers.is_comment_line(line)
	regex.match(_sensitive, _java_cookie_name(content, line))
	not regex.match(`\bCookie\s*\(\s*(?:"[^"]+"|[A-Za-z_][\w.]*)\s*,\s*(?:""|null)\s*\)`, line)
	v := _cookie_var(lines, i)
	not _secured(lines, i, v)
	not _expired(lines, i, v)
	finding := _finding(path, i, line, "Session/auth cookie created without setSecure(true): it is also sent over plain HTTP")
}

# The variable the cookie is assigned to, on this line or the one above
# (`Cookie c =` / `new Cookie(...)` split over two lines).
_cookie_var(lines, i) := v if {
	v := helpers.assigned_first(lines[i])
} else := v if {
	i > 0
	regex.match(`=\s*$`, lines[i - 1])
	v := helpers.assigned_first(concat(" ", [lines[i - 1], trim_space(lines[i])]))
}

_secured(lines, i, v) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 15]))
	regex.match(concat("", [`\b`, v, `\.setSecure\s*\(`]), lines[k])
}

# A cookie being deleted (setMaxAge(0)) carries no credential.
_expired(lines, i, v) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 15]))
	regex.match(concat("", [`\b`, v, `\.setMaxAge\s*\(\s*0\s*\)`]), lines[k])
}

# JavaScript: document.cookie = "token=..." without ; Secure.
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "document.cookie")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "document.cookie")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\bdocument\.cookie\s*=\s*["'\x60]\s*([\w.-]+)=`, line, 1)
	count(m) > 0
	regex.match(_sensitive, m[0][1])
	not regex.match(`(?i)\bsecure\b`, line)
	not regex.match(`=\s*["'\x60]\s*[\w.-]+=\s*;`, line)
	finding := _finding(path, i, line, "Sensitive cookie written from script without ; Secure: it is also sent over plain HTTP")
}

# Java (Spring): ResponseCookie.from("<sensitive name>", ...) built without
# .secure(true), or with .secure(false).
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "ResponseCookie")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ResponseCookie")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\bResponseCookie\s*\.\s*(?:from|fromClientResponse)\s*\(\s*"([^"]+)"\s*,\s*([^)]*)\)`, line, 1)
	count(m) > 0
	chain := _builder_chain(lines, i)
	_rc_insecure(m[0][1], m[0][2], chain)
	finding := _finding(path, i, line, "Session/auth cookie built without .secure(true): it is also sent over plain HTTP")
}

# The builder chain from line i to the line holding .build() (at most 8 lines).
_builder_chain(lines, i) := txt if {
	end := min([count(lines) - 1, i + 8])
	ks := [k | some k in numbers.range(i, end); contains(lines[k], ".build()")]
	k := min(array.concat(ks, [end]))
	txt := concat("\n", array.slice(lines, i, k + 1))
}

_rc_insecure(name, value, chain) if regex.match(`\.secure\s*\(\s*(?:false|Boolean\.FALSE)\s*\)`, chain)

_rc_insecure(name, value, chain) if {
	regex.match(_sensitive, name)
	not regex.match(`\.secure\s*\(`, chain)
	trim_space(value) != `""`
	not regex.match(`\.maxAge\s*\(\s*(?:0|0L|Duration\.ZERO)\s*\)`, chain)
}

# Spring Boot: server.servlet.session.cookie.secure=false in a properties file.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".properties")
	contains(content, "cookie.secure")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "cookie.secure")
	regex.match(`^\s*server\.(?:servlet\.)?(?:reactive\.)?session\.cookie\.secure\s*[=:]\s*false\s*$`, line)
	finding := _finding(path, i, line, "Spring session cookie Secure flag disabled: the session cookie is sent over plain HTTP. Set it to true")
}

# The cookie name of new Cookie(...): a string literal, or a String constant
# of the same file (static final String COOKIE_NAME = "session").
_java_cookie_name(content, line) := n if {
	m := regex.find_all_string_submatch_n(`\bnew\s+(?:[\w.]+\.)?Cookie\s*\(\s*"([^"]+)"`, line, 1)
	n := m[0][1]
} else := n if {
	m := regex.find_all_string_submatch_n(`\bnew\s+(?:[\w.]+\.)?Cookie\s*\(\s*(?:[A-Z]\w*\.)?([A-Z][A-Z0-9_]*)\s*,`, line, 1)
	c := regex.find_all_string_submatch_n(concat("", [`\bString\s+`, m[0][1], `\s*=\s*"([^"]+)"`]), content, 1)
	n := c[0][1]
}
