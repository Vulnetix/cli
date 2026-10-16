# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1004",
	"name": "Sensitive cookie set without the HttpOnly flag",
	"description": "A cookie whose name says it carries a session, authentication or identity value (session, sess, sid, auth, token, jwt, access/refresh, remember, login, credential, userid/uid, admin, role, JSESSIONID, PHPSESSID; a constant naming the cookie is resolved within the file) is set without HttpOnly, so any script injected into the page can read it. Reported: Go http.Cookie{...} literals without HttpOnly: true (and no later .HttpOnly = true), and HttpOnly: false in a session store's Options; Express res.cookie(...) and Fastify reply.setCookie(...) without httpOnly: true, an explicit httpOnly: false in session/cookie options, and document.cookie assignments of such a cookie; PHP setcookie()/setrawcookie() without the httponly argument or with it false (positional or options array), ini_set('session.cookie_httponly', 0/false/'0'/'off') and session_set_cookie_params with httponly false; Python set_cookie(...) (Flask, Django, Starlette) without httponly=True, and SESSION_COOKIE_HTTPONLY = False; Java new Cookie(...) with no setHttpOnly(true) on it within the next lines, ResponseCookie.from(...) builders without .httpOnly(true), and server.servlet.session.cookie.http-only=false. Not reported: cookies with other names (preferences and lookalikes such as author_view, accessibility_mode, controller_layout, CSRF/XSRF tokens, which double-submit schemes must let scripts read), cookies being deleted (empty or None value), wrappers that take HttpOnly as a parameter, Koa ctx.cookies.set (HttpOnly by default), test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1004/",
	"languages": ["go", "node", "php", "python", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1004],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cookie", "httponly", "session", "cwe-1004"],
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

# "auth" but not "author", "access" but not "accessibility", "role" only at
# the start of a word (not "controller").
_sensitive_re := `(?i)sess|auth(?:$|[^o]|oriz)|token|jwt|(?:^|[^a-z])sid|remember|login|credential|refresh|access(?:$|[^i])|user_?id|(?:^|[^a-z])uid|admin|(?:^|[^a-z])roles?(?:$|[^a-z])|(?-i:[a-z]Roles?(?:$|[^a-z]))`

_csrf_re := `(?i)csrf|xsrf`

# A cookie name expression is sensitive when its literal (or, for an
# identifier, the literal it is assigned in this file, else the identifier
# itself) names a session/auth/identity value and is not a CSRF token.
_sensitive(content, expr) if {
	n := _name_text(content, expr)
	regex.match(_sensitive_re, n)
	not regex.match(_csrf_re, n)
}

_name_text(_, expr) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*["'\x60]([^"'\x60]*)["'\x60]`, expr, 1)
	count(m) > 0
}

_name_text(content, expr) := v if {
	not regex.match(`^\s*["'\x60]`, expr)
	m := regex.find_all_string_submatch_n(`^\s*\$?([A-Za-z_][\w.]*)\s*$`, expr, 1)
	count(m) > 0
	id := m[0][1]
	parts := split(id, ".")
	last := parts[count(parts) - 1]
	v := _const_or(content, last, id)
}

_name_text(_, expr) := expr if {
	not regex.match(`^\s*["'\x60]`, expr)
	not regex.match(`^\s*\$?[A-Za-z_][\w.]*\s*$`, expr)
}

_const_or(content, name, _) := c[0][1] if {
	c := regex.find_all_string_submatch_n(concat("", [`\b`, name, `\s*(?::[^=\n]*)?=\s*["']([^"'\n]+)["']`]), content, 1)
	count(c) > 0
}

_const_or(content, name, d) := d if {
	count(regex.find_all_string_submatch_n(concat("", [`\b`, name, `\s*(?::[^=\n]*)?=\s*["']([^"'\n]+)["']`]), content, 1)) == 0
}

# Text of the bracketed construct opened on line i, from `rest` through the
# line that balances `open`/`close` (at most `span` lines on).
_block_text(lines, i, rest, open, close, span) := txt if {
	last := min([count(lines) - 1, i + span])
	ends := [k |
		some k in numbers.range(i, last)
		_balance(lines, i, k, rest, open, close) <= 0
	]
	end := _first_or(ends, last)
	more := [lines[k] | some k in numbers.range(i + 1, end); end > i]
	txt := concat("\n", array.concat([rest], more))
}

_first_or(arr, _) := arr[0] if count(arr) > 0

_first_or(arr, d) := d if count(arr) == 0

_balance(lines, i, k, rest, open, close) := b if {
	parts := array.concat([rest], [lines[m] | some m in numbers.range(i + 1, k); k > i])
	s := _strip(concat("\n", parts))
	b := strings.count(s, open) - strings.count(s, close)
}

_strip(s) := regex.replace(s, `"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|\x60[^\x60]*\x60`, `""`)

# Top-level arguments of a call whose text starts at its "(".
_args(call) := args if {
	s := _strip(call)
	m := regex.find_all_string_submatch_n(`^\(((?:[^()]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*)\)`, s, 1)
	count(m) > 0
	args := [trim_space(x[0]) | some x in regex.find_all_string_submatch_n(`(?:[^,()\[\]{}]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|\[(?:[^\[\]]|\[(?:[^\[\]]|\[[^\[\]]*\])*\])*\]|\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})+`, m[0][1], -1)]
}

# First argument of a call, taken from the raw text so a literal keeps its value.
_first_raw(call) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\(\s*((?:["'\x60][^"'\x60]*["'\x60])|[$\w.\->]+)`, call, 1)
	count(m) > 0
}

# A deletion: the value is an empty literal, None/null or the expiry is in the past.
_deleting(call) if regex.match(`^\(\s*[^,]+,\s*(?:""|''|None|null|nil)\s*[,)]`, call)

_deleting(call) if regex.match(`(?i)max_?age\s*[:=]\s*-1|expires\s*[:=]\s*(?:time\.Unix\(0|new Date\(0\)|0\b)`, call)

# ── Go ───────────────────────────────────────────────────────────────────

findings contains _finding(path, i, line, "Session or auth cookie built without HttpOnly: true: a script injected into the page can read it. Set HttpOnly: true") if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	contains(content, "http.Cookie{")
	lines := split(content, "\n")
	some i, line in lines
	idx := indexof(line, "http.Cookie{")
	idx >= 0
	not helpers.is_comment_line(line)
	lit := _block_text(lines, i, substring(line, idx + 11, -1), "{", "}", 15)
	not _go_on(_go_code(lit))
	m := regex.find_all_string_submatch_n(`\bName\s*:\s*([^,\n}]+)`, _go_code(lit), 1)
	count(m) > 0
	_sensitive(content, m[0][1])
	not _deleting(lit)
	not _go_set_later(lines, i)
}

_go_code(s) := regex.replace(s, `//[^\n]*`, "")

_go_set_later(lines, i) if {
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 20]))
	regex.match(`\.HttpOnly\s*=\s*true`, lines[k])
}

findings contains _finding(path, i, line, "Session store configured with HttpOnly: false: the session cookie is readable by any script in the page. Set HttpOnly: true") if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	regex.match(`HttpOnly\s*:\s*false`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*HttpOnly\s*:\s*false\b`, line)
	opener := _go_opener(lines, i)
	regex.match(`(?i)sessions?\.Options\{|SessionOptions\{|session|store`, opener)
	not contains(opener, "http.Cookie{")
}

_go_opener(lines, i) := lines[j] if {
	js := [k |
		some d in numbers.range(1, min([i, 12]))
		k := i - d
		contains(lines[k], "{")
	]
	count(js) > 0
	j := js[0]
}

# ── Node.js ──────────────────────────────────────────────────────────────

_js_ext(path) if regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx)$`, path)

findings contains _finding(path, i, line, "Session or auth cookie set without httpOnly: true (Express and Fastify default to false): a script injected into the page can read it. Pass { httpOnly: true }") if {
	some path, content in input.file_contents
	_js_ext(path)
	not helpers.is_test_path(path)
	regex.match(`\.(?:cookie|setCookie)\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`\b(?:res|resp|response|reply)\.(?:cookie|setCookie)\s*(\(.*)$`, line, 1)
	count(m) > 0
	regex.match(`\b(?:res|resp|response|reply)\.(?:cookie|setCookie)\s*\(`, _strip(line))
	not helpers.is_comment_line(line)
	call := _block_text(lines, i, m[0][1], "(", ")", 8)
	not regex.match(`httpOnly\s*:\s*(?:true|!0|[A-Za-z_])`, call)
	_sensitive(content, _first_raw(call))
	not _deleting(call)
	_js_opts_unprotected(content, call)
	not _n029_call(path, content, lines, i, line)
}

# No options, or an options object literal (already known to lack httpOnly),
# or an options variable while the file never sets httpOnly: true.
_js_opts_unprotected(_, call) if count(_args(call)) < 3

_js_opts_unprotected(_, call) if {
	args := _args(call)
	count(args) >= 3
	startswith(args[2], "{")
}

_js_opts_unprotected(content, call) if {
	args := _args(call)
	count(args) >= 3
	not startswith(args[2], "{")
	not regex.match(`httpOnly\s*:\s*true`, content)
}

findings contains _finding(path, i, line, "Cookie options set httpOnly: false for a session cookie: any script in the page can read it. Remove the override (express-session and cookie-session default to true)") if {
	some path, content in input.file_contents
	_js_ext(path)
	not helpers.is_test_path(path)
	regex.match(`httpOnly\s*:\s*false`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\bhttpOnly\s*:\s*false\b`, line)
	not helpers.is_comment_line(line)
	win := helpers.code_window(lines, i, 8, 2)
	regex.match(`(?i)session\s*\(|cookieSession\s*\(|\.cookie\s*\(|setCookie\s*\(|cookie\s*:|cookieOptions|sessionOptions`, win)
	not regex.match(_csrf_re, win)
	not _n029_off(path, lines, i, line)
}

findings contains _finding(path, i, line, "Session or auth token written to document.cookie: a cookie set from script can never be HttpOnly, so any injected script can read it. Set it from the server with HttpOnly") if {
	some path, content in input.file_contents
	_js_ext(path)
	not helpers.is_test_path(path)
	contains(content, "document.cookie")
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`document\.cookie\s*=\s*["'\x60]\s*([A-Za-z_][\w.-]*)\s*=`, line, 1)
	count(m) > 0
	not helpers.is_comment_line(line)
	regex.match(_sensitive_re, m[0][1])
	not regex.match(_csrf_re, m[0][1])
	not regex.match(`(?i)=\s*;|expires\s*=\s*Thu,\s*01 Jan 1970|max-age\s*=\s*(?:0|-1)\b`, line)
}

# ── PHP ──────────────────────────────────────────────────────────────────

findings contains _finding(path, i, line, "Session or auth cookie set without the httponly flag: a script injected into the page can read it. Pass httponly true (seventh argument or 'httponly' => true)") if {
	some path, content in input.file_contents
	endswith(path, ".php")
	not helpers.is_test_path(path)
	contains(content, "setcookie(")
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`\bset(?:raw)?cookie\s*(\(.*)$`, line, 1)
	count(m) > 0
	regex.match(`\bset(?:raw)?cookie\s*\(`, _strip(line))
	not helpers.is_comment_line(line)
	call := _block_text(lines, i, m[0][1], "(", ")", 8)
	_sensitive(content, _first_raw(call))
	not _deleting(call)
	not regex.match(`^\(\s*[^,]+,\s*(?:""|'')\s*,\s*(?:time\(\)\s*-|1\s*[,)])`, call)
	_php_no_httponly(call)
}

_php_no_httponly(call) if {
	args := _args(call)
	count(args) < 7
	not _php_opts_array(args)
}

_php_no_httponly(call) if {
	args := _args(call)
	count(args) >= 7
	regex.match(`^(?i:false|0)$`, args[6])
}

_php_no_httponly(call) if {
	args := _args(call)
	_php_opts_array(args)
	not regex.match(`(?i)['"]httponly['"]\s*=>\s*(?:true|1|\$)`, call)
}

_php_opts_array(args) if {
	count(args) >= 3
	regex.match(`^(?:\[|array\()`, args[2])
}

findings contains _finding(path, i, line, "Session cookie HttpOnly turned off: PHPSESSID becomes readable by any script in the page. Set session.cookie_httponly to 1") if {
	some path, content in input.file_contents
	endswith(path, ".php")
	not helpers.is_test_path(path)
	regex.match(`session\.cookie_httponly|session_set_cookie_params`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	_php_session_off(lines, i, line)
}

_php_session_off(_, _, line) if {
	regex.match(`(?i)ini_set\(\s*['"]session\.cookie_httponly['"]\s*,\s*(?:0|false|['"](?:0|off|false)?['"])\s*\)`, line)
}

_php_session_off(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`\bsession_set_cookie_params\s*(\(.*)$`, line, 1)
	count(m) > 0
	call := _block_text(lines, i, m[0][1], "(", ")", 10)
	_php_params_off(call)
}

_php_params_off(call) if regex.match(`(?i)['"]httponly['"]\s*=>\s*(?:false|0)\b`, call)

_php_params_off(call) if {
	args := _args(call)
	count(args) >= 5
	regex.match(`^(?i:false|0)$`, args[4])
}

# ── Python ───────────────────────────────────────────────────────────────

findings contains _finding(path, i, line, "Session or auth cookie set without httponly=True (Flask, Django and Starlette default to False): a script injected into the page can read it. Pass httponly=True") if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "set_cookie(")
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`\.set_cookie\s*(\(.*)$`, line, 1)
	count(m) > 0
	regex.match(`\.set_cookie\s*\(`, _strip(line))
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:async\s+)?def\s`, line)
	call := _block_text(lines, i, m[0][1], "(", ")", 8)
	not _py_httponly_on(call)
	_sensitive(content, _py_name(call))
	not _py_deleting(call)
	not regex.match(`\*\*\w+`, call)
}

# httponly= given a value other than False (True or a variable).
_py_httponly_on(call) if {
	some m in regex.find_all_string_submatch_n(`httponly\s*=\s*([A-Za-z_]\w*)`, call, -1)
	m[1] != "False"
}

_py_name(call) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`\bkey\s*=\s*((?:["'][^"']*["'])|[\w.]+)`, call, 1)
	count(m) > 0
}

_py_name(call) := n if {
	not regex.match(`\bkey\s*=`, call)
	n := _first_raw(call)
}

_py_deleting(call) if _deleting(call)

_py_deleting(call) if regex.match(`\bvalue\s*=\s*(?:None|""|'')`, call)

_py_deleting(call) if regex.match(`max_age\s*=\s*0\b`, call)

findings contains _finding(path, i, line, "SESSION_COOKIE_HTTPONLY disabled: the framework session cookie becomes readable by any script in the page. Leave it True") if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "SESSION_COOKIE_HTTPONLY")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\bSESSION_COOKIE_HTTPONLY["']?\s*\]?\s*(?:=|:)\s*False\b`, line)
	not helpers.is_comment_line(line)
}

# ── Java ─────────────────────────────────────────────────────────────────

findings contains _finding(path, i, line, "Session or auth cookie created without setHttpOnly(true): a script injected into the page can read it. Call cookie.setHttpOnly(true) before adding it") if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "new Cookie(")
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`\b(?:Cookie\s+)?(\w+)\s*=\s*new\s+(?:javax\.servlet\.http\.|jakarta\.servlet\.http\.)?Cookie\s*(\(.*)$`, line, 1)
	count(m) > 0
	not helpers.is_comment_line(line)
	regex.match(`\bnew\s+[\w.]*Cookie\s*\(`, _strip(line))
	v := m[0][1]
	call := m[0][2]
	_sensitive(content, _first_raw(call))
	not _deleting(call)
	not _java_protected(lines, i, v)
}

_java_protected(lines, i, v) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 15]))
	regex.match(concat("", [`\b`, v, `\.setHttpOnly\(\s*true\s*\)`]), lines[k])
}

_java_protected(lines, i, v) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 15]))
	regex.match(concat("", [`\b`, v, `\.setMaxAge\(\s*0\s*\)`]), lines[k])
}

findings contains _finding(path, i, line, "Session or auth ResponseCookie built without .httpOnly(true): a script injected into the page can read it. Add .httpOnly(true) to the builder") if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "ResponseCookie.from(")
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`\bResponseCookie\.from\s*(\(.*)$`, line, 1)
	count(m) > 0
	not helpers.is_comment_line(line)
	_sensitive(content, _first_raw(m[0][1]))
	chain := _java_chain(lines, i)
	not regex.match(`\.httpOnly\(\s*true\s*\)`, chain)
	not regex.match(`\.maxAge\(\s*0\s*\)`, chain)
}

_java_chain(lines, i) := txt if {
	last := min([count(lines) - 1, i + 10])
	ends := [k | some k in numbers.range(i, last); contains(lines[k], ";")]
	end := _first_or(ends, last)
	txt := concat("\n", [lines[k] | some k in numbers.range(i, end)])
}

findings contains _finding(path, i, line, "Servlet session cookie HttpOnly turned off: JSESSIONID becomes readable by any script in the page. Remove the override") if {
	some path, content in input.file_contents
	endswith(path, ".properties")
	contains(content, "http-only")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*server\.servlet\.session\.cookie\.http-only\s*[=:]\s*false\s*$`, line)
}

_go_on(lit) if {
	regex.match(`\bHttpOnly\s*:\s*\w`, lit)
	not regex.match(`\bHttpOnly\s*:\s*false\b`, lit)
}

# ── Node.js lines VNX-NODE-029 reports ──────────────────────────────────
# VNX-NODE-029 is the Node.js form of this rule (CWE-1004): it reports an
# Express/Fastify res.cookie()/reply.setCookie() of a session or credential
# cookie without httpOnly, and httpOnly: false next to a cookie call. This
# rule leaves those lines to it and keeps the Node.js shapes VNX-NODE-029
# does not see (a cookie named only for an identity or role, such as
# user_id or admin; express-session options; document.cookie). The
# conditions below mirror VNX-NODE-029's.
_n029_call_re := `(?:\b(?:res|resp|response|reply)\.(?:cookie|setCookie)|\bcookie\.serialize)\s*\(`

_n029_sensitive_re := `(?i)(sess|\bsid\b|sid['"]|token|auth(?:$|[^o]|o[^r])|jwt|login|identity|credential|bearer|access(?:$|[^i])|refresh|remember_?me)`

_n029_strip(s) := regex.replace(s, concat("", [`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`, "`[^`]*`"]), `''`)

_n029_depth(lines, s, j) := sum([d |
	some k in numbers.range(s, j)
	c := _n029_strip(lines[k])
	d := strings.count(c, "(") - strings.count(c, ")")
])

_n029_call_end(lines, i) := e if {
	hi := min([count(lines) - 1, i + 8])
	ends := [j | some j in numbers.range(i, hi); _n029_depth(lines, i, j) <= 0]
	e := min(array.concat(ends, [hi]))
}

_n029_call_text(lines, i) := concat("\n", [l | some k in numbers.range(i, _n029_call_end(lines, i)); l := lines[k]; not helpers.is_comment_line(l)])

_n029_args(text) := a if {
	m := regex.find_all_string_submatch_n(concat("", ["(?s)", _n029_call_re, `(.*)$`]), text, 1)
	count(m) > 0
	a := m[0][1]
}

_n029_head(args) := concat(",", array.slice(split(split(replace(args, "${", "$<"), "{")[0], ","), 0, 2))

_n029_clearing(args) if trim_space(split(split(args, "{")[0], ",")[1]) in {"''", `""`, "``", "null", "undefined"}

_n029_clearing(args) if regex.match(`expires\s*:\s*new Date\(\s*0\s*\)|maxAge\s*:\s*0\b`, args)

_n029_httponly_true(content, args) if {
	not contains(args, "{")
	parts := split(args, ",")
	count(parts) >= 3
	id := trim(trim_space(parts[2]), ") ;")
	regex.match(`^[A-Za-z_$][\w$.]*$`, id)
	regex.match(concat("", [`(?s)\b`, id, `\b[^=\n]*=\s*\{[^}]*httpOnly\s*:\s*true`]), content)
}

_n029_unknown_options(content, args) if {
	not contains(args, "{")
	parts := split(args, ",")
	count(parts) >= 3
	id := trim(trim_space(parts[2]), ") ;")
	regex.match(`^[A-Za-z_$][\w$.]*$`, id)
	not regex.match(concat("", [`\b`, id, `\b[^=\n]*=\s*\{`]), content)
}

_n029_unknown_options(_, args) if {
	not contains(args, "{")
	parts := split(args, ",")
	count(parts) >= 3
	regex.match(`^\s*[A-Za-z_$][\w$.]*\s*\(`, parts[2])
}

_n029_unknown_options(_, args) if regex.match(`\{\s*\.\.\.|,\s*\.\.\.[A-Za-z_$]`, args)

# VNX-NODE-029 reports this cookie call.
_n029_call(path, content, lines, i, line) if {
	not endswith(path, ".min.js")
	contains(line, "ookie")
	regex.match(_n029_call_re, _n029_strip(line))
	args := _n029_args(_n029_call_text(lines, i))
	head := _n029_head(args)
	regex.match(_n029_sensitive_re, head)
	not regex.match(_csrf_re, head)
	not _n029_clearing(args)
	not regex.match(`\bhttpOnly\s*:`, args)
	not _n029_httponly_true(content, args)
	not _n029_unknown_options(content, args)
}

# VNX-NODE-029 reports this httpOnly: false.
_n029_off(path, lines, i, line) if {
	not endswith(path, ".min.js")
	regex.match(`\bhttpOnly\s*:\s*false\b`, line)
	some j in numbers.range(max([0, i - 6]), i)
	regex.match(`\.cookies?\s*\(|\.cookies\.set\s*\(|setCookie\s*\(|\bserialize\s*\(`, lines[j])
	not helpers.is_comment_line(lines[j])
}
