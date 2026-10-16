package vulnetix.rules.vnx_sec_013

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-SEC-013",
	"name": "Insecure cookie configuration",
	"description": "A cookie's HttpOnly or Secure protection is switched off, or a session or authentication cookie is issued without HttpOnly. Reported: httpOnly/secure/http-only set to false in cookie options (express-session and res.cookie options, Go http.Cookie and gorilla sessions.Options, ASP.NET CookieOptions, rack and Rails session_store, Spring application.yml, PHP 'httponly' => false); Django and Flask SESSION_COOKIE_SECURE / SESSION_COOKIE_HTTPONLY / CSRF_COOKIE_SECURE / REMEMBER_COOKIE_* = False (also app.config[...] = False and config.update(...)); Python set_cookie(..., secure=False / httponly=False); Java cookie.setHttpOnly(false)/setSecure(false), Spring ResponseCookie .httpOnly(false)/.secure(false) and Kotlin cookie.isHttpOnly = false; Spring server.servlet.session.cookie.secure/http-only=false; CookieSecurePolicy.None and web.config httpCookies httpOnlyCookies=\"false\"/requireSSL=\"false\"; PHP ini_set('session.cookie_httponly'/'session.cookie_secure', 0) and the php.ini / .htaccess equivalents; false as the secure or httponly argument of PHP setcookie() or gin's c.SetCookie(); and a cookie whose name or value names a session, token, auth, JWT, remember-me, login or user id issued without any HttpOnly setting (Express res.cookie, Fastify reply.setCookie, Next.js response.cookies.set / cookies().set, a document.cookie assignment (which can never be HttpOnly), Python set_cookie (also with its arguments on following lines), ASP.NET Core Response.Cookies.Append with no CookieOptions, Rails cookies[:name] = value or a hash with no httponly, a Spring ResponseCookie.from builder with no httpOnly(...), a Go http.Cookie or fiber.Cookie literal with no HttpOnly/HTTPOnly field, Java new Cookie with no setHttpOnly, PHP setcookie with fewer than seven arguments). Not reported: a document.cookie assignment that clears the cookie (empty value, Max-Age=0, a 1970 expiry), Koa ctx.cookies.set (HttpOnly by default), the CSRF/XSRF cookie's HttpOnly (JavaScript must read it), non-session cookies left at defaults (theme, language), flags taken from variables or the environment, options passed as a variable, Django CSRF_COOKIE_HTTPONLY, Flask's own default-config dict, unrelated secure: false options (SMTP, WebSocket clients) away from any cookie, variable declarations named secure/httpOnly, development settings files (settings/local.py, application-dev.yml), tests, comments and documentation.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-013/",
	"languages": [],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [614, 1004],
	"capec": ["CAPEC-31"],
	"attack_technique": ["T1539"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cookies", "session", "web-security"],
}

_ext_re := `(?i)(\.(js|jsx|mjs|cjs|ts|tsx|py|go|java|kt|kts|cs|php|rb|properties|ya?ml|config|ini)|(^|/)\.htaccess)$`

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(?i)\.min\.js$|(^|/)(node_modules|vendor)/`, path)

_skip(path) if regex.match(`(^|/)([A-Za-z]+Tests?|[A-Za-z.]+\.Tests?)/`, path)

# Development settings deliberately run over plain HTTP.
_skip(path) if regex.match(`(?i)(^|/)(settings/)?(local|dev|develop|development|test|testing)(_settings)?\.py$|settings_(local|dev|development|test)\.py$|application-(dev|local|test)\.(properties|ya?ml)$`, path)

# ── Flags switched off ──────────────────────────────────────────────────

# String literals removed, so `"Set httpOnly: false ..."` is not an option.
_strip(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_off_key_re := `(?i)(?:^|[\s{,(.])(httponly|http-only|http_only|secure)\s*[:=]\s*false\b`

_decl_re := `(?i)\b(var|val|let|const|private|public|protected|internal|bool|boolean|final|static)\s+(httponly|secure)\b|\$\w*(httponly|secure)\s*=`

_cookie_ctx(lines, i) if regex.match(`(?i)cookie|\bsession\b|session\(|sessions\.`, _strip(helpers.code_window(lines, i, 10, 1)))

_csrf_ctx(lines, i) if regex.match(`(?i)xsrf|csrf`, helpers.code_window(lines, i, 6, 0))

_off(path, content, lines, i, line) if {
	m := regex.find_all_string_submatch_n(_off_key_re, _strip(line), -1)
	count(m) > 0
	not regex.match(_decl_re, line)
	_cookie_ctx(lines, i)
	name := lower(m[0][1])
	_flag_counts(name, lines, i)
	some mm in m
	flag := lower(mm[1])
	_flag_counts(flag, lines, i)
	not _key_owned(path, content, lines, i, line, flag)
}

_off(path, _, lines, i, line) if {
	endswith(path, ".php")
	regex.match(`(?i)["']httponly["']\s*=>\s*false\b`, line)
	not _csrf_ctx(lines, i)
	not _o1004_php_call(line)
}

_off(path, _, _, _, line) if {
	endswith(path, ".php")
	regex.match(`(?i)["']secure["']\s*=>\s*false\b`, line)
}

# HttpOnly may be off on the CSRF cookie: the page's script must read it.
_flag_counts(name, lines, i) if {
	name in {"httponly", "http-only", "http_only"}
	not _csrf_ctx(lines, i)
}

_flag_counts(name, _, _) if name == "secure"

_off(path, _, _, _, line) if {
	endswith(path, ".py")
	some m in regex.find_all_string_submatch_n(`\b(SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|CSRF_COOKIE_SECURE|REMEMBER_COOKIE_SECURE|REMEMBER_COOKIE_HTTPONLY)["']?\s*\]?\s*=\s*False\b`, line, -1)
	not _py_setting_owned(path, m[1])
}

_off(path, _, lines, i, line) if {
	regex.match(`\.(java|kt|kts)$`, path)
	some m in regex.find_all_string_submatch_n(`\.(set(?:HttpOnly|Secure)|httpOnly|secure)\(\s*false\s*\)`, line, -1)
	regex.match(`Cookie`, helpers.code_window(lines, i, 10, 0))
	not _java_off_owned(path, line, m[1])
}

_off(path, _, _, _, line) if {
	regex.match(`\.(kt|kts)$`, path)
	regex.match(`(?i)\w*cookie\w*\.is(HttpOnly|Secure)\s*=\s*false\b`, line)
}

_off(path, _, _, _, line) if {
	regex.match(`(?i)\.(properties|ya?ml)$`, path)
	regex.match(`(?i)session\.cookie\.(secure|http-only|httponly)\s*[=:]\s*false\b`, line)
	not _properties_owned(path, line)
}

_off(path, _, _, _, line) if {
	endswith(path, ".cs")
	regex.match(`\bCookieSecurePolicy\.None\b`, line)
}

_off(path, _, _, _, line) if {
	regex.match(`(?i)\.config$`, path)
	regex.match(`(?i)<\s*(httpCookies|forms)\b`, line)
	regex.match(`(?i)\b(httpOnlyCookies|requireSSL)\s*=\s*["']false["']`, line)
}

_off(path, _, _, _, line) if {
	endswith(path, ".php")
	regex.match(`(?i)\bini_set\(\s*["']session\.cookie_(httponly|secure)["']\s*,\s*(?:0|false|off|["'](?:0|off|false)?["'])\s*\)`, line)
	not regex.match(`(?i)ini_set\(\s*['"]session\.cookie_httponly['"]\s*,\s*(?:0|false|['"](?:0|off|false)?['"])\s*\)`, line)
}

_off(path, _, _, _, line) if {
	regex.match(`(?i)(\.ini|(^|/)\.htaccess)$`, path)
	regex.match(`(?i)^\s*(?:php_(?:admin_)?(?:flag|value)\s+)?session\.cookie_(httponly|secure)\s*=?\s*(0|off|false|"0"|""|'0')\s*(;.*)?$`, line)
}

# false as the 6th (secure) or 7th (httponly) argument of PHP setcookie /
# setrawcookie or gin's Context.SetCookie.
_off(path, _, _, _, line) if {
	regex.match(`\.(php|go)$`, path)
	regex.match(`\b(?:setcookie|setrawcookie|SetCookie)\s*\(([^,()]*(?:\([^()]*\))?[^,()]*,){5}\s*false\b`, line)
}

_off(path, _, lines, i, line) if {
	regex.match(`\.(php|go)$`, path)
	regex.match(`\b(?:setcookie|setrawcookie|SetCookie)\s*\(([^,()]*(?:\([^()]*\))?[^,()]*,){6}\s*false\b`, line)
	not _csrf_ctx(lines, i)
	not _php_seventh_owned(path, line)
}

# ── Session cookie issued without HttpOnly ──────────────────────────────
_sensitive_re := `(?i)sess|token|auth|jwt|\bsid\b|remember|login|user_?id|\buid\b|access|refresh|identity|credential`

_sensitive(s) if {
	regex.match(_sensitive_re, s)
	not regex.match(`(?i)csrf|xsrf`, s)
}

# The text of a call opened on line i, up to the line that closes it.
_call_text(lines, i) := t if {
	end := min([count(lines) - 1, i + 8])
	closers := [k | some k in numbers.range(i, end); regex.match(`\)\s*[;,]?\s*(?://.*|#.*)?$`, lines[k])]
	stop := min(array.concat([end], closers))
	t := concat("\n", [l | some k in numbers.range(i, stop); l := lines[k]])
}

_missing(path, content, lines, i, line) if {
	regex.match(`\.(js|jsx|mjs|cjs|ts|tsx)$`, path)
	m := regex.find_all_string_submatch_n(`\b(?:res\.cookie|(?:reply|res|response)\.setCookie|(?:res|response)\.cookies\.set|cookies\(\)\.set)\(\s*([^,]+),\s*([^,{]+?)\s*(?:,\s*([{A-Za-z_])|\))`, line, 1)
	count(m) > 0
	m[0][3] in {"", "{"}
	_sensitive(concat(" ", [m[0][1], m[0][2]]))
	not _flag_value(m[0][2])
	not regex.match(`(?i)httponly`, _call_text(lines, i))
	not _o029_call(path, content, lines, i, line)
	not _o1004_js_call(lines, i, line)
}

_missing(path, _, lines, i, line) if {
	endswith(path, ".py")
	contains(line, ".set_cookie(")
	t := _py_call_text(lines, i)
	flat := replace(t, "\n", " ")
	m := regex.find_all_string_submatch_n(`\.set_cookie\(\s*([^,]+),\s*([^,]+)`, flat, 1)
	count(m) > 0
	_sensitive(concat(" ", [m[0][1], m[0][2]]))
	not _flag_value(m[0][2])
	not regex.match(`(?i)httponly|\*\*`, t)
	not _o1004_py_call(line, t)
}

# A Python call: the line itself when its parentheses balance, otherwise up to
# the line that closes the call with a bare ")".
_py_call_text(lines, i) := lines[i] if {
	count(indexof_n(lines[i], "(")) <= count(indexof_n(lines[i], ")"))
}

_py_call_text(lines, i) := t if {
	count(indexof_n(lines[i], "(")) > count(indexof_n(lines[i], ")"))
	end := min([count(lines) - 1, i + 10])
	closers := [k | some k in numbers.range(i + 1, end); regex.match(`^\s*\)`, lines[k])]
	stop := min(array.concat([end], closers))
	t := concat("\n", [l | some k in numbers.range(i, stop); l := lines[k]])
}

# document.cookie can never be HttpOnly: a session or auth token written from
# script is readable by any script on the page.
_missing(path, _, _, _, line) if {
	regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|html?|vue|svelte)$`, path)
	m := regex.find_all_string_submatch_n("\\bdocument\\.cookie\\s*=\\s*[\"'`]\\s*([A-Za-z0-9_.\\-]+)=([^;\"'`]*)", line, 1)
	count(m) > 0
	_sensitive(m[0][1])
	not regex.match(`(?i)max-age=0\b|expires=thu,\s*01 jan 1970`, line)
	not _js_cleared(m[0][2], line)
	not _o1004_document_cookie(path, line)
}

# 'auth=; Max-Age=0' or "token=" + "" clears the cookie.
_js_cleared(v, line) if {
	trim_space(v) == ""
	not regex.match("[\"'`]\\s*\\+|\\$\\{", line)
}

# ASP.NET Core Response.Cookies.Append(name, value) with no CookieOptions:
# HttpOnly defaults to false.
_missing(path, _, _, _, line) if {
	endswith(path, ".cs")
	m := regex.find_all_string_submatch_n(`\.Cookies\.Append\(\s*([^,()]+),\s*([^,()]*(?:\([^()]*\))?[^,()]*)\)\s*;`, line, 1)
	count(m) > 0
	_sensitive(m[0][1])
	not _flag_value(m[0][2])
}

# Rails cookies jar: cookies[:auth_token] = value, or a hash with no httponly.
_missing(path, _, lines, i, line) if {
	endswith(path, ".rb")
	m := regex.find_all_string_submatch_n(`\bcookies(?:\.(?:permanent|signed|encrypted))*\[\s*:?["']?(\w+)["']?\s*\]\s*=\s*(.+?)\s*$`, line, 1)
	count(m) > 0
	_sensitive(m[0][1])
	v := m[0][2]
	not regex.match(`^(nil|""|''|true|false|\d+)$`, v)
	not _rb_has_httponly(lines, i, v)
}

_rb_has_httponly(_, _, v) if regex.match(`(?i)httponly`, v)

_rb_has_httponly(lines, i, v) if {
	startswith(v, "{")
	not contains(v, "}")
	regex.match(`(?i)httponly`, concat(" ", array.slice(lines, i + 1, i + 8)))
}

# Spring ResponseCookie builder with no httpOnly(...) before build().
_missing(path, _, lines, i, line) if {
	regex.match(`\.(java|kt|kts)$`, path)
	m := regex.find_all_string_submatch_n(`\bResponseCookie\.from\(\s*([^,()]+)`, line, 1)
	count(m) > 0
	_sensitive(m[0][1])
	t := _builder_text(lines, i)
	not regex.match(`\.httpOnly\(|\.maxAge\(\s*0\s*\)`, t)
	not _o1004_response_cookie(path, m[0][1])
}

_builder_text(lines, i) := t if {
	end := min([count(lines) - 1, i + 8])
	closers := [k | some k in numbers.range(i, end); contains(lines[k], ".build()")]
	stop := min(array.concat([end], closers))
	t := concat("\n", [l | some k in numbers.range(i, stop); l := lines[k]])
}

_missing(path, _, lines, i, line) if {
	endswith(path, ".go")
	regex.match(`\b(?:http|fiber)\.Cookie\{`, line)
	not regex.match(`\bhttp\.Cookie\{\s*\}`, line)
	block := _go_block(lines, i)
	not regex.match(`HttpOnly|HTTPOnly`, block)
	not _go_harmless_name(block)
	not _o1004_go_cookie(lines, i, line, block)
}

_go_block(lines, i) := b if {
	regex.match(`\}`, _after_brace(lines[i]))
	b := lines[i]
}

_go_block(lines, i) := b if {
	not regex.match(`\}`, _after_brace(lines[i]))
	end := min([count(lines) - 1, i + 15])
	closers := [k | some k in numbers.range(i + 1, end); regex.match(`^\s*\}`, lines[k])]
	stop := min(array.concat([end], closers))
	b := concat("\n", [l | some k in numbers.range(i, stop); l := lines[k]])
}

_after_brace(l) := substring(l, indexof(l, "Cookie{") + 7, -1)

# A literal, non-session name: a theme or language cookie.
_go_harmless_name(block) if {
	m := regex.find_all_string_submatch_n(`\bName:\s*"([^"]*)"`, block, 1)
	count(m) > 0
	not _sensitive(m[0][1])
}

_missing(path, _, lines, i, line) if {
	endswith(path, ".java")
	m := regex.find_all_string_submatch_n(`\bnew\s+Cookie\(([^)]*)\)`, line, 1)
	count(m) > 0
	_sensitive(m[0][1])
	not _clearing(m[0][1])
	not contains(helpers.code_window(lines, i, 0, 10), "setHttpOnly(")
	not _o1004_java_cookie(lines, i, line)
}

_missing(path, _, lines, i, line) if {
	regex.match(`\.(kt|kts)$`, path)
	m := regex.find_all_string_submatch_n(`=\s*Cookie\(([^)]*)\)`, line, 1)
	count(m) > 0
	_sensitive(m[0][1])
	not _clearing(m[0][1])
	not regex.match(`isHttpOnly|setHttpOnly\(`, helpers.code_window(lines, i, 0, 10))
}

_missing(path, _, _, _, line) if {
	endswith(path, ".php")
	m := regex.find_all_string_submatch_n(`\bset(?:raw)?cookie\(\s*([^,]+),\s*([^,]+?)\s*(,\s*(?:\[|array\s*\()|,|\))`, line, 1)
	count(m) > 0
	not regex.match(`\[|array`, m[0][3])
	_sensitive(concat(" ", [m[0][1], m[0][2]]))
	not _flag_value(m[0][2])
	not regex.match(`\bset(?:raw)?cookie\s*\(([^,()]*(?:\([^()]*\))?[^,()]*,){6}`, line)
	not _o1004_php_call(line)
}

_kind(path, content, lines, i, line) := "off" if {
	_off(path, content, lines, i, line)
}

_kind(path, content, lines, i, line) := "missing" if {
	not _off(path, content, lines, i, line)
	_missing(path, content, lines, i, line)
}

_message := {
	"off": "Cookie protection switched off: keep HttpOnly (no script access) and Secure (HTTPS only) enabled for session and authentication cookies",
	"missing": "Session or authentication cookie set without HttpOnly; set httpOnly/HttpOnly to true (and Secure, SameSite) so script injected into the page cannot read it",
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(_ext_re, path)
	contains(lower(content), "cookie")
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)cookie|httponly|http-only|secure|session`, line)
	not helpers.is_comment_line(line)
	k := _kind(path, content, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": _message[k],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A flag or an emptied value carries no secret: a logout clears the cookie.
_flag_value(v) if regex.match(`(?i)^\s*(?:key\s*=\s*|value\s*=\s*)?(\d+|true|false|none|null|""|''|"[^"]{0,3}"|'[^']{0,3}')\s*\)?\s*;?\s*$`, v)

_clearing(args) if regex.match(`,\s*(""|null|None)\s*$`, args)

# ── Lines the per-flag rules report ─────────────────────────────────────
# This rule is the catch-all for both cookie flags. Where a rule dedicated to
# one flag reports the same line, the line is left to it, so one missing flag
# is one finding:
#   VNX-614  Secure in Java, JavaScript/TypeScript and Python;
#   VNX-1004 HttpOnly in Go, PHP, Python and Java, and document.cookie;
#   VNX-NODE-029 HttpOnly for Express/Fastify res.cookie()/reply.setCookie()
#   and httpOnly: false beside a cookie call.
# This rule keeps everything else: Ruby, C#, Kotlin, web.config, php.ini and
# .htaccess, YAML, gin and fiber cookies, Next.js cookies().set, PHP and Go
# Secure, setHttpOnly(false) lines, and cookies whose names only this rule
# counts as sensitive. Each predicate below mirrors the owner's condition.

_js_path(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx)$`, path)

# VNX-1004's cookie-name test.
_o1004_sensitive_re := `(?i)sess|auth(?:$|[^o]|oriz)|token|jwt|(?:^|[^a-z])sid|remember|login|credential|refresh|access(?:$|[^i])|user_?id|(?:^|[^a-z])uid|admin|(?:^|[^a-z])roles?(?:$|[^a-z])|(?-i:[a-z]Roles?(?:$|[^a-z]))`

_o1004_name(n) if {
	regex.match(_o1004_sensitive_re, n)
	not regex.match(`(?i)csrf|xsrf`, n)
}

_o1004_deleting(call) if regex.match(`(?i)max_?age\s*[:=]\s*-1|expires\s*[:=]\s*(?:time\.Unix\(0|new Date\(0\)|0\b)`, call)

_o1004_empty(v) if regex.match(`^\s*(?:""|''|None|null|nil)\s*$`, v)

# A flag found by the generic `httpOnly: false` / `secure = False` scan.
_key_owned(path, _, lines, i, line, "secure") if {
	endswith(path, ".py")
	regex.match(`\.set_cookie\s*\(`, _strip(line))
	regex.match(`\bsecure\s*=\s*False\b`, line)
}

_key_owned(path, content, lines, i, line, "secure") if {
	_js_path(path)
	regex.match(`\bsecure\s*:\s*false\b`, _strip(line))
	regex.match(`(?i)\bcookie|\bsession\s*\(|cookieSession\s*\(`, helpers.code_window(lines, i, 8, 0))
}

_key_owned(path, _, lines, i, line, flag) if {
	flag != "secure"
	_js_path(path)
	regex.match(`\bhttpOnly\s*:\s*false\b`, line)
	_js_httponly_off_owned(path, lines, i)
}

_key_owned(path, _, lines, i, line, flag) if {
	flag != "secure"
	endswith(path, ".py")
	regex.match(`\bhttponly\s*=\s*False\b`, line)
	m := regex.find_all_string_submatch_n(`\.set_cookie\s*\(\s*(?:key\s*=\s*)?["']([^"']*)["']\s*,\s*(?:value\s*=\s*)?([^,)]*)`, line, 1)
	count(m) > 0
	_o1004_name(m[0][1])
	not _o1004_empty(m[0][2])
	t := _py_call_text(lines, i)
	not regex.match(`max_age\s*=\s*0\b|\*\*\w+`, t)
	not _o1004_deleting(t)
	not regex.match(`^\s*(?:async\s+)?def\s`, line)
}

# Go: HttpOnly: false in a session store's Options (VNX-1004).
_key_owned(path, _, lines, i, line, flag) if {
	flag != "secure"
	endswith(path, ".go")
	regex.match(`^\s*HttpOnly\s*:\s*false\b`, line)
	js := [k |
		some d in numbers.range(1, min([i, 12]))
		k := i - d
		contains(lines[k], "{")
	]
	count(js) > 0
	opener := lines[js[0]]
	regex.match(`(?i)sessions?\.Options\{|SessionOptions\{|session|store`, opener)
	not contains(opener, "http.Cookie{")
}

# JavaScript httpOnly: false: VNX-NODE-029 next to a cookie call, VNX-1004
# in session or cookie options.
_js_httponly_off_owned(_, lines, i) if {
	some j in numbers.range(max([0, i - 6]), i)
	regex.match(`\.cookies?\s*\(|\.cookies\.set\s*\(|setCookie\s*\(|\bserialize\s*\(`, lines[j])
	not helpers.is_comment_line(lines[j])
}

_js_httponly_off_owned(_, lines, i) if {
	win := helpers.code_window(lines, i, 8, 2)
	regex.match(`(?i)session\s*\(|cookieSession\s*\(|\.cookie\s*\(|setCookie\s*\(|cookie\s*:|cookieOptions|sessionOptions`, win)
	not regex.match(`(?i)csrf|xsrf`, win)
}

# Django/Flask settings: *_COOKIE_SECURE (VNX-614, outside its development
# settings files) and SESSION_COOKIE_HTTPONLY (VNX-1004).
_py_setting_owned(path, name) if {
	name in {"SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE", "REMEMBER_COOKIE_SECURE"}
	not regex.match(`(?i)(?:^|/)(?:settings[_/])?(?:dev|develop|development|local|test|testing|ci)(?:_settings)?\.py$`, path)
}

_py_setting_owned(_, "SESSION_COOKIE_HTTPONLY")

# Java: setSecure(false) (VNX-614); a ResponseCookie.from("name", ...) on the
# same line with .secure(false) (VNX-614) or, for a session/auth name,
# .httpOnly(false) (VNX-1004).
_java_off_owned(path, line, "setSecure") if {
	endswith(path, ".java")
	regex.match(`\.setSecure\s*\(\s*(?:false|Boolean\.FALSE)\s*\)`, _strip(line))
}

_java_off_owned(path, line, "secure") if {
	endswith(path, ".java")
	regex.match(`\bResponseCookie\s*\.\s*(?:from|fromClientResponse)\s*\(\s*"([^"]+)"\s*,\s*([^)]*)\)`, line)
}

_java_off_owned(path, line, "httpOnly") if {
	endswith(path, ".java")
	m := regex.find_all_string_submatch_n(`\bResponseCookie\.from\s*\(\s*"([^"]*)"`, line, 1)
	count(m) > 0
	_o1004_name(m[0][1])
	not regex.match(`\.maxAge\(\s*0\s*\)`, line)
}

# Spring Boot properties: secure=false (VNX-614), http-only=false (VNX-1004).
_properties_owned(path, line) if {
	endswith(path, ".properties")
	regex.match(`^\s*server\.(?:servlet\.)?(?:reactive\.)?session\.cookie\.secure\s*[=:]\s*false\s*$`, line)
}

_properties_owned(path, line) if {
	endswith(path, ".properties")
	regex.match(`^\s*server\.servlet\.session\.cookie\.http-only\s*[=:]\s*false\s*$`, line)
}

# PHP setcookie()/setrawcookie() of a session or auth cookie: VNX-1004
# reports it whether httponly is missing, false in seventh place, or absent
# from the options array.
_o1004_php_call(line) if {
	m := regex.find_all_string_submatch_n(`\bset(?:raw)?cookie\s*\(\s*["']([^"']*)["']\s*,\s*([^,)]*)`, line, 1)
	count(m) > 0
	_o1004_name(m[0][1])
	not _o1004_empty(m[0][2])
	not _o1004_deleting(line)
}

_php_seventh_owned(path, line) if {
	endswith(path, ".php")
	_o1004_php_call(line)
}

# Express/Fastify res.cookie()/reply.setCookie() of a session or auth cookie
# with no options or an options literal (VNX-1004).
_o1004_js_call(lines, i, line) if {
	m := regex.find_all_string_submatch_n("\\b(?:res|resp|response|reply)\\.(?:cookie|setCookie)\\s*\\(\\s*[\"'`]([^\"'`]*)[\"'`]\\s*,\\s*([^,)]*)", line, 1)
	count(m) > 0
	_o1004_name(m[0][1])
	not _o1004_empty(m[0][2])
	not _o1004_deleting(_call_text(lines, i))
}

# Python set_cookie() of a session or auth cookie (VNX-1004).
_o1004_py_call(line, t) if {
	m := regex.find_all_string_submatch_n(`\.set_cookie\s*\(\s*(?:key\s*=\s*)?["']([^"']*)["']`, line, 1)
	count(m) > 0
	_o1004_name(m[0][1])
	not regex.match(`\bvalue\s*=\s*(?:None|""|'')|max_age\s*=\s*0\b`, t)
	not _o1004_deleting(t)
	not regex.match(`^\s*(?:async\s+)?def\s`, line)
}

# document.cookie = "token=..." in a script file (VNX-1004).
_o1004_document_cookie(path, line) if {
	_js_path(path)
	m := regex.find_all_string_submatch_n("document\\.cookie\\s*=\\s*[\"'`]\\s*([A-Za-z_][\\w.-]*)\\s*=", line, 1)
	count(m) > 0
	_o1004_name(m[0][1])
	not regex.match(`(?i)=\s*;|expires\s*=\s*Thu,\s*01 Jan 1970|max-age\s*=\s*(?:0|-1)\b`, line)
}

# Spring ResponseCookie.from("session", ...) without .httpOnly (VNX-1004).
_o1004_response_cookie(path, arg) if {
	endswith(path, ".java")
	m := regex.find_all_string_submatch_n(`^\s*"([^"]*)"`, arg, 1)
	count(m) > 0
	_o1004_name(m[0][1])
}

# Go http.Cookie{Name: "session", ...} without HttpOnly (VNX-1004).
_o1004_go_cookie(lines, i, line, block) if {
	contains(line, "http.Cookie{")
	m := regex.find_all_string_submatch_n(`\bName\s*:\s*"([^"]*)"`, block, 1)
	count(m) > 0
	_o1004_name(m[0][1])
	not _o1004_deleting(block)
	not regex.match(`(?i)\bValue\s*:\s*(?:""|nil)\s*[,}]`, block)
	not _o1004_go_set_later(lines, i)
}

_o1004_go_set_later(lines, i) if {
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 20]))
	regex.match(`\.HttpOnly\s*=\s*true`, lines[k])
}

# Java Cookie c = new Cookie("session", value) never given setHttpOnly(true)
# (VNX-1004).
_o1004_java_cookie(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`\b(?:Cookie\s+)?(\w+)\s*=\s*new\s+(?:javax\.servlet\.http\.|jakarta\.servlet\.http\.)?Cookie\s*\(\s*"([^"]*)"\s*,\s*([^,)]*)`, line, 1)
	count(m) > 0
	_o1004_name(m[0][2])
	not _o1004_empty(m[0][3])
	v := m[0][1]
	not _o1004_java_protected(lines, i, v)
}

_o1004_java_protected(lines, i, v) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 15]))
	regex.match(concat("", [`\b`, v, `\.set(?:HttpOnly\(\s*true|MaxAge\(\s*0)\s*\)`]), lines[k])
}

# VNX-NODE-029's res.cookie()/reply.setCookie() test.
_o029_call_re := `(?:\b(?:res|resp|response|reply)\.(?:cookie|setCookie)|\bcookie\.serialize)\s*\(`

_o029_sensitive_re := `(?i)(sess|\bsid\b|sid['"]|token|auth(?:$|[^o]|o[^r])|jwt|login|identity|credential|bearer|access(?:$|[^i])|refresh|remember_?me)`

_o029_strip(s) := regex.replace(s, concat("", [`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`, "`[^`]*`"]), `''`)

_o029_depth(lines, s, j) := sum([d |
	some k in numbers.range(s, j)
	c := _o029_strip(lines[k])
	d := strings.count(c, "(") - strings.count(c, ")")
])

_o029_call_end(lines, i) := e if {
	hi := min([count(lines) - 1, i + 8])
	ends := [j | some j in numbers.range(i, hi); _o029_depth(lines, i, j) <= 0]
	e := min(array.concat(ends, [hi]))
}

_o029_call_text(lines, i) := concat("\n", [l | some k in numbers.range(i, _o029_call_end(lines, i)); l := lines[k]; not helpers.is_comment_line(l)])

_o029_args(text) := a if {
	m := regex.find_all_string_submatch_n(concat("", ["(?s)", _o029_call_re, `(.*)$`]), text, 1)
	count(m) > 0
	a := m[0][1]
}

_o029_head(args) := concat(",", array.slice(split(split(replace(args, "${", "$<"), "{")[0], ","), 0, 2))

_o029_clearing(args) if trim_space(split(split(args, "{")[0], ",")[1]) in {"''", `""`, "``", "null", "undefined"}

_o029_clearing(args) if regex.match(`expires\s*:\s*new Date\(\s*0\s*\)|maxAge\s*:\s*0\b`, args)

_o029_options_hidden(content, args) if {
	not contains(args, "{")
	parts := split(args, ",")
	count(parts) >= 3
	id := trim(trim_space(parts[2]), ") ;")
	regex.match(`^[A-Za-z_$][\w$.]*$`, id)
	regex.match(concat("", [`(?s)\b`, id, `\b[^=\n]*=\s*\{[^}]*httpOnly\s*:\s*true`]), content)
}

_o029_options_hidden(content, args) if {
	not contains(args, "{")
	parts := split(args, ",")
	count(parts) >= 3
	id := trim(trim_space(parts[2]), ") ;")
	regex.match(`^[A-Za-z_$][\w$.]*$`, id)
	not regex.match(concat("", [`\b`, id, `\b[^=\n]*=\s*\{`]), content)
}

_o029_options_hidden(_, args) if {
	not contains(args, "{")
	parts := split(args, ",")
	count(parts) >= 3
	regex.match(`^\s*[A-Za-z_$][\w$.]*\s*\(`, parts[2])
}

_o029_options_hidden(_, args) if regex.match(`\{\s*\.\.\.|,\s*\.\.\.[A-Za-z_$]`, args)

_o029_call(path, content, lines, i, line) if {
	not endswith(path, ".min.js")
	regex.match(_o029_call_re, _o029_strip(line))
	args := _o029_args(_o029_call_text(lines, i))
	head := _o029_head(args)
	regex.match(_o029_sensitive_re, head)
	not regex.match(`(?i)(csrf|xsrf)`, head)
	not _o029_clearing(args)
	not regex.match(`\bhttpOnly\s*:`, args)
	not _o029_options_hidden(content, args)
}
