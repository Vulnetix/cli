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

_off(_, lines, i, line) if {
	m := regex.find_all_string_submatch_n(_off_key_re, _strip(line), 1)
	count(m) > 0
	not regex.match(_decl_re, line)
	_cookie_ctx(lines, i)
	name := lower(m[0][1])
	_flag_counts(name, lines, i)
}

_off(path, lines, i, line) if {
	endswith(path, ".php")
	regex.match(`(?i)["']httponly["']\s*=>\s*false\b`, line)
	not _csrf_ctx(lines, i)
}

_off(path, _, _, line) if {
	endswith(path, ".php")
	regex.match(`(?i)["']secure["']\s*=>\s*false\b`, line)
}

# HttpOnly may be off on the CSRF cookie: the page's script must read it.
_flag_counts(name, lines, i) if {
	name in {"httponly", "http-only", "http_only"}
	not _csrf_ctx(lines, i)
}

_flag_counts(name, _, _) if name == "secure"

_off(path, _, _, line) if {
	endswith(path, ".py")
	regex.match(`\b(SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|CSRF_COOKIE_SECURE|REMEMBER_COOKIE_SECURE|REMEMBER_COOKIE_HTTPONLY)["']?\s*\]?\s*=\s*False\b`, line)
}

_off(path, lines, i, line) if {
	regex.match(`\.(java|kt|kts)$`, path)
	regex.match(`\.(?:set(?:HttpOnly|Secure)|httpOnly|secure)\(\s*false\s*\)`, line)
	regex.match(`Cookie`, helpers.code_window(lines, i, 10, 0))
}

_off(path, _, _, line) if {
	regex.match(`\.(kt|kts)$`, path)
	regex.match(`(?i)\w*cookie\w*\.is(HttpOnly|Secure)\s*=\s*false\b`, line)
}

_off(path, _, _, line) if {
	regex.match(`(?i)\.(properties|ya?ml)$`, path)
	regex.match(`(?i)session\.cookie\.(secure|http-only|httponly)\s*[=:]\s*false\b`, line)
}

_off(path, _, _, line) if {
	endswith(path, ".cs")
	regex.match(`\bCookieSecurePolicy\.None\b`, line)
}

_off(path, _, _, line) if {
	regex.match(`(?i)\.config$`, path)
	regex.match(`(?i)<\s*(httpCookies|forms)\b`, line)
	regex.match(`(?i)\b(httpOnlyCookies|requireSSL)\s*=\s*["']false["']`, line)
}

_off(path, _, _, line) if {
	endswith(path, ".php")
	regex.match(`(?i)\bini_set\(\s*["']session\.cookie_(httponly|secure)["']\s*,\s*(?:0|false|off|["'](?:0|off|false)?["'])\s*\)`, line)
}

_off(path, _, _, line) if {
	regex.match(`(?i)(\.ini|(^|/)\.htaccess)$`, path)
	regex.match(`(?i)^\s*(?:php_(?:admin_)?(?:flag|value)\s+)?session\.cookie_(httponly|secure)\s*=?\s*(0|off|false|"0"|""|'0')\s*(;.*)?$`, line)
}

# false as the 6th (secure) or 7th (httponly) argument of PHP setcookie /
# setrawcookie or gin's Context.SetCookie.
_off(path, _, _, line) if {
	regex.match(`\.(php|go)$`, path)
	regex.match(`\b(?:setcookie|setrawcookie|SetCookie)\s*\(([^,()]*(?:\([^()]*\))?[^,()]*,){5}\s*false\b`, line)
}

_off(path, lines, i, line) if {
	regex.match(`\.(php|go)$`, path)
	regex.match(`\b(?:setcookie|setrawcookie|SetCookie)\s*\(([^,()]*(?:\([^()]*\))?[^,()]*,){6}\s*false\b`, line)
	not _csrf_ctx(lines, i)
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

_missing(path, lines, i, line) if {
	regex.match(`\.(js|jsx|mjs|cjs|ts|tsx)$`, path)
	m := regex.find_all_string_submatch_n(`\b(?:res\.cookie|(?:reply|res|response)\.setCookie|(?:res|response)\.cookies\.set|cookies\(\)\.set)\(\s*([^,]+),\s*([^,{]+?)\s*(?:,\s*([{A-Za-z_])|\))`, line, 1)
	count(m) > 0
	m[0][3] in {"", "{"}
	_sensitive(concat(" ", [m[0][1], m[0][2]]))
	not _flag_value(m[0][2])
	not regex.match(`(?i)httponly`, _call_text(lines, i))
}

_missing(path, lines, i, line) if {
	endswith(path, ".py")
	contains(line, ".set_cookie(")
	t := _py_call_text(lines, i)
	flat := replace(t, "\n", " ")
	m := regex.find_all_string_submatch_n(`\.set_cookie\(\s*([^,]+),\s*([^,]+)`, flat, 1)
	count(m) > 0
	_sensitive(concat(" ", [m[0][1], m[0][2]]))
	not _flag_value(m[0][2])
	not regex.match(`(?i)httponly|\*\*`, t)
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
_missing(path, _, _, line) if {
	regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|html?|vue|svelte)$`, path)
	m := regex.find_all_string_submatch_n("\\bdocument\\.cookie\\s*=\\s*[\"'`]\\s*([A-Za-z0-9_.\\-]+)=([^;\"'`]*)", line, 1)
	count(m) > 0
	_sensitive(m[0][1])
	not regex.match(`(?i)max-age=0\b|expires=thu,\s*01 jan 1970`, line)
	not _js_cleared(m[0][2], line)
}

# 'auth=; Max-Age=0' or "token=" + "" clears the cookie.
_js_cleared(v, line) if {
	trim_space(v) == ""
	not regex.match("[\"'`]\\s*\\+|\\$\\{", line)
}

# ASP.NET Core Response.Cookies.Append(name, value) with no CookieOptions:
# HttpOnly defaults to false.
_missing(path, _, _, line) if {
	endswith(path, ".cs")
	m := regex.find_all_string_submatch_n(`\.Cookies\.Append\(\s*([^,()]+),\s*([^,()]*(?:\([^()]*\))?[^,()]*)\)\s*;`, line, 1)
	count(m) > 0
	_sensitive(m[0][1])
	not _flag_value(m[0][2])
}

# Rails cookies jar: cookies[:auth_token] = value, or a hash with no httponly.
_missing(path, lines, i, line) if {
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
_missing(path, lines, i, line) if {
	regex.match(`\.(java|kt|kts)$`, path)
	m := regex.find_all_string_submatch_n(`\bResponseCookie\.from\(\s*([^,()]+)`, line, 1)
	count(m) > 0
	_sensitive(m[0][1])
	t := _builder_text(lines, i)
	not regex.match(`\.httpOnly\(|\.maxAge\(\s*0\s*\)`, t)
}

_builder_text(lines, i) := t if {
	end := min([count(lines) - 1, i + 8])
	closers := [k | some k in numbers.range(i, end); contains(lines[k], ".build()")]
	stop := min(array.concat([end], closers))
	t := concat("\n", [l | some k in numbers.range(i, stop); l := lines[k]])
}

_missing(path, lines, i, line) if {
	endswith(path, ".go")
	regex.match(`\b(?:http|fiber)\.Cookie\{`, line)
	not regex.match(`\bhttp\.Cookie\{\s*\}`, line)
	block := _go_block(lines, i)
	not regex.match(`HttpOnly|HTTPOnly`, block)
	not _go_harmless_name(block)
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

_missing(path, lines, i, line) if {
	endswith(path, ".java")
	m := regex.find_all_string_submatch_n(`\bnew\s+Cookie\(([^)]*)\)`, line, 1)
	count(m) > 0
	_sensitive(m[0][1])
	not _clearing(m[0][1])
	not contains(helpers.code_window(lines, i, 0, 10), "setHttpOnly(")
}

_missing(path, lines, i, line) if {
	regex.match(`\.(kt|kts)$`, path)
	m := regex.find_all_string_submatch_n(`=\s*Cookie\(([^)]*)\)`, line, 1)
	count(m) > 0
	_sensitive(m[0][1])
	not _clearing(m[0][1])
	not regex.match(`isHttpOnly|setHttpOnly\(`, helpers.code_window(lines, i, 0, 10))
}

_missing(path, _, _, line) if {
	endswith(path, ".php")
	m := regex.find_all_string_submatch_n(`\bset(?:raw)?cookie\(\s*([^,]+),\s*([^,]+?)\s*(,\s*(?:\[|array\s*\()|,|\))`, line, 1)
	count(m) > 0
	not regex.match(`\[|array`, m[0][3])
	_sensitive(concat(" ", [m[0][1], m[0][2]]))
	not _flag_value(m[0][2])
	not regex.match(`\bset(?:raw)?cookie\s*\(([^,()]*(?:\([^()]*\))?[^,()]*,){6}`, line)
}

_kind(path, lines, i, line) := "off" if {
	_off(path, lines, i, line)
}

_kind(path, lines, i, line) := "missing" if {
	not _off(path, lines, i, line)
	_missing(path, lines, i, line)
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
	k := _kind(path, lines, i, line)
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
