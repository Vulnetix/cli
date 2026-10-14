package vulnetix.rules.vnx_kotlin_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-KOTLIN-003",
	"name": "Kotlin sensitive cookie without HttpOnly",
	"description": "A session or credential cookie reaches the browser without the HttpOnly attribute, so any script injected into the page can read it. Reported in Kotlin (.kt, .kts): HttpOnly explicitly disabled (cookie.setHttpOnly(false), cookie.isHttpOnly = false or isHttpOnly = false in an apply block, ServletContext sessionCookieConfig, Spring ResponseCookie .httpOnly(false), Spring Session setUseHttpOnlyCookie(false), Ktor Cookie(..., httpOnly = false) and Ktor Sessions cookie.httpOnly = false); and a cookie whose name or value names a session, token, JWT, auth, login, remember-me or similar credential that is sent without any HttpOnly setting: a servlet or Ktor Cookie(...) passed to response.addCookie() or call.response.cookies.append() (inline, or through a variable constructed up to 25 lines above), Ktor cookies.append(name, value, ...), a Spring ResponseCookie.from(...) chain built without .httpOnly(true), and a raw Set-Cookie header literal without HttpOnly. Not reported: cookies that set HttpOnly true anywhere between construction and the response, non-credential cookies (theme, locale, UI flags) that scripts are meant to read, CSRF/XSRF double-submit token cookies, cookies built by helper functions or added through a parameter whose construction is not visible, client-side cookie jars (OkHttp Cookie.Builder), test code, and the calls in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-kotlin-003/",
	"languages": ["kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1004],
	"capec": ["CAPEC-60"],
	"attack_technique": ["T1185"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cookie", "session", "xss", "kotlin"],
}

_is_kotlin(path) if endswith(path, ".kt")

_is_kotlin(path) if endswith(path, ".kts")

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)src/[A-Za-z]*[Tt]est[A-Za-z]*/`, path)

_is_test(path) if regex.match(`(Test|Tests|Spec|IT)\.kts?$`, path)

_is_test(path) if regex.match(`(^|/)([\w.]+[-_])?test(s|ing)?([-_][\w.-]+)?/`, path)

# String-literal contents blanked, trailing comment cut.
_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

# A name or value that says the cookie carries a credential. CSRF/XSRF
# double-submit tokens are meant to be read by the page script.
_sensitive(txt) if {
	regex.match(`(?i)(sess|\bsid\b|token|auth|jwt|login|remember|credential|bearer|access|refresh|identity|\buid\b|user_?id|account|passw|secret|api_?key)`, txt)
	not _csrf(txt)
}

_csrf(txt) if regex.match(`(?i)(csrf|xsrf)`, txt)

# ── HttpOnly explicitly disabled ─────────────────────────────────────────

_false_re := [
	`\bsetHttpOnly\s*\(\s*false\s*\)`,
	`\.httpOnly\s*\(\s*false\s*\)`,
	`\bsetUseHttpOnlyCookie\s*\(\s*false\s*\)`,
	`(^|[^\w])useHttpOnlyCookie\s*=\s*false\b`,
	`\.(isHttpOnly|httpOnly)\s*=\s*false\b`,
	`^\s*isHttpOnly\s*=\s*false\b`,
	`[(,]\s*(isHttpOnly|httpOnly)\s*=\s*false\b`,
]

_disables(code, _, _) if {
	some re in _false_re
	regex.match(re, code)
}

# A named argument on its own line of a multi-line Cookie(...) or append(...)
# call; a local `var httpOnly` is a declaration and does not match.
_disables(code, lines, i) if {
	regex.match(`^\s*httpOnly\s*=\s*false\b`, code)
	above := concat("\n", array.slice(lines, max([0, i - 6]), i))
	regex.match(`(Cookie\s*\(|cookies\s*\.\s*append\s*\()`, above)
}

_shape("disabled", lines, i, line, _) if {
	contains(line, "ttpOnly")
	code := _code(line)
	contains(code, "false")
	_disables(code, lines, i)
	not _csrf(concat("\n", array.slice(lines, max([0, i - 6]), i + 2)))
}

# ── Sensitive cookie sent with no HttpOnly setting ───────────────────────


# Cookie classes a constructor call can name: Cookie (servlet, Ktor, Javalin,
# http4k), fully qualified, Micronaut's Cookie.of(...), or an import alias of
# any of them.
_ctor_names(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`import\s+[\w.]+\.Cookie\s+as\s+(\w+)`, content, -1)
} | {"Cookie"}

_ctor_re(content) := concat("", [`(?:^|[^\w.])(?:[a-z]\w*\.)*(?:`, concat("|", _ctor_names(content)), `)\s*(?:\.\s*of\s*)?\(`])

_depth_to(lines, i, k) := sum([d |
	some m in numbers.range(i, k)
	c := _code(lines[m])
	d := count(indexof_n(c, "(")) - count(indexof_n(c, ")"))
])

# Lines i..end of the call that opens on line i (balanced parentheses, at
# most 12 lines).
_call_text(lines, i) := txt if {
	hi := min([count(lines) - 1, i + 12])
	ends := [k | some k in numbers.range(i, hi); _depth_to(lines, i, k) <= 0]
	end := _first_or(ends, hi)
	txt := concat("\n", [l | some l in array.slice(lines, i, end + 1); not helpers.is_comment_line(l)])
}

_first_or(xs, _) := xs[0] if count(xs) > 0

_first_or(xs, d) := d if count(xs) == 0

_mentions_httponly(txt) if regex.match(`(?i)httponly`, _code_lines(txt))

_code_lines(txt) := concat("\n", [_code(l) | some l in split(txt, "\n")])

# response.addCookie(...), Ktor call.response.cookies.append(...), Javalin
# ctx.cookie(...), http4k Response.cookie(...), Micronaut HttpResponse.cookie(...)
_sink_re := `(\baddCookie|\bcookies\s*\.\s*append|\.cookie)\s*\(`

# The cookie object is built inside the call: addCookie(Cookie("jwt", t)).
_unprotected_sink(lines, i, content, ct) if {
	regex.match(_ctor_re(content), _code_lines(ct))
	_sensitive(ct)
}

# Ktor cookies.append("session", id, ...) / append(name = "session", ...) and
# Javalin ctx.cookie("session", id): HttpOnly defaults to false. A single
# string argument (ctx.cookie("session")) reads a cookie.
_unprotected_sink(lines, i, content, ct) if {
	regex.match(`(\bcookies\s*\.\s*append|\.cookie)\s*\(\s*("(?:[^"\\]|\\.)*"\s*,|name\s*=)`, regex.replace(ct, `\s+`, " "))
	_sensitive(ct)
}

# addCookie(c) / cookies.append(c) where c was constructed a few lines up and
# nothing between sets HttpOnly.
_unprotected_sink(lines, i, content, ct) if {
	id := _sink_ident(lines[i])
	id != "it"
	ctor := _ctor_re(content)
	re := concat("", [`\b`, id, `\s*(?::\s*[\w.]+)?\s*=\s*`])
	js := [k |
		some k in numbers.range(max([0, i - 25]), i - 1)
		contains(lines[k], id)
		not helpers.is_comment_line(lines[k])
		regex.match(re, lines[k])
		regex.match(ctor, _code(lines[k]))
	]
	count(js) > 0
	_unprotected_since(lines, max(js), i)
}

# Cookie(...).also { ...; response.addCookie(it) }
_unprotected_sink(lines, i, content, ct) if {
	_sink_ident(lines[i]) == "it"
	ctor := _ctor_re(content)
	js := [k |
		some k in numbers.range(max([0, i - 6]), i - 1)
		regex.match(`\.\s*(also|let)\s*\{`, lines[k])
		regex.match(ctor, _code(lines[k]))
	]
	count(js) > 0
	_unprotected_since(lines, max(js), i)
}

_sink_ident(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`(?:\baddCookie|\bcookies\s*\.\s*append|\.cookie)\s*\(\s*([A-Za-z_]\w*)\s*\)`, _code(line), 1)
	count(m) > 0
}

_unprotected_since(lines, j, i) if {
	between := concat("\n", [l | some l in array.slice(lines, j, i); not helpers.is_comment_line(l)])
	not _mentions_httponly(between)
	_sensitive(concat("\n", array.slice(lines, j, j + 3)))
}

_shape("missing", lines, i, line, content) if {
	regex.match(`addCookie|append|\.cookie`, line)
	regex.match(_sink_re, _code(line))
	ct := _call_text(lines, i)
	not _mentions_httponly(ct)
	_unprotected_sink(lines, i, content, ct)
}


# Spring ResponseCookie.from(...) ... .build() with no .httpOnly(...) call:
# the builder's default is not HttpOnly.
_shape("spring", lines, i, line, _) if {
	contains(line, "ResponseCookie")
	regex.match(`\bResponseCookie\s*\.\s*from\s*\(`, _code(line))
	hi := min([count(lines) - 1, i + 12])
	builds := [k | some k in numbers.range(i, hi); contains(lines[k], ".build()")]
	end := _first_or(builds, hi)
	chain := concat("\n", [l | some l in array.slice(lines, i, end + 1); not helpers.is_comment_line(l)])
	not _mentions_httponly(chain)
	_sensitive(line)
}

# A raw Set-Cookie header literal for a credential cookie that omits HttpOnly.
_shape("header", _, _, line, _) if {
	regex.match(`(?i)set-?_?cookie`, line)
	regex.match(`\b(addHeader|setHeader|header|append)\s*\(\s*("(?i:set-cookie)"|HttpHeaders\s*\.\s*(SET_COOKIE|SetCookie))\s*,\s*"`, line)
	m := regex.find_all_string_submatch_n(`,\s*"((?:[^"\\]|\\.)*)"`, line, 1)
	count(m) > 0
	value := m[0][1]
	contains(value, "=")
	not regex.match(`(?i)httponly`, value)
	_sensitive(value)
}

_messages := {
	"disabled": "HttpOnly is explicitly disabled on this cookie; any injected script can read it. Leave HttpOnly on for session and credential cookies",
	"missing": "Session or credential cookie is added to the response without HttpOnly; set isHttpOnly = true (servlet) or httpOnly = true (Ktor) so scripts cannot read it",
	"spring": "Spring ResponseCookie for a session or credential is built without .httpOnly(true); scripts on the page can read it",
	"header": "Set-Cookie header for a session or credential cookie omits HttpOnly; add the HttpOnly attribute so scripts cannot read it",
}

findings contains finding if {
	some path, content in input.file_contents
	_is_kotlin(path)
	regex.match(`(?i)cookie`, content)
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`ttpOnly|addCookie|append|\.cookie|ResponseCookie|(?i:set-?_?cookie)`, line)
	not helpers.is_comment_line(line)
	some key, msg in _messages
	_shape(key, lines, i, line, content)
	finding := _finding(path, i, line, msg)
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
