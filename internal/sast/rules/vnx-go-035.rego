package vulnetix.rules.vnx_go_035

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-035",
	"name": "Missing HttpOnly flag on cookie",
	"description": "A cookie the server sends to the browser is not marked HttpOnly, so any script running in the page (an XSS payload included) can read it from document.cookie. Reported: an http.Cookie, fiber.Cookie or gorilla sessions.Options literal with no HttpOnly/HTTPOnly field or with it set to false that is passed to http.SetCookie/c.SetCookie/c.Cookie, returned to a caller, or assigned to a variable that is (session.Options = &sessions.Options{...} configures every session cookie); a new(http.Cookie) that is sent without .HttpOnly being set; gin c.SetCookie(name, value, maxAge, path, domain, secure, false), on one line or with its arguments wrapped over up to 10 lines; csrf.HttpOnly(false); x.HttpOnly = false; and sessions.NewCookieStore/NewFilesystemStore in a project that never sets the store's Options (their default leaves HttpOnly off). Not reported: HttpOnly set to true or to any expression (a config value), a deletion cookie (MaxAge negative, Expires at the Unix epoch), a CSRF/XSRF double-submit token cookie (it must be readable by the page's script), cookies a client sends (req.AddCookie, a cookie jar), test files, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-035/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1004],
	"capec": ["CAPEC-63"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cookie", "httponly", "session"],
}

_msg_missing := "Cookie is sent without the HttpOnly attribute: any script in the page, including an XSS payload, can read it. Set HttpOnly: true"

_msg_false := "Cookie HttpOnly attribute is explicitly turned off: any script in the page, including an XSS payload, can read it. Set it to true"

_msg_store := "gorilla sessions store is created and its Options are never set: the default session cookie is not HttpOnly. Set store.Options = &sessions.Options{HttpOnly: true, Secure: true, ...}"

# String literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `//.*$`, "")

_lit_re := `&?(?:http\.Cookie|fiber\.Cookie|sessions\.Options)\{`

_fn_end(lines, i) := e if {
	n := count(lines) - 1
	ends := [j | some j in numbers.range(min([i + 1, n]), min([i + 120, n])); startswith(lines[j], "}")]
	e := min(array.concat([min([i + 120, n])], ends))
}

_depth(s) := count(indexof_n(s, "{")) - count(indexof_n(s, "}"))

# The composite literal's text, from its type to its closing brace.
_literal(lines, i, first) := first if _depth(first) <= 0

_literal(lines, i, first) := txt if {
	_depth(first) > 0
	end := min([count(lines) - 1, i + 30])
	end >= i + 1
	ks := [k |
		some k in numbers.range(i + 1, end)
		_depth(concat("\n", array.concat([first], [lines[j] | some j in numbers.range(i + 1, k)]))) <= 0
	]
	count(ks) > 0
	txt := concat("\n", array.concat([first], [lines[j] | some j in numbers.range(i + 1, ks[0])]))
}

_deletion(txt) if regex.match(`\bMaxAge\s*:\s*-`, txt)

_deletion(txt) if regex.match(`\bExpires\s*:\s*time\.Unix\(\s*0\s*,\s*0\s*\)`, txt)

# A double-submit CSRF token cookie is meant to be read by the page.
_js_readable(txt) if regex.match(`\bName\s*:\s*"(?i:[^"]*(?:csrf|xsrf)[^"]*)"`, txt)

_httponly_false(txt) if regex.match(`\b(?:HttpOnly|HTTPOnly)\s*:\s*false\b`, txt)

_httponly_set(txt) if regex.match(`\b(?:HttpOnly|HTTPOnly)\s*:`, txt)

_word(n) := concat("", [`\b`, n, `\b`])

# The literal's variable, if it is assigned to one.
_var(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:var\s+)?([A-Za-z_]\w*)\s*:?=\s*(?:&?(?:http\.Cookie|fiber\.Cookie|sessions\.Options)\{|new\(http\.Cookie\))`, line, 1)
	count(m) > 0
	v := m[0][1]
}

# The cookie goes to the browser.
_sent(_, _, line, _) if regex.match(`\bSetCookie\(|\.Cookie\(\s*&`, line)

_sent(_, _, line, _) if regex.match(`^\s*return\s+&?(?:http\.Cookie|fiber\.Cookie)\{`, line)

_sent(_, _, line, _) if contains(line, "sessions.Options{")

_sent(lines, i, line, e) if {
	v := _var(line)
	i + 1 <= e
	some k in numbers.range(i + 1, e)
	l := lines[k]
	not helpers.is_comment_line(l)
	_uses_var(l, v)
}

_uses_var(l, v) if {
	regex.match(`\bSetCookie\(|\.Cookie\(`, l)
	regex.match(_word(v), substring(l, indexof(l, "Cookie("), -1))
}

_uses_var(l, v) if regex.match(concat("", [`^\s*return\s+&?`, v, `\b`]), l)

# x.HttpOnly = ... (or x.Name = "XSRF-...") later in the function.
_fixed_later(lines, i, line, e) if {
	v := _var(line)
	i + 1 <= e
	some k in numbers.range(i + 1, e)
	regex.match(concat("", [`^\s*`, v, `\.(?:HttpOnly|HTTPOnly)\s*=\s*\S`]), lines[k])
	not regex.match(`=\s*false\b`, lines[k])
}

_fixed_later(lines, i, line, e) if {
	v := _var(line)
	i + 1 <= e
	some k in numbers.range(i + 1, e)
	regex.match(concat("", [`^\s*`, v, `\.Name\s*=\s*"(?i:[^"]*(?:csrf|xsrf))`]), lines[k])
}

_lit_text(lines, i, line) := txt if {
	ms := regex.find_all_string_submatch_n(_lit_re, line, 1)
	count(ms) > 0
	txt := _literal(lines, i, substring(line, indexof(line, ms[0][0]), -1))
}

_hit(lines, i, line, code) := _msg_false if {
	regex.match(_lit_re, code)
	txt := _lit_text(lines, i, line)
	_httponly_false(txt)
	not _js_readable(txt)
}

_hit(lines, i, line, code) := _msg_missing if {
	regex.match(_lit_re, code)
	txt := _lit_text(lines, i, line)
	not _httponly_set(txt)
	not _deletion(txt)
	not _js_readable(txt)
	e := _fn_end(lines, i)
	_sent(lines, i, line, e)
	not _fixed_later(lines, i, line, e)
}

_hit(lines, i, line, code) := _msg_missing if {
	contains(code, "new(http.Cookie)")
	e := _fn_end(lines, i)
	_sent(lines, i, line, e)
	not _fixed_later(lines, i, line, e)
}

# gin c.SetCookie(name, value, maxAge, path, domain, secure, httpOnly).
_hit(lines, i, line, code) := _msg_false if {
	contains(code, "SetCookie(")
	txt := _gin_call(lines, i, line)
	regex.match(`\.SetCookie\(\s*(?:(?:[^,()]|\((?:[^()]|\([^()]*\))*\))+,){6}\s*false\s*,?\s*\)`, txt)
	not regex.match(`\.SetCookie\(\s*"(?i:[^"]*(?:csrf|xsrf)[^"]*)"`, txt)
}

_pdepth(s) := count(indexof_n(s, "(")) - count(indexof_n(s, ")"))

# The SetCookie call joined onto one line when its arguments are wrapped
# (at most 10 lines).
_gin_call(_, _, line) := line if _pdepth(_code(line)) <= 0

_gin_call(lines, i, line) := txt if {
	_pdepth(_code(line)) > 0
	end := min([count(lines) - 1, i + 10])
	end >= i + 1
	ks := [k |
		some k in numbers.range(i + 1, end)
		_pdepth(concat(" ", [_code(lines[j]) | some j in numbers.range(i, k)])) <= 0
	]
	count(ks) > 0
	txt := concat(" ", [lines[j] | some j in numbers.range(i, ks[0])])
}

_hit(_, _, _, code) := _msg_false if regex.match(`\bcsrf\.HttpOnly\(\s*false\s*\)`, code)

_hit(_, _, _, code) := _msg_false if regex.match(`^\s*[\w\.]*\.(?:HttpOnly|HTTPOnly)\s*=\s*false\b`, code)

_hit(_, _, _, code) := _msg_store if {
	regex.match(`\bsessions\.New(?:Cookie|Filesystem)Store\(`, code)
	not _project_sets_store_options
}

_project_sets_store_options if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "Options")
	regex.match(`\.Options\s*=|\.Options\(|\.Options\.\w+\s*=`, content)
}

_hint(line) if contains(line, "Cookie")

_hint(line) if contains(line, "sessions.")

_hint(line) if contains(line, "HttpOnly")

_hint(line) if contains(line, "HTTPOnly")

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`http\.Cookie|fiber\.Cookie|sessions\.|SetCookie\(|csrf\.HttpOnly|\.(?:HttpOnly|HTTPOnly)\s*=`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_hint(line)
	not helpers.is_comment_line(line)
	code := _code(line)
	some msg in {m | m := _hit(lines, i, line, code)}
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
