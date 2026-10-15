package vulnetix.rules.vnx_go_030

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-030",
	"name": "Missing Secure flag on cookie",
	"description": "A cookie the server sends to the browser is not marked Secure, so the browser also sends it over plain HTTP where a network attacker can read it. Reported: an http.Cookie, fiber.Cookie or gorilla sessions.Options literal with no Secure field or with Secure: false that is passed to http.SetCookie/c.SetCookie/c.Cookie, returned to a caller, or assigned to a variable that is (session.Options = &sessions.Options{...} configures every session cookie); a new(http.Cookie) that is sent without .Secure being set; gin c.SetCookie(name, value, maxAge, path, domain, false, httpOnly); csrf.Secure(false); x.Secure = false / store.Options.Secure = false; a hand-written Set-Cookie header (w.Header().Set/Add(\"Set-Cookie\", ...)) whose attributes on that line include no Secure; and sessions.NewCookieStore/NewFilesystemStore in a project that never sets the store's Options (their default leaves Secure off). Not reported: Secure set to true or to any expression (Secure: !isLocal, r.TLS != nil, a config value), a deletion cookie (MaxAge negative, Expires at the Unix epoch), cookies a client sends (req.AddCookie, a cookie jar, a []*http.Cookie built to send), test files, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-030/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [614],
	"capec": ["CAPEC-63"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cookie", "secure", "session"],
}

_msg_missing := "Cookie is sent without the Secure attribute: the browser will also send it over plain HTTP, where it can be read. Set Secure: true (and HttpOnly, SameSite)"

_msg_false := "Cookie Secure attribute is explicitly turned off: the browser will send it over plain HTTP, where it can be read. Set it to true"

_msg_store := "gorilla sessions store is created and its Options are never set: the default session cookie has Secure off. Set store.Options = &sessions.Options{Secure: true, HttpOnly: true, ...}"

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

_secure_false(txt) if regex.match(`\bSecure\s*:\s*false\b`, txt)

_secure_set(txt) if regex.match(`\bSecure\s*:`, txt)

_word(n) := concat("", [`\b`, n, `\b`])

# The literal's variable, if it is assigned to one.
_var(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:var\s+)?([A-Za-z_]\w*)\s*:?=\s*(?:&?(?:http\.Cookie|fiber\.Cookie|sessions\.Options)\{|new\(http\.Cookie\))`, line, 1)
	count(m) > 0
	v := m[0][1]
}

# The cookie goes to the browser: the literal sits in a SetCookie/Cookie
# call, is returned, configures a session store, or its variable is set or
# returned later in the function.
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

# x.Secure = ... later in the function.
_secure_assigned(lines, i, line, e) if {
	v := _var(line)
	i + 1 <= e
	some k in numbers.range(i + 1, e)
	regex.match(concat("", [`^\s*`, v, `\.Secure\s*=\s*\S`]), lines[k])
	not regex.match(`=\s*false\b`, lines[k])
}

_hit(lines, i, line, code) := _msg_false if {
	regex.match(_lit_re, code)
	ms := regex.find_all_string_submatch_n(_lit_re, line, 1)
	count(ms) > 0
	txt := _literal(lines, i, substring(line, indexof(line, ms[0][0]), -1))
	_secure_false(txt)
}

_hit(lines, i, line, code) := _msg_missing if {
	regex.match(_lit_re, code)
	ms := regex.find_all_string_submatch_n(_lit_re, line, 1)
	count(ms) > 0
	txt := _literal(lines, i, substring(line, indexof(line, ms[0][0]), -1))
	not _secure_set(txt)
	not _deletion(txt)
	e := _fn_end(lines, i)
	_sent(lines, i, line, e)
	not _secure_assigned(lines, i, line, e)
}

_hit(lines, i, line, code) := _msg_missing if {
	contains(code, "new(http.Cookie)")
	e := _fn_end(lines, i)
	_sent(lines, i, line, e)
	not _secure_assigned(lines, i, line, e)
}

# gin c.SetCookie(name, value, maxAge, path, domain, secure, httpOnly).
_hit(_, _, line, code) := _msg_false if {
	contains(code, "SetCookie(")
	regex.match(`\.SetCookie\(\s*(?:(?:[^,()]|\([^()]*\))+,){5}\s*false\s*,`, line)
}

_hit(_, _, _, code) := _msg_false if regex.match(`\bcsrf\.Secure\(\s*false\s*\)`, code)

_hit(_, _, _, code) := _msg_false if regex.match(`^\s*[\w\.]*\.Secure\s*=\s*false\b`, code)

_hit(_, _, _, code) := _msg_store if {
	regex.match(`\bsessions\.New(?:Cookie|Filesystem)Store\(`, code)
	not _project_sets_store_options
}

# A Set-Cookie header written by hand whose attributes on the line carry no
# Secure: w.Header().Add("Set-Cookie", "sid="+id+"; Path=/; HttpOnly").
_hit(_, _, line, code) := _msg_missing if {
	regex.match(`\.Header\(\)\.(?:Set|Add)\(\s*""\s*,`, code)
	regex.match(`\.Header\(\)\.(?:Set|Add)\(\s*"Set-Cookie"\s*,`, line)
	regex.match(`(?i);\s*(?:path|httponly|samesite|max-age|expires|domain)\b`, line)
	not regex.match(`(?i);\s*secure\b`, line)
	not regex.match(`(?i)max-age=(?:0\b|-)|1970`, line)
}

_project_sets_store_options if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "Options")
	regex.match(`\.Options\s*=|\.Options\(|\.Options\.\w+\s*=`, content)
}

_hint(line) if contains(line, "Cookie")

_hint(line) if contains(line, "sessions.")

_hint(line) if contains(line, "Secure")

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`http\.Cookie|fiber\.Cookie|sessions\.|SetCookie\(|"Set-Cookie"|csrf\.Secure|\.Secure\s*=`, content)
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
