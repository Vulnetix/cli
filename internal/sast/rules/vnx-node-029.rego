package vulnetix.rules.vnx_node_029

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-029",
	"name": "Missing HttpOnly flag on cookie",
	"description": "Reports a session or credential cookie set without HttpOnly in Node.js: an Express res.cookie() (also response/resp/reply.cookie(), reply.setCookie()) or cookie.serialize() call whose cookie name or value names a session, sid, token, auth, JWT, login, credential or access/refresh token and whose options (inline, across lines, or an options object assigned in the same file) do not set httpOnly: true (both APIs default to a script-readable cookie), a Set-Cookie header literal for such a cookie without the HttpOnly attribute (setHeader/append/set, the first entry of an array, or a writeHead headers object), and any cookie options that set httpOnly: false. Script-readable session cookies are stolen by any XSS. Not reported: options with httpOnly: true, options the rule cannot see (imported, built by a helper call, or spread from another object), non-sensitive cookies (theme, lang, remember=1, lookalike names such as authorFilter or accessibilityMode), CSRF/XSRF token cookies (which the page must read), Koa ctx.cookies.set() (HttpOnly by default) unless it sets httpOnly: false, cookies being cleared (empty value, clearCookie), comments, strings and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-029/",
	"languages": ["javascript", "typescript"],
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

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".jsx")
_is_js(path) if endswith(path, ".tsx")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

_call_re := `(?:\b(?:res|resp|response|reply)\.(?:cookie|setCookie)|\bcookie\.serialize)\s*\(`

# auth but not author (authorFilter); access but not accessibility.
_sensitive_re := `(?i)(sess|\bsid\b|sid['"]|token|auth(?:$|[^o]|o[^r])|jwt|login|identity|credential|bearer|access(?:$|[^i])|refresh|remember_?me)`

_csrf_re := `(?i)(csrf|xsrf)`

_strip(s) := regex.replace(s, concat("", [`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`, "`[^`]*`"]), `''`)

_depth(lines, s, j) := sum([d |
	some k in numbers.range(s, j)
	c := _strip(lines[k])
	d := strings.count(c, "(") - strings.count(c, ")")
])

_call_end(lines, i) := e if {
	hi := min([count(lines) - 1, i + 8])
	ends := [j | some j in numbers.range(i, hi); _depth(lines, i, j) <= 0]
	e := min(array.concat(ends, [hi]))
}

_call_text(lines, i) := concat("\n", [l | some k in numbers.range(i, _call_end(lines, i)); l := lines[k]; not helpers.is_comment_line(l)])

_args(text) := a if {
	m := regex.find_all_string_submatch_n(concat("", ["(?s)", _call_re, `(.*)$`]), text, 1)
	count(m) > 0
	a := m[0][1]
}

# The cookie name and value: the arguments before the options object.
_head(args) := concat(",", array.slice(split(split(replace(args, "${", "$<"), "{")[0], ","), 0, 2))

_value(args) := trim_space(split(split(args, "{")[0], ",")[1])

_clearing(args) if _value(args) in {"''", `""`, "``", "null", "undefined"}

_clearing(args) if regex.match(`expires\s*:\s*new Date\(\s*0\s*\)|maxAge\s*:\s*0\b`, args)

_httponly_true(_, args) if regex.match(`\bhttpOnly\s*:\s*true\b`, args)

# options passed as a variable defined in the file
_httponly_true(content, args) if {
	not contains(args, "{")
	parts := split(args, ",")
	count(parts) >= 3
	id := trim(trim_space(parts[2]), ") ;")
	regex.match(`^[A-Za-z_$][\w$.]*$`, id)
	regex.match(concat("", [`(?s)\b`, id, `\b[^=\n]*=\s*\{[^}]*httpOnly\s*:\s*true`]), content)
}

# options variable the rule cannot see: say nothing
_unknown_options(content, args) if {
	not contains(args, "{")
	parts := split(args, ",")
	count(parts) >= 3
	id := trim(trim_space(parts[2]), ") ;")
	regex.match(`^[A-Za-z_$][\w$.]*$`, id)
	not regex.match(concat("", [`\b`, id, `\b[^=\n]*=\s*\{`]), content)
}

# options built by a helper call: cookieOptions()
_unknown_options(_, args) if {
	not contains(args, "{")
	parts := split(args, ",")
	count(parts) >= 3
	regex.match(`^\s*[A-Za-z_$][\w$.]*\s*\(`, parts[2])
}

# options spread from another object: { ...base, maxAge }
_unknown_options(_, args) if regex.match(`\{\s*\.\.\.|,\s*\.\.\.[A-Za-z_$]`, args)

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "ookie")
	not helpers.is_test_path(path)
	not endswith(path, ".min.js")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ookie")
	not helpers.is_comment_line(line)
	regex.match(_call_re, _strip(line))
	args := _args(_call_text(lines, i))
	head := _head(args)
	regex.match(_sensitive_re, head)
	not regex.match(_csrf_re, head)
	not _clearing(args)
	not regex.match(`\bhttpOnly\s*:`, args)
	not _httponly_true(content, args)
	not _unknown_options(content, args)
	finding := {
		"rule_id": metadata.id,
		"message": "Session/credential cookie set without httpOnly: true; page scripts (and any XSS) can read it. Pass { httpOnly: true, secure: true, sameSite: 'lax' }",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# explicit httpOnly: false in cookie options
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "httpOnly")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "httpOnly")
	not helpers.is_comment_line(line)
	regex.match(`\bhttpOnly\s*:\s*false\b`, line)
	some j in numbers.range(max([0, i - 6]), i)
	regex.match(`\.cookies?\s*\(|\.cookies\.set\s*\(|setCookie\s*\(|\bserialize\s*\(`, lines[j])
	not helpers.is_comment_line(lines[j])
	finding := {
		"rule_id": metadata.id,
		"message": "Cookie set with httpOnly: false; page scripts (and any XSS) can read it. Use httpOnly: true unless the page genuinely needs the value",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Set-Cookie header literal for a session cookie without HttpOnly
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "Set-Cookie")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Set-Cookie")
	not helpers.is_comment_line(line)
	regex.match(`\.(setHeader|header|set|append|writeHead)\s*\(\s*['"]Set-Cookie['"]\s*,\s*\[?\s*['"\x60]|^\s*['"]?Set-Cookie['"]?\s*:\s*\[?\s*['"\x60]`, line)
	m := regex.find_all_string_submatch_n(`['"]?Set-Cookie['"]?\s*[,:]\s*\[?\s*['"\x60]\s*([\w.-]+)=`, line, 1)
	count(m) > 0
	regex.match(_sensitive_re, m[0][1])
	not regex.match(_csrf_re, m[0][1])
	not regex.match(`(?i)httponly`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Set-Cookie header for a session/credential cookie lacks the HttpOnly attribute; page scripts (and any XSS) can read it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
