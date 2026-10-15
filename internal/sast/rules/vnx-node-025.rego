package vulnetix.rules.vnx_node_025

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-025",
	"name": "Insecure express-session or cookie-session configuration",
	"description": "Reports the options object passed to an express-session or cookie-session middleware (the name bound by require()/import of that package, called inline or with an options variable defined in the same file) when it sets secure: false or httpOnly: false, and an express-session configuration that never sets the cookie's secure flag (express-session defaults it to false, so the session id travels over plain HTTP). A secure flag set to any non-false expression (true, 'auto', process.env.NODE_ENV === 'production') or assigned later through <options>.cookie.secure = ... counts as set. Not reported: cookie-session without an explicit secure (it marks the cookie Secure on HTTPS requests), resave/saveUninitialized settings, secure: false on other objects (mail transports, HTTP agents), options the rule cannot see (imported from another module), commented-out configuration, and test or example files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-025/",
	"languages": ["javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [614],
	"capec": ["CAPEC-60"],
	"attack_technique": ["T1539"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["session", "cookie", "secure-flag", "express", "node"],
}

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".jsx")
_is_js(path) if endswith(path, ".tsx")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

_is_sample_path(path) if regex.match(`(^|/)(examples?|samples?|demos?)/`, path)

_require_re := `(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"](express-session|cookie-session)['"]\s*\)`

_import_re := `import\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s*from\s*['"](express-session|cookie-session)['"]`

# name bound to the middleware factory -> package
_bindings(content) := {[m[1], m[2]] |
	some re in [_require_re, _import_re]
	some m in regex.find_all_string_submatch_n(re, content, -1)
}

_depth(lines, s, j) := sum([d |
	some k in numbers.range(s, j)
	not helpers.is_comment_line(lines[k])
	d := strings.count(lines[k], "{") - strings.count(lines[k], "}")
])

# Last line of the object literal opened on line s (bounded).
_obj_end(lines, s) := e if {
	hi := min([count(lines) - 1, s + 60])
	ends := [j | some j in numbers.range(s, hi); _depth(lines, s, j) <= 0]
	e := min(array.concat(ends, [hi]))
}

# Line k lies inside a /* ... */ block opened at or after s.
_in_block_comment(lines, s, k) if {
	opens := [j | some j in numbers.range(s, k); contains(lines[j], "/*")]
	count(opens) > 0
	o := max(opens)
	not _closed_after(lines, o, k)
}

_closed_after(lines, o, k) if {
	some j in numbers.range(o, k - 1)
	contains(lines[j], "*/")
	not _opens_after_close(lines[j])
}

_closed_after(lines, o, k) if {
	o == k
	contains(lines[k], "*/")
}

_opens_after_close(line) if {
	regex.match(`\*/.*/\*`, line)
}

# The line with string-literal contents removed, so a call named in a message
# is not a call.
_strip(line) := regex.replace(line, concat("", [`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`, "`[^`]*`"]), `""`)

# The options object of a call on line i: [start, end, options identifier or ""].
_options(lines, i, name) := [i, _obj_end(lines, i), ""] if {
	regex.match(concat("", [`\b`, name, `\s*\(\s*\{`]), _strip(lines[i]))
}

_options(lines, i, name) := [s, _obj_end(lines, s), id] if {
	m := regex.find_all_string_submatch_n(concat("", [`\b`, name, `\s*\(\s*([A-Za-z_$][\w$]*)\s*\)`]), _strip(lines[i]), 1)
	count(m) > 0
	id := m[0][1]
	defs := [j |
		some j, l in lines
		contains(l, id)
		regex.match(concat("", [`^\s*(?:export\s+)?(?:const|let|var)\s+`, id, `\b[^=]*=\s*\{`]), l)
	]
	count(defs) > 0
	s := defs[0]
}

_calls contains [i, opts, pkg] if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	regex.match(`(express|cookie)-session`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some b in _bindings(content)
	name := b[0]
	some i, line in lines
	contains(line, name)
	not helpers.is_comment_line(line)
	not contains(line, "require(")
	not regex.match(`^\s*import\b`, line)
	opts := _options(lines, i, name)
	not _in_block_comment(lines, max([0, i - 40]), i)
	pkg := [path, b[1]]
}

_flag_re := `\b(secure|httpOnly)\s*:\s*false\b`

# First line of `const <id> = {` in the file.
_obj_def(lines, id) := s if {
	defs := [j |
		some j, l in lines
		contains(l, id)
		regex.match(concat("", [`^\s*(?:export\s+)?(?:const|let|var)\s+`, id, `\b[^=]*=\s*\{`]), l)
	]
	count(defs) > 0
	s := defs[0]
}

# Identifier given as the cookie options (cookie: cookieOptions).
_cookie_ref(lines, s, e) := id if {
	ids := [m[0][1] |
		some k in numbers.range(s, e)
		not helpers.is_comment_line(lines[k])
		m := regex.find_all_string_submatch_n(`\bcookie\s*:\s*([A-Za-z_$][\w$]*)\s*(?:,|\}|$)`, lines[k], 1)
		count(m) > 0
	]
	count(ids) > 0
	id := ids[0]
}

# The ranges whose flags describe the session cookie: the options object and
# a cookie options object it names in this file.
_ranges(lines, c) := [[c[1][0], c[1][1]]] if not _cookie_ref(lines, c[1][0], c[1][1])

_ranges(lines, c) := [[c[1][0], c[1][1]], [d, _obj_end(lines, d)]] if {
	id := _cookie_ref(lines, c[1][0], c[1][1])
	d := _obj_def(lines, id)
}

_ranges(lines, c) := [[c[1][0], c[1][1]]] if {
	id := _cookie_ref(lines, c[1][0], c[1][1])
	not _obj_def(lines, id)
}

# The cookie options are an identifier: settled when its object sets secure,
# and unknown (so not reported) when it is not defined in this file.
_cookie_secure_known(lines, c) if {
	id := _cookie_ref(lines, c[1][0], c[1][1])
	not _obj_def(lines, id)
}

_cookie_secure_known(lines, c) if {
	id := _cookie_ref(lines, c[1][0], c[1][1])
	d := _obj_def(lines, id)
	_sets_secure(lines, d, _obj_end(lines, d))
}

_cookie_secure_known(lines, c) if {
	id := _cookie_ref(lines, c[1][0], c[1][1])
	regex.match(concat("", [`\b`, id, `\.secure\s*=\s*[^=\s]`]), concat("\n", lines))
}

findings contains finding if {
	some c in _calls
	path := c[2][0]
	lines := split(input.file_contents[path], "\n")
	some r in _ranges(lines, c)
	some k in numbers.range(r[0], r[1])
	line := lines[k]
	contains(line, "false")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_flag_re, line, 1)
	count(m) > 0
	not _in_block_comment(lines, r[0], k)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Session cookie configured with %s: false; set %s: true so the session id is only sent over HTTPS and cannot be read by page scripts", [m[0][1], m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": line,
	}
}

_sets_secure(lines, s, e) if {
	some k in numbers.range(s, e)
	not helpers.is_comment_line(lines[k])
	regex.match(`\bsecure\s*:|[{,]\s*secure\s*(?:[,}]|$)|\.\.\.[A-Za-z_$]`, lines[k])
	not _in_block_comment(lines, s, k)
}

_secure_assigned(content, id) if {
	id != ""
	regex.match(concat("", [`\b`, id, `\.cookie\.secure\s*=\s*[^=\s]`]), content)
}

_secure_assigned(content, _) if {
	regex.match(`(?m)^\s*[\w$.]*\.cookie\.secure\s*=\s*(?:true|['"]auto['"])`, content)
}

findings contains finding if {
	some c in _calls
	c[2][1] == "express-session"
	path := c[2][0]
	not _is_sample_path(path)
	content := input.file_contents[path]
	lines := split(content, "\n")
	not _sets_secure(lines, c[1][0], c[1][1])
	not _cookie_secure_known(lines, c)
	not _secure_assigned(content, c[1][2])
	finding := {
		"rule_id": metadata.id,
		"message": "express-session is configured without cookie.secure (it defaults to false), so the session cookie is sent over plain HTTP; set cookie: { secure: true } (or 'auto' behind a TLS-terminating proxy)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c[0] + 1,
		"snippet": lines[c[0]],
	}
}
