# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_501

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-501",
	"name": "Trust Boundary Violation",
	"description": "A value read from the HTTP request is stored in the server-side session, where the rest of the application treats it as trusted state. Reported in Java: HttpSession.setAttribute()/putValue() (on a session variable or on request.getSession()) whose key or value is a request parameter, header, cookie, query string, body reader or a Spring @RequestParam/@PathVariable/@RequestHeader/@CookieValue/@RequestBody argument, inline or through up to four assignments in the 60 lines above (including a for-each over getCookies(), a single-line if-assignment, a map entry read back under the same literal key, and a same-file helper method that returns its parameter). Reported in Python: session[...] = (Flask session, flask.session, Django request.session) or session.update()/setdefault() with a value or key from request.args/form/values/cookies/headers/json/data/GET/POST/COOKIES/META or from an object constructed from request, inline (f-string interpolation included) or through such assignments. A value stored in a list (Java add/set/push, Python append/insert or a dict/list subscript) is followed to a later read of that collection. Before reporting, the enclosing method or function (at most 120 lines up) is read, and a name that provably holds a constant at the session write is not request data: a literal it was last assigned on every live path, the taken side of an if/else or conditional expression whose condition folds to a constant (integer literals and int locals assigned once, or in Python a literal tested with in/not in against a string local), the selected case of a switch or match on a constant, the element a list index or map, dict or ConfigParser key actually holds when that is a literal, a Python copy of what a name held at that line, and the result of a same-file method or function whose every return is constant. Not reported: constant or server-generated values, a value checked against an allowlist, pattern or validator first (a .contains()/.matches()/re.match/valid*/sanitize* line naming it), a session written after a password check or authenticate() call (the identity the server established), reading the session, comments and string literals. A value the analysis cannot resolve (a condition on run-time data, a helper in another file, a collection passed elsewhere) stays reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-501/",
	"languages": ["java", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [501],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["trust-boundary", "session", "cwe-501"],
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "py" if endswith(path, ".py")

_gate("java", content) if {
	contains(content, "ession")
	regex.match(`(?:setAttribute|putValue)\s*\(`, content)
}

_gate("py", content) if {
	contains(content, "session")
	contains(content, "request")
}

_src := {
	"java": `\b\w*(?:[Rr]equest|req)\s*\.\s*(?:getParameter\w*|getHeaders?|getHeaderNames|getCookies|getQueryString|getReader|getInputStream|getPathInfo|getRequestURI)\s*\(`,
	"py": `\brequest\s*\.\s*(?:args|form|values|cookies|headers|json|data|GET|POST|COOKIES|META|get_json|query_params)\b|\b\w+\s*\(\s*request\s*\)`,
}

_sink := {
	"java": `\b(?:\w*[Ss]ession|sess)(?:\(\w*\))?\s*\.\s*(?:setAttribute|putValue)\s*\(`,
	"py": `\bsession\s*(?:\[[^\]]+\]\s*=[^=]|\.\s*(?:update|setdefault)\s*\()`,
}

# String literals blanked: a sink or source named inside a message is text.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_assign_re := {
	"java": `^\s*(?:final\s+)?(?:[\w.]+(?:<[^=]*>)?(?:\[\])*\s+)?(\w+)\s*\+?=\s*([^=].*)$`,
	"py": `^\s*(\w+)(?:\s*:\s*[\w\[\], .]+)?\s*\+?=\s*([^=].*)$`,
}

_foreach_re := {
	"java": `\bfor\s*\(\s*(?:final\s+)?[\w.<>\[\]]+\s+(\w+)\s*:\s*(.+)\)`,
	"py": `^\s*for\s+(\w+)\s+in\s+(.+):`,
}

_annot_re := `@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody)(?:\s*\([^)]*\))?\s+(?:final\s+)?[\w.<>\[\]]+\s+(\w+)`

_words(s) := {w | some m in regex.find_all_string_submatch_n(`[A-Za-z_]\w*`, s, -1); w := m[0]}

_bindings(lang, line) := [m[1], m[2]] if {
	m := regex.find_all_string_submatch_n(_assign_re[lang], line, 1)[0]
}

_bindings(lang, line) := [m[1], m[2]] if {
	m := regex.find_all_string_submatch_n(_foreach_re[lang], line, 1)[0]
}

# An assignment guarded on the same line: `if (cond) bar = param;`.
_bindings(lang, line) := [m[1], m[2]] if {
	m := regex.find_all_string_submatch_n(`^\s*(?:\}?\s*else\s+)?if\s*\(.*\)\s*(\w+)\s*\+?=\s*([^=].*)$`, line, 1)[0]
}

# A map entry is a value of its own, keyed by the literal: map.put("k", v)
# carries v to map.get("k") and to no other key.
_map_puts(lang, l) := [[concat("#", [m[1], m[2]]), m[3]] |
	lang == "java"
	contains(l, ".put(")
	some m in regex.find_all_string_submatch_n(`^\s*(\w+)\s*\.\s*put\s*\(\s*"([^"]*)"\s*,\s*(.*)\)\s*;`, l, 1)
]

_map_gets(lang, l) := {concat("#", [m[1], m[2]]) |
	lang == "java"
	contains(l, ".get(")
	some m in regex.find_all_string_submatch_n(`(\w+)\s*\.\s*get\s*\(\s*"([^"]*)"\s*\)`, l, -1)
}

# Names interpolated into a Python f-string, which _code blanks.
_fwords("java", _) := set()

_fwords("py", l) := {w |
	contains(l, "{")
	some m in regex.find_all_string_submatch_n(`\bf["'][^"']*\{([^{}]+)\}`, l, -1)
	some w in _words(m[1])
}

# Every assignment in the window, with the identifiers on its right side.
_assigns(lang, lines, s, e) := array.concat(array.concat(
	[{"j": j, "v": b[0], "w": (_words(b[1]) | _map_gets(lang, l)) | _fwords(lang, l)} |
		some j in numbers.range(s, e)
		l := lines[j]
		not helpers.is_comment_line(l)
		c := _code(l)
		some b in [x | x := _bindings(lang, c)]
	],
	[{"j": j, "v": p[0], "w": _words(_code(p[1]))} |
		some j in numbers.range(s, e)
		l := lines[j]
		not helpers.is_comment_line(l)
		some p in _map_puts(lang, l)
	]),
	[{"j": j, "v": p[0], "w": _words(p[1])} |
		some j in numbers.range(s, e)
		l := lines[j]
		not helpers.is_comment_line(l)
		some p in _carrier_stores(lang, _code(l))
	],
)

# A value stored into a list (or a Python dict/list by subscript; the session
# itself is the sink, not a carrier) taints the
# collection, so a later read of it is followed; whether the element read is
# the stored one is decided by the constant analysis at the sink.
_carrier_stores("java", c) := [[m[1], m[2]] |
	contains(c, ".")
	some m in regex.find_all_string_submatch_n(`^\s*(\w+)\s*\.\s*(?:add|addAll|addElement|push|offer|set|insert)\s*\((.*)\)\s*;`, c, 1)
]

_carrier_stores("py", c) := array.concat([[m[1], m[2]] |
	some m in regex.find_all_string_submatch_n(`^\s*(\w+)\s*(?:\[[^\]]*\]\s*=\s*([^=].*)$|\.\s*(?:append|insert|extend|add|update|setdefault|set)\s*\((.*)\)\s*$)`, c, 1)
	m[2] != ""
	not endswith(lower(m[1]), "session")
], [[m[1], m[3]] |
	some m in regex.find_all_string_submatch_n(`^\s*(\w+)\s*(?:\[[^\]]*\]\s*=\s*([^=].*)$|\.\s*(?:append|insert|extend|add|update|setdefault|set)\s*\((.*)\)\s*$)`, c, 1)
	m[3] != ""
	not endswith(lower(m[1]), "session")
])

_seed(lang, lines, asg, s, e) := {a.v | some a in asg; regex.match(_src[lang], _code(lines[a.j]))} | {m[1] |
	lang == "java"
	some j in numbers.range(s, e)
	contains(lines[j], "@")
	some m in regex.find_all_string_submatch_n(_annot_re, lines[j], -1)
}

_step(asg, t) := t | {a.v | some a in asg; count(a.w & t) > 0}

_tainted(lang, lines, i) := t if {
	s := max([0, i - 60])
	e := i - 1
	e >= s
	asg := _assigns(lang, lines, s, e)
	t0 := _seed(lang, lines, asg, s, e)
	t := _step(asg, _step(asg, _step(asg, _step(asg, t0))))
}

_after("py", c) := c

_after("java", c) := concat(" ", array.slice(parts, 1, count(parts))) if parts := regex.split(_sink.java, c)

# The sink's arguments: the rest of the line, plus up to two continuation
# lines of a Java call split across lines.
_args("py", lines, i, c) := c

_args("java", lines, i, c) := c if regex.match(`[;{]\s*$`, c)

_args("java", lines, i, c) := concat(" ", array.concat([c], [_code(lines[j]) | some j in numbers.range(i + 1, min([count(lines) - 1, i + 2]))])) if {
	not regex.match(`[;{]\s*$`, c)
}

_reported(lang, lines, i, args) if regex.match(_src[lang], args)

_reported(lang, lines, i, args) if {
	t := _tainted(lang, lines, i)
	cand := {h | some h in _words(args) & t; not _helper_clean(lang, lines, i, h)}
	count(cand) > 0
	C := _consts(lang, lines, i)
	hit := {h | some h in cand; not _const_at(C, h)}
	count(hit) > 0
	not _guarded(lines, i, hit)
	not _authenticated(lines, i)
}

# The method is read before reporting: a name that provably holds a constant
# at the session write (helpers.flow_consts / flow_py_consts: a literal on
# every live path, a folded condition or switch/match, a collection read at
# a constant index or key, a same-file helper returning a constant) carries
# no request data, whatever it was derived from on a dead path.
_consts("java", lines, i) := helpers.flow_consts(lines, i)

_consts("py", lines, i) := helpers.flow_py_consts(lines, i)

_const_at(C, h) if _ = C[h]

# The variable was last assigned the result of a method declared in this
# file (`v = new Helper().pick(request, param)`), and that method's
# returned variable is not derived from its parameters or a request source:
# the helper does not pass the request data on.
_helper_clean("java", lines, i, h) if {
	s := max([0, i - 60])
	js := [j |
		some j in numbers.range(s, i - 1)
		not helpers.is_comment_line(lines[j])
		b := _bindings("java", _code(lines[j]))
		b[0] == h
	]
	count(js) > 0
	j := max(js)
	m := regex.find_all_string_submatch_n(`\b(\w+)\s*\(([^()]*)\)\s*;\s*$`, _code(lines[j]), 1)[0]
	name := m[1]
	decl_re := concat("", [`^\s*(?:(?:public|private|protected|static|final|synchronized)\s+)*[\w.<>\[\]]+\s+`, name, `\s*\(`])
	some k, l in lines
	k != j
	contains(l, name)
	regex.match(decl_re, l)
	rest := regex.split(concat("", [name, `\s*\(`]), l)[1]
	params := {p[1] | some p in regex.find_all_string_submatch_n(`[\w.<>\[\]]+\s+(\w+)\s*(?:,|\)|$)`, rest, -1)}
	rets := [r |
		some r in numbers.range(k + 1, min([count(lines) - 1, k + 60]))
		regex.match(`^\s*return\s+\w+\s*;`, lines[r])
	]
	count(rets) > 0
	r := rets[0]
	rv := regex.find_all_string_submatch_n(`^\s*return\s+(\w+)\s*;`, lines[r], 1)[0][1]
	asg := _assigns("java", lines, k + 1, r - 1)
	t0 := params | _seed("java", lines, asg, k + 1, r - 1)
	t := _step(asg, _step(asg, _step(asg, _step(asg, t0))))
	not rv in t
}

_guard_re :=`(?i)\.contains\s*\(|\.matches\s*\(|\bvalid|sanitiz|allowlist|whitelist|\bre\.(?:full)?match\s*\(|\bin\s+[A-Z][A-Z0-9_]{2,}\b`

_guarded(lines, i, hit) if {
	some j in numbers.range(max([0, i - 30]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_guard_re, l)
	count(_words(_code(l)) & hit) > 0
}

_authenticated(lines, i) if {
	w := helpers.code_window(lines, i, 30, 0)
	regex.match(`check_password\w*\s*\(|\bauthenticate\s*\(|verify_password\s*\(|\bcheckpw\s*\(|\.matches\s*\(\s*\w*(?:[Pp]assword|[Pp]wd)|\blogin_user\s*\(`, w)
}

_is_sink(lang, _, c) if regex.match(_sink[lang], c)

# `from flask import session as flask_session`: the alias is the session.
_is_sink("py", content, c) if {
	contains(content, "session as ")
	some m in regex.find_all_string_submatch_n(`\bimport\s+(?:[\w, ]+,\s*)?session\s+as\s+(\w+)`, content, 3)
	regex.match(concat("", [`\b`, m[1], `\s*(?:\[[^\]]+\]\s*=[^=]|\.\s*(?:update|setdefault)\s*\()`]), c)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ess")
	not helpers.is_comment_line(line)
	c := _code(line)
	_is_sink(lang, content, c)
	args := _args(lang, lines, i, _after(lang, c))
	_reported(lang, lines, i, args)
	finding := {
		"rule_id": metadata.id,
		"message": "Untrusted request data is stored in the server-side session, where the application will treat it as trusted; validate it against an allowlist before storing it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
