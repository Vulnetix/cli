# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_346

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-346",
	"name": "Origin Validation Error",
	"description": "A request's Origin or Referer (or a postMessage event.origin) is validated by a test that a hostile site can satisfy. Reported, in JavaScript/TypeScript, Python, Java and Go: a substring test of the origin (indexOf/includes/contains/search, Python `\"x\" in origin`, Go strings.Contains/strings.Index) against a domain literal or a variable (`referer.contains(host)`); a prefix test (startsWith/startswith/strings.HasPrefix) against a domain literal that does not end in '/' (https://app.example.com.evil.net passes); a suffix test (endsWith/endswith/strings.HasSuffix) against a domain literal without a leading dot (evilexample.com passes); a regular expression applied to the origin that is not anchored at the end (re.match/re.search in Python, /re/.test() and .match() in JavaScript); and a gorilla/websocket CheckOrigin function that only returns true (in the Upgrader literal or assigned as upgrader.CheckOrigin = func...). The origin is recognised as an identifier named origin/referer/referrer (event.origin, req.headers.origin, document.referrer, also through optional chaining such as req.headers.origin?.includes(...)), a header read of Origin/Referer, or a variable of any name assigned directly from one of those in the 10 lines above (const sender = event.origin). A substring test whose argument is a concatenation (origin.includes('://' + host)) is reported too. Not reported: exact comparisons and allow-list membership (ALLOWED.has(origin), allowedOrigins.includes(origin), origin in ALLOWED), anchored regular expressions and re.fullmatch, a suffix with a leading dot, scheme checks (startsWith('https://')), parsed host comparisons, document.referrer tested against a bare domain (traffic-source analytics such as indexOf(\"google.com\"); a test against a full origin with a scheme is still reported), comments and string literals. Wildcard and reflected CORS headers are VNX-SEC-012's concern, and a message listener that never checks the origin is VNX-NODE-024's.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-346/",
	"languages": ["node", "python", "java", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [346],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["origin-validation", "csrf", "cwe-346", "cors"],
}

_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".py", ".java", ".go"}

_ext_ok(path) if {
	some e in _exts
	endswith(path, e)
}

# The origin value: an identifier whose last segment names it, or a header
# read of Origin/Referer.
_recv := `(?:\b(?:[A-Za-z_$][\w$]*\.)*(?i:origin|referr?er|req_?origin|request_?origin|origin_?header|http_origin|http_referer|referer_?header)\b(?:\(\))?|\b(?:[A-Za-z_$][\w$]*(?:\(\))?\.)+(?:get|getHeader|header|Get)\(\s*["'](?i:origin|referr?er)["'](?:\s*,\s*["'][^"']*["'])?\s*\)(?:\s*(?:\?\?|\|\|)\s*["']["'])?|\[\s*["'](?i:origin|referr?er|http_origin|http_referer)["']\s*\])`

_lit := "[\"'`]([^\"'`]*)[\"'`]"

_method_re := concat("", [_recv, `\s*\??\.(indexOf|includes|contains|search|startsWith|startswith|endsWith|endswith)\(\s*(?:`, _lit, `|([A-Za-z_$][\w$.]*)\s*[,)])`])

_go_re := concat("", [`\bstrings\.(Contains|Index|HasPrefix|HasSuffix)\(\s*`, _recv, `\s*,\s*(?:`, _lit, `|([A-Za-z_][\w.]*)\s*\))`])

_py_in_re := concat("", [`(?:`, _lit, `|\b([A-Za-z_]\w*))\s+in\s+`, _recv])

_py_re_re := concat("", [`\bre\.(match|search)\(\s*[rbu]?["']([^"']*)["']\s*,\s*`, _recv])

_js_test_re := concat("", [`/((?:[^/\\\n]|\\.)+)/[gimsuy]*\.test\(\s*`, _recv])

_js_match_re := concat("", [_recv, `\s*\??\.match\(\s*/((?:[^/\\\n]|\\.)+)/`])

# The line still has the operator once plain string literals are blanked:
# the test is code, not text inside a string.
_skeleton_re := `\.(?:indexOf|includes|contains|search|startsWith|startswith|endsWith|endswith|test|match)\(|\bstrings\.(?:Contains|Index|HasPrefix|HasSuffix)\(|\bre\.(?:match|search)\(|\sin\s`

_mentions(s) if contains(s, "rigin")

_mentions(s) if contains(s, "RIGIN")

_mentions(s) if contains(s, "eferer")

_mentions(s) if contains(s, "eferrer")

_mentions(s) if contains(s, "EFERER")

# Some line names the origin and applies one of the tests to it.
_gate_re := `(?m)(?:rigin|RIGIN|eferr?er|EFERER)\b[^\n]{0,40}\.(?:indexOf|includes|contains|search|startsWith|startswith|endsWith|endswith|match)\(|(?:strings\.(?:Contains|Index|HasPrefix|HasSuffix)|re\.(?:match|search)|\.test)\([^\n]{0,80}(?:rigin|RIGIN|eferr?er|EFERER)|\sin\s+[^\n]{0,60}(?:rigin|RIGIN|eferr?er|EFERER)`

_code(line) := c if {
	a := regex.replace(line, `(^|[^fFrRbBu\w"'])"(?:[^"\\]|\\.)*"`, `$1""`)
	c := regex.replace(a, `(^|[^fFrRbBu\w"'])'(?:[^'\\]|\\.)*'`, `$1''`)
}

_domain(s) if regex.match(`[A-Za-z0-9-]\.[A-Za-z]`, s)

# literal argument
_weak(method, lit, "") if {
	method in {"indexOf", "includes", "contains", "search", "Contains", "Index", "in"}
	_domain(lit)
}

_weak(method, lit, "") if {
	method in {"startsWith", "startswith", "HasPrefix"}
	_domain(lit)
	not endswith(lit, "/")
}

_weak(method, lit, "") if {
	method in {"endsWith", "endswith", "HasSuffix"}
	_domain(lit)
	not startswith(lit, ".")
	not contains(lit, "//")
}

# variable argument: only a substring test is wrong whatever it holds
_weak(method, "", ident) if {
	ident != ""
	method in {"indexOf", "includes", "contains", "Contains", "Index", "in"}
	not ident in {"true", "false", "null", "None", "nil", "undefined"}
}

_unanchored(pat) if not regex.match(`(?:\$|\\Z|\\z)\)*$`, pat)

_bad(line) if {
	some m in regex.find_all_string_submatch_n(_method_re, line, -1)
	_weak(m[1], m[2], m[3])
	not _traffic_source(m[0], m[2])
}

# document.referrer.indexOf("google.com") classifies where a visitor came
# from (analytics), not who may act. A test against a full origin
# ("https://example.com") is a site-identity check and stays reported.
_traffic_source(match, lit) if {
	regex.match(`\bdocument\.referrer\b`, match)
	not contains(lit, "://")
}

# A substring test whose argument is built by concatenation
# (origin.includes('://' + host)): whatever it holds, a containing string passes.
_concat_re := concat("", [_recv, `\s*\??\.(?:indexOf|includes|contains)\(\s*(?:["'\x60][^"'\x60]*["'\x60]|[A-Za-z_$][\w$.]*)\s*\+`])

_bad(line) if regex.match(_concat_re, line)

_bad(line) if {
	some m in regex.find_all_string_submatch_n(_go_re, line, -1)
	_weak(m[1], m[2], m[3])
}

_bad(line) if {
	some m in regex.find_all_string_submatch_n(_py_in_re, line, -1)
	_weak("in", m[1], m[2])
}

_bad(line) if {
	some m in regex.find_all_string_submatch_n(_py_re_re, line, -1)
	_unanchored(m[2])
}

_bad(line) if {
	some m in regex.find_all_string_submatch_n(_js_test_re, line, -1)
	_unanchored(m[1])
}

_bad(line) if {
	some m in regex.find_all_string_submatch_n(_js_match_re, line, -1)
	_unanchored(m[1])
}

findings contains finding if {
	some path, content in input.file_contents
	_ext_ok(path)
	_mentions(content)
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	_mentions(line)
	not helpers.is_comment_line(line)
	regex.match(_skeleton_re, _code(line))
	_bad(line)
	finding := {
		"rule_id": metadata.id,
		"message": "The request origin is validated with a substring, prefix, unanchored-regex or dot-less suffix test, which a hostile origin such as https://example.com.evil.net or https://evilexample.com passes. Compare the parsed origin exactly against an allow-list, or match the host against '.example.com' with a leading dot",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The origin copied into a variable with another name in the 10 lines above
# (const source = req.get("Origin") || ""; sender := r.Header.Get("Origin")):
# the test on that variable is judged as a test on the origin.
_alias_assign_re := concat("", [`^\s*(?:(?:const|let|var|final|val|String|string)\s+)?([A-Za-z_]\w*)\s*(?::\s*string\s*)?(?::=|=)\s*`, _recv, `\s*(?:\|\||\?\?|\bor\b|;|$|\.(?:trim|toLowerCase|lower|strip)\(\))`])

_aliases(lines, i) := {m[1] |
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	_mentions(l)
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_alias_assign_re, l, 1)
	not regex.match(`(?i)origin|referr?er`, m[1])
}

findings contains finding if {
	some path, content in input.file_contents
	_ext_ok(path)
	_mentions(content)
	regex.match(concat("", [`(?m)`, _alias_assign_re]), content)
	lines := split(content, "\n")
	some i, line in lines
	not _mentions(line)
	regex.match(_skeleton_re, _code(line))
	not helpers.is_comment_line(line)
	some a in _aliases(lines, i)
	regex.match(concat("", [`\b`, a, `\b`]), line)
	_bad(regex.replace(line, concat("", [`\b`, a, `\b`]), "origin"))
	finding := {
		"rule_id": metadata.id,
		"message": "The request origin is validated with a substring, prefix, unanchored-regex or dot-less suffix test, which a hostile origin such as https://example.com.evil.net or https://evilexample.com passes. Compare the parsed origin exactly against an allow-list, or match the host against '.example.com' with a leading dot",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# gorilla/websocket CheckOrigin that accepts every origin
_check_origin_true(lines, i) if regex.match(`CheckOrigin\s*(?::|=)\s*func\s*\([^)]*\)\s*bool\s*\{\s*return\s+true\s*\}`, lines[i])

_check_origin_true(lines, i) if {
	regex.match(`CheckOrigin\s*(?::|=)\s*func\s*\([^)]*\)\s*bool\s*\{\s*$`, lines[i])
	j := helpers.next_code_index(lines, i, 3)
	regex.match(`^\s*return\s+true\s*$`, lines[j])
	k := helpers.next_code_index(lines, j, 3)
	regex.match(`^\s*\}`, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "CheckOrigin")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "CheckOrigin")
	not helpers.is_comment_line(line)
	_check_origin_true(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The WebSocket upgrader's CheckOrigin accepts every origin, so any website can open an authenticated socket with the visitor's cookies (cross-site WebSocket hijacking). Compare the Origin header against an allow-list",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
