package vulnetix.rules.vnx_java_008

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-008",
	"name": "Java server-side request forgery",
	"description": "Reports an outbound request whose URL or host comes from the request: new URL(), RestTemplate getForObject/getForEntity/postForObject/postForEntity/exchange/execute, WebClient.create()/baseUrl()/uri(), java.net.http HttpRequest.newBuilder()/uri(), Apache HttpClient new HttpGet/HttpPost/... and fluent Request.Get/Post, OkHttp Request.Builder url(), Jsoup.connect() and new Socket(host, ...) whose first argument reads getParameter/getHeader/getQueryString/getCookies, is a @RequestParam/@PathVariable/@RequestHeader/@RequestBody/@CookieValue parameter, or is a variable assigned from one through up to two intermediate assignments within the 40 lines above (URI.create(value) and concatenation included). The server can then be made to reach internal services, cloud metadata endpoints or arbitrary ports. Not reported: JdbcTemplate (or any *Jdbc*/*Sql* receiver) execute(), which runs SQL rather than a request (SQL built from the request there is reported by VNX-JAVA-003), a URL that starts with a fixed scheme and host (\"https://api.example.com/items/\" + id), a value checked by an if guard (getHost comparison, startsWith, matches, allowlist contains/isAllowed) before the call, URLs from configuration, a URL handed in as a plain method parameter (its callers decide), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-008/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [918],
	"capec": ["CAPEC-664"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["ssrf", "web", "cloud"],
}

# ── Shared expression helpers ────────────────────────────────────────────

# String and char literals emptied, so a quoted "+" or "exec(" is not code.
_strip(s) := regex.replace(regex.replace(s, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)'`, `''`)

_joined(lines, i, span, strip) := concat(" ", [t |
	some k in numbers.range(i, min([count(lines) - 1, i + span]))
	t := _maybe_strip(lines[k], strip)
])

_maybe_strip(l, true) := _strip(l)

_maybe_strip(l, false) := l

# The text after the call opened by `re` on line i, up to the first `;`,
# over up to four lines (a call broken across lines).
_after(text, re) := a if {
	m := regex.find_all_string_submatch_n(concat("", [re, `([^;]*)`]), text, 1)
	count(m) > 0
	a := m[0][count(m[0]) - 1]
}

_const_ident(id) if regex.match(`^(?:\w+\.)*[A-Z][A-Z0-9_]*$`, id)

_const_ident(id) if id in {"true", "false", "null"}

_nonconst_operand(")")

_nonconst_operand(id) if {
	id != ")"
	not _const_ident(id)
}

# A `+` with a non-literal, non-constant operand on either side.
_nonconst_concat(expr) if {
	s := regex.replace(expr, `\+\+|\+=`, " ")
	contains(s, "+")
	some m in regex.find_all_string_submatch_n(`\+\s*([A-Za-z_][\w.]*)|([A-Za-z_][\w.]*|\))\s*\+`, s, -1)
	_nonconst_operand(concat("", [m[1], m[2]]))
}

_formats(expr) if regex.match(`\b(?:String|MessageFormat)\.format\s*\([^)]*,\s*[A-Za-z_(]|\.formatted\s*\(\s*[A-Za-z_]|\.concat\s*\(\s*[A-Za-z_]`, expr)

_kw := {"new", "null", "true", "false", "this", "super", "return", "instanceof", "final"}

# Local names an expression reads (not fields after a dot, not calls).
_idents(expr) := {v |
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w."'])([a-z_]\w*)(\s*\()?`, expr, -1)
	m[2] == ""
	v := m[1]
	not v in _kw
}

_src_re := `\b(?:getParameter(?:Values|Map)?|getHeaders?|getQueryString|getCookies|getInputStream|getReader|getPathInfo|readLine|nextLine)\s*\(`

_param_re := `@(?:RequestParam|PathVariable|RequestHeader|RequestBody|CookieValue|QueryParam|PathParam|FormParam|HeaderParam|MatrixParam)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?[\w.]+(?:<[^>]*>)?(?:\[\])?\s+`

_win(i) := max([0, i - 40])

# The right-hand side of an assignment to v on line j (up to `;`).
_rhs(lines, j, v) := r if {
	pat := concat("", [`(?:^|[^\w.])`, v, `\s*(?:\[\s*\])?\s*\+?=\s*([^=;][^;]*|$)`])
	regex.match(pat, _strip(lines[j]))
	not helpers.is_comment_line(lines[j])
	r := _after(_joined(lines, j, 6, true), concat("", [`(?:^|[^\w.])`, v, `\s*(?:\[\s*\])?\s*\+?=`]))
}

# v holds a request value: assigned from a source, or an annotated parameter.
_src_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	regex.match(_src_re, _rhs(lines, j, v))
}

_src_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i)
	contains(lines[j], v)
	regex.match(concat("", [_param_re, v, `\b`]), _strip(lines[j]))
}

# v holds run-time built text or a request value.
_tainted(lines, i, v) if _src_tainted(lines, i, v)

_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	r := _rhs(lines, j, v)
	_dynamic(r)
}

_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	r := _rhs(lines, j, v)
	some w in _idents(r)
	w != v
	_src_tainted(lines, j, w)
}

# cmd += value: appending a non-constant builds the text at run time.
_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], "+=")
	contains(lines[j], v)
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, v, `\s*\+=\s*([^;]*)`]), _strip(lines[j]), 1)
	count(m) > 0
	_nonconst_concat(concat("", ["x + ", m[0][1]]))
}

_dynamic(e) if _nonconst_concat(e)

_dynamic(e) if _formats(e)

_dynamic(e) if regex.match(_src_re, e)

_bad(_, _, a) if _dynamic(a)

_bad(lines, i, a) if {
	some v in _idents(a)
	_tainted(lines, i, v)
}

# ── Rule-specific ────────────────────────────────────────────────────────

_src_direct := `\b(?:getParameter(?:Values|Map)?|getHeaders?|getQueryString|getCookies)\s*\(`

# One intermediate assignment: relay = decode(raw), raw from the request.
_req1(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	r := _rhs(lines, j, v)
	some w in _idents(r)
	w != v
	_src_tainted(lines, j, w)
}

_req(lines, i, v) if _src_tainted(lines, i, v)

_req(lines, i, v) if _req1(lines, i, v)

# Two intermediate assignments: jwt = decode(token); jku = jwt.claim(); new URL(jku...)
_req(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	r := _rhs(lines, j, v)
	some w in _idents(r)
	w != v
	_req1(lines, j, w)
}

_guard_re := `(?i)getHost\s*\(|startsWith|matches\s*\(|contains\s*\(|isAllowed|isSafe|isValid|allow|whitelist|trusted|validate|equals\w*\s*\(`

_guarded(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	regex.match(`^\s*(?:\}\s*else\s+)?if\s*\(|^\s*(?:return\s+)?\w*(?:valid|allow|safe)\w*\s*\(`, lines[j])
	regex.match(concat("", [`\b`, v, `\b`]), lines[j])
	regex.match(_guard_re, lines[j])
}

# A guard on a value parsed from v (URI uri = URI.create(v); if (!HOSTS.contains(uri.getHost())) throw ...).
_guarded(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	m := regex.find_all_string_submatch_n(concat("", [`(\w+)\s*=\s*[^=;]*\b`, v, `\b`]), _strip(lines[j]), 1)
	count(m) > 0
	w := m[0][1]
	w != v
	some k in helpers.span(j + 1, i - 1)
	contains(lines[k], w)
	regex.match(`^\s*(?:\}\s*else\s+)?if\s*\(|^\s*(?:return\s+)?\w*(?:valid|allow|safe)\w*\s*\(`, lines[k])
	regex.match(concat("", [`\b`, w, `\b`]), lines[k])
	regex.match(_guard_re, lines[k])
}

# A fixed scheme and host in front of the value.
_fixed_prefix(raw) if regex.match(`^\s*(?:(?:URI\.create|new\s+URI|new\s+URL)\s*\(\s*)?"https?://[^/"]+/`, raw)

_ssrf_bad(_, _, a) if regex.match(_src_direct, a)

_ssrf_bad(lines, i, a) if {
	some v in _idents(a)
	_req(lines, i, v)
	not _guarded(lines, i, v)
}

_sinks := [
	`new\s+(?:java\.net\.)?URL\s*\(`,
	`(?i:\b\w*(?:rest|template)\w*)\s*\.\s*(?:getForObject|getForEntity|postForObject|postForEntity|postForLocation|exchange|execute|patchForObject)\s*\(`,
	`\bWebClient\s*\.\s*create\s*\(`,
	`\.\s*baseUrl\s*\(`,
	`\.\s*uri\s*\(`,
	`\bHttpRequest\s*\.\s*newBuilder\s*\(`,
	`new\s+Http(?:Get|Post|Put|Delete|Head|Patch|Options)\s*\(`,
	`\bRequest\s*\.\s*(?:Get|Post|Put|Delete|Head|Patch)\s*\(`,
	`\bJsoup\s*\.\s*connect\s*\(`,
	`new\s+(?:java\.net\.)?Socket\s*\(`,
	`Request\.Builder\s*\(\s*\)\s*\.\s*url\s*\(`,
]

_gate := `new\s+(?:java\.net\.)?URL\s*\(|ForObject|ForEntity|ForLocation|exchange\s*\(|\.execute\s*\(|WebClient|baseUrl|\.uri\s*\(|newBuilder|new\s+Http|Request\s*\.\s*[A-Z]|Jsoup|Socket\s*\(|Request\.Builder`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(_gate, content)
	regex.match(`getParameter|getHeader|getQueryString|getCookies|@RequestParam|@PathVariable|@RequestHeader|@RequestBody|@CookieValue|@QueryParam|@PathParam|@FormParam`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	some re in _sinks
	regex.match(re, line)
	# JdbcTemplate.execute(sql) is a database call, not an HTTP one: SQL
	# built from the request there is VNX-JAVA-003's to report.
	not regex.match(`(?i)\b\w*(?:jdbc|sql)\w*\s*\.\s*(?:execute|exchange)\s*\(`, line)
	raw := _after(_joined(lines, i, 3, false), re)
	not _fixed_prefix(raw)
	a := _first_arg(_strip(raw))
	_ssrf_bad(lines, i, a)
	finding := {
		"rule_id": metadata.id,
		"message": "Outbound request URL or host is taken from the request; resolve it against an allowlist of permitted hosts (and block internal and metadata addresses) before connecting",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_first_arg(a) := f if {
	parts := regex.find_all_string_submatch_n(`^((?:[^,()]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*)`, a, 1)
	count(parts) > 0
	f := parts[0][1]
}
