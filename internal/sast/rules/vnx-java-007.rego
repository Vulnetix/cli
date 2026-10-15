package vulnetix.rules.vnx_java_007

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-007",
	"name": "Java open redirect",
	"description": "Reports a redirect whose target comes from the request: HttpServletResponse.sendRedirect(), a Spring \"redirect:\" + value view name (returned or passed to ModelAndView), new RedirectView(), and a Location header (setHeader/addHeader(\"Location\" | HttpHeaders.LOCATION) or ResponseEntity .location(URI.create(...))) whose argument reads getParameter/getHeader/getQueryString/getCookies, is a @RequestParam/@PathVariable/@RequestHeader/@CookieValue parameter, or is a variable assigned from one (directly or through one intermediate assignment such as URLDecoder.decode) within the 40 lines above. Attackers use it to send users to phishing pages from a trusted domain. Not reported: a target that starts with a fixed local path (\"/account?next=\" + v) or fixed absolute URL, a value looked up in a map of allowed destinations (DESTINATIONS.get(id)), a value checked by an if guard (startsWith, matches, an allowlist contains/isAllowed/isSafe/isValid, getHost comparison) before the redirect, on the value itself or on a value parsed from it (URI uri = URI.create(v)), values from configuration, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-007/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [601],
	"capec": ["CAPEC-194"],
	"attack_technique": ["T1566"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["open-redirect", "web", "phishing"],
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

_lookup(r, w) if regex.match(concat("", [`\b\w+\s*\.\s*(?:get|getOrDefault)\s*\(\s*`, w, `\b`]), r)

# v holds a request value, directly or through one intermediate assignment.
_req(lines, i, v) if _src_tainted(lines, i, v)

_req(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	r := _rhs(lines, j, v)
	some w in _idents(r)
	w != v
	_src_tainted(lines, j, w)
	not _lookup(r, w)
}

_guard_re := `(?i)startsWith|matches\s*\(|contains\s*\(|isAllowed|isSafe|isValid|allow|whitelist|trusted|validate|getHost\s*\(|equals\s*\(`

_guarded(lines, i, v) if _guard_on(lines, _win(i), i, v)

# A guard on a value parsed from v (URI uri = URI.create(v); if (!ok(uri.getHost())) ...).
_guarded(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	m := regex.find_all_string_submatch_n(concat("", [`(\w+)\s*=\s*[^=;]*\b`, v, `\b`]), _strip(lines[j]), 1)
	count(m) > 0
	w := m[0][1]
	w != v
	_guard_on(lines, j + 1, i, w)
}

_guard_on(lines, lo, i, v) if {
	some j in numbers.range(lo, i - 1)
	contains(lines[j], v)
	regex.match(`^\s*(?:\}\s*else\s+)?if\s*\(|^\s*(?:return\s+)?\w*(?:valid|allow|safe)\w*\s*\(`, lines[j])
	regex.match(concat("", [`\b`, v, `\b`]), lines[j])
	regex.match(_guard_re, lines[j])
}

# A fixed local path or a fixed absolute URL in front of the value.
_fixed_prefix(raw) if regex.match(`^\s*"(?:redirect:)?(?:/[^/\\"]|https?://[^/"]+/)`, raw)

_redirect_bad(lines, i, a) if regex.match(_src_direct, a)

_redirect_bad(lines, i, a) if {
	some v in _idents(a)
	_req(lines, i, v)
	not _guarded(lines, i, v)
}

_sinks := [
	`\.sendRedirect\s*\(`,
	`new\s+RedirectView\s*\(`,
	`\.(?:setHeader|addHeader|header)\s*\(\s*(?:"Location"|HttpHeaders\.LOCATION)\s*,`,
	`\.location\s*\(\s*(?:URI\.create\s*\(|new\s+URI\s*\()`,
	`"redirect:"\s*\+`,
]

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`sendRedirect|RedirectView|"redirect:"|"Location"|LOCATION|\.location\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`sendRedirect|RedirectView|"redirect:"|"Location"|LOCATION|\.location\s*\(`, line)
	not helpers.is_comment_line(line)
	some re in _sinks
	regex.match(re, line)
	raw := _after(_joined(lines, i, 3, false), re)
	not _fixed_prefix(raw)
	a := _strip(raw)
	_redirect_bad(lines, i, a)
	finding := {
		"rule_id": metadata.id,
		"message": "Redirect target is taken from the request; redirect only to relative paths or to destinations checked against an allowlist",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
