# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_437

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-437",
	"name": "Incomplete Model of Endpoint Features",
	"description": "A URL is vetted with a model of it that is simpler than the one the HTTP client or browser uses to act on it, so the check and the request disagree about which host is meant (https://trusted.example.com.evil.net, https://trusted.example.com@evil.net, https://evil.net/?trusted.example.com). Reported in JavaScript/TypeScript and Python, on the line that then requests or redirects to the unchanged string: a raw-string check of the URL variable against a literal host (startsWith/startswith with a scheme and host but no '/' after the host, or endsWith/endswith, includes, indexOf or Python 'in' with a host literal, or a regular-expression literal whose pattern ends at a host name tested with .test(), as in /^https:\\/\\/cdn\\.acme\\.com/.test(u)) followed within fifteen lines by fetch/axios/got/needle/superagent/http(s).get/request, res.redirect/ctx.redirect/reply.redirect (JS) or requests.*, httpx.*, session/client .get/.post, urlopen, redirect or HttpResponseRedirect (Python) of that same variable; and, in Node, a host/hostname/protocol/origin decision taken on the result of the legacy url.parse() (assigned to a variable, read inline as url.parse(u).hostname or destructured as const { hostname } = url.parse(u); a lenient, non-WHATWG parser that Node documents as prone to hostname spoofing) while the original string, not the parsed one, is requested within thirty lines. Not reported: a prefix check that ends at a path separator (startsWith('https://api.example.com/')), checks on the parsed URL object of new URL()/urlparse (hostname comparison on the parsed value), a raw check followed by new URL()/urlparse of the same variable before the request, checks whose result is not followed by a request of the same variable, scheme-only checks (startsWith('https://')), comments and string literals. HTTP request smuggling through a lenient parser is VNX-444.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-437/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [437],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["incomplete-model-endpoint-features", "url-parsing", "ssrf", "open-redirect", "cwe-437"],
}

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".d.ts")
	not endswith(path, ".min.js")
}

_lang(path) := "py" if endswith(path, ".py")

_gate := `(?:startsWith|startswith|endsWith|endswith|includes|indexOf)\s*\(\s*['"]|['"]\s+(?:not\s+)?in\s+[A-Za-z_]|url\.parse\s*\(|/[gimsuy]*\.test\s*\(`

_var := `([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`

# A host literal: a dotted name, optionally with a scheme.
_host := `(?:(?:https?:)?//|\.)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}`

_urlish_name := `(?i)(?:url|uri|href|link|host|origin|redirect|next|target|dest|callback|return|webhook|endpoint|location|src|source|image|img|avatar|feed|site|domain|upstream|remote)`

# ── raw-string checks of a URL against a host literal ────────────────────


# [variable, literal] pairs checked on a line.
_checks(line) := ((_prefix_checks(line) | _suffix_checks(line)) | _in_checks(line)) | _regex_checks(line)

# A regular-expression literal tested against the URL whose pattern ends at a
# host name (no \/, $ or (\/|$) after it): /^https:\/\/cdn\.acme\.com/.test(u)
# accepts https://cdn.acme.com.evil.example.
_regex_checks(line) := {[m[2], h] |
	contains(line, ".test")
	some m in regex.find_all_string_submatch_n(concat("", [`(?:^|[(!=&|,:?\s])/((?:[^/\\\n]|\\.)+)/[gimsuy]*\.test\(\s*`, _var, `\s*\)`]), line, -1)
	hs := regex.find_all_string_submatch_n(`([A-Za-z0-9-]+(?:\\?\.[A-Za-z0-9-]+)*\\?\.[A-Za-z]{2,24})$`, m[1], 1)
	count(hs) > 0
	h := replace(hs[0][1], `\.`, ".")
	contains(h, ".")
	_urlish(m[2], concat("", ["//", h]))
}

_prefix_checks(line) := {[m[1], m[3]] |
	some m in regex.find_all_string_submatch_n(concat("", [_var, `\s*\.\s*(startsWith|startswith)\s*\(\s*['"]((?:https?:)?//[^/'"\s]+)['"]`]), line, -1)
	regex.match(concat("", [`^`, _host, `$`]), m[3])
}

_suffix_checks(line) := {[m[1], m[3]] |
	some m in regex.find_all_string_submatch_n(concat("", [_var, `\s*\.\s*(endsWith|endswith|includes|indexOf)\s*\(\s*['"](`, _host, `/?)['"]`]), line, -1)
	_urlish(m[1], m[3])
}

_in_checks(line) := {[m[2], m[1]] |
	some m in regex.find_all_string_submatch_n(concat("", [`['"](`, _host, `/?)['"]\s+(?:not\s+)?in\s+`, _var, `\b`]), line, -1)
	_urlish(m[2], m[1])
}

_urlish(_, lit) if contains(lit, "//")

_urlish(v, _) if regex.match(_urlish_name, v)

_sink_res(lang, v) := {re |
	some t in _sink_templates[lang]
	re := concat("", [t[0], _quote(v), t[1]])
}

_sink_templates := {
	"js": [
		[`(?:^|[^\w$.])(?:fetch|axios(?:\s*\.\s*(?:get|post|put|patch|delete|head|request))?|got(?:\s*\.\s*\w+)?|needle(?:\s*\.\s*\w+)?|superagent\s*\.\s*\w+|https?\s*\.\s*(?:get|request)|request(?:\s*\.\s*(?:get|post|put|patch|del))?|(?:res|ctx|reply|response)\s*\.\s*redirect|location\s*\.\s*(?:assign|replace))\s*\(\s*(?:\d{3}\s*,\s*)?`, `\s*[,)]`],
		[`(?:^|[^\w$.])(?:window\.|document\.)?location(?:\.href)?\s*=\s*`, `\s*;?\s*$`],
	],
	"py": [
		[`(?:^|[^\w.])(?:(?:requests|httpx|session|client|http|s)\s*\.\s*(?:get|post|put|patch|delete|head|options|stream)|(?:urllib\.request\.)?urlopen|redirect|HttpResponseRedirect|RedirectResponse)\s*\(\s*(?:url\s*=\s*)?`, `\s*[,)]`],
		[`\brequests\s*\.\s*request\s*\(\s*['"]\w*['"]\s*,\s*`, `\s*[,)]`],
	],
}

_quote(v) := regex.replace(v, `([.$])`, `\$1`)

_sink_lines(lang, lines, j, v, span) := {i |
	res := _sink_res(lang, v)
	some i in numbers.range(j, min([count(lines) - 1, j + span]))
	line := lines[i]
	contains(line, v)
	not helpers.is_comment_line(line)
	stripped := _strip_strings(line)
	some re in res
	regex.match(re, stripped)
}

# String literals blanked (keeping their quotes) so a request written inside
# a message is not a request.
_strip_strings(s) := regex.replace(s, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, `""`)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some j, line in lines
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	some c in _checks(line)
	some i in _sink_lines(lang, lines, j, c[0], 15)
	_gated(lines, j, i, line, c[0])
	not _reparsed(lines, j, i, c[0])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is checked as a raw string against '%s' (line %d) and then requested or redirected to unchanged: the client parses userinfo, subdomains and paths that the string check ignores, so https://%s.evil.example or https://%s@evil.example passes. Parse it (new URL()/urlparse) and compare the hostname exactly, or end the prefix with '/'", [c[0], c[1], j + 1, _bare(c[1]), _bare(c[1])]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}

# The request depends on the check: a negated check (if not ...: abort) guards
# whatever follows it; a positive one guards only its own line or block.
_negated(line, v) if regex.match(concat("", [`(?:\bnot\s+|!\s*\(?\s*)`, _quote(v), `\s*\.`]), line)

_negated(line, v) if regex.match(concat("", [`\bnot\s+in\s+`, _quote(v), `\b`]), line)

_negated(line, v) if regex.match(concat("", [`!\s*/(?:[^/\\\n]|\\.)+/[gimsuy]*\.test\(\s*`, _quote(v), `\s*\)`]), line)

_negated(line, v) if regex.match(concat("", [_quote(v), `\s*\.\s*indexOf\s*\([^)]*\)\s*(?:===?\s*-1|<\s*0)`]), line)

_indent(line) := count(line) - count(trim_left(line, " \t"))

_gated(_, j, i, _, _) if i == j

# The URL is parsed again and its hostname compared before the request.
_reparsed(lines, j, i, v) if {
	re := concat("", [`(?:new\s+URL|urlparse|urlsplit)\s*\(\s*`, _quote(v), `\s*[,)]`])
	some k in numbers.range(j + 1, i)
	regex.match(re, lines[k])
}

_gated(_, j, i, line, v) if {
	i > j
	_negated(line, v)
}

_gated(lines, j, i, line, v) if {
	i > j
	not _negated(line, v)
	base := _indent(line)
	every k in numbers.range(j + 1, i) {
		_inside(lines[k], base)
	}
}

_inside(l, _) if trim_space(l) == ""

_inside(l, base) if _indent(l) > base

_bare(lit) := regex.replace(lit, `^(?:https?:)?//|/$`, "")

# ── Node legacy url.parse() vetting, raw string requested ────────────────

_legacy_parse_re := concat("", [`^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:url|require\(\s*['"](?:node:)?url['"]\s*\))\s*\.\s*parse\s*\(\s*`, _var, `\s*[,)]`])

_legacy_checked(lines, j, i, x) if {
	re := concat("", [`\b`, x, `\s*\.\s*(?:hostname|host|protocol|origin)\b`])
	some k in numbers.range(j + 1, i)
	not helpers.is_comment_line(lines[k])
	regex.match(re, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "js"
	contains(content, ".parse")
	regex.match(`(?m)\burl\s*\.\s*parse\s*\(|require\(\s*['"](?:node:)?url['"]\s*\)\s*\.\s*parse`, content)
	lines := split(content, "\n")
	some j, line in lines
	contains(line, "parse")
	m := regex.find_all_string_submatch_n(_legacy_parse_re, line, 1)
	count(m) > 0
	x := m[0][1]
	raw := m[0][2]
	some i in _sink_lines("js", lines, j + 1, raw, 30)
	_legacy_checked(lines, j, i, x)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("The host of '%s' is vetted on the legacy url.parse() result '%s' (line %d), but the original string is what gets requested: url.parse() is lenient and disagrees with the WHATWG parser the client uses, so the host checked is not the host contacted. Parse once with new URL() and request the parsed URL", [raw, x, j + 1]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}

# The legacy parser's host fields read inline (url.parse(u).hostname) or
# destructured (const { hostname } = url.parse(u)), the raw string requested.
_legacy_src := `(?:\burl|require\(\s*['"](?:node:)?url['"]\s*\))\s*\.\s*parse\s*\(\s*`

_legacy_inline_re := concat("", [_legacy_src, _var, `\s*\)\s*\.\s*(?:hostname|host|protocol|origin)\b`])

_legacy_destructure_re := concat("", [`^\s*(?:const|let|var)\s*\{[^}]*\b(?:hostname|host|origin|protocol)\b[^}]*\}\s*=\s*`, _legacy_src, _var, `\s*[,)]`])

_legacy_inline_raw(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(_legacy_inline_re, line, 1)
	count(m) > 0
}

_legacy_inline_raw(line) := m[0][1] if {
	not regex.match(_legacy_inline_re, line)
	m := regex.find_all_string_submatch_n(_legacy_destructure_re, line, 1)
	count(m) > 0
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "js"
	contains(content, ".parse")
	regex.match(`(?m)\burl\s*\.\s*parse\s*\(|require\(\s*['"](?:node:)?url['"]\s*\)\s*\.\s*parse`, content)
	lines := split(content, "\n")
	some j, line in lines
	contains(line, "parse")
	not helpers.is_comment_line(line)
	raw := _legacy_inline_raw(line)
	some i in _sink_lines("js", lines, j + 1, raw, 30)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("The host of '%s' is read from the legacy url.parse() (line %d), but the original string is what gets requested: url.parse() is lenient and disagrees with the WHATWG parser the client uses, so the host checked is not the host contacted. Parse once with new URL() and request the parsed URL", [raw, j + 1]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}
