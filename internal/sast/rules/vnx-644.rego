# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_644

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-644",
	"name": "HTTP response header set from request data without neutralisation",
	"description": "A response header value is taken from the request (query string, form, path parameter, body, cookie or another request header) and written back without encoding, so script syntax or CR/LF in the value reaches every component that reads raw headers (CWE-644; the CR/LF case is also CWE-113). Reported in Python: Flask/Werkzeug resp.headers[...] = v and headers.add()/set()/setdefault(), Django response[...] = v, and a headers={...} dict passed to Response/make_response/HttpResponse/JSONResponse; in JavaScript/TypeScript: Express/Fastify res.setHeader()/set()/header()/append()/setHeaders(), Node res.writeHead() header objects, and Koa ctx.set()/ctx.response.set(). A call broken right after its opening parenthesis is read with its next three lines. The value must contain the request expression itself (request.args/form/GET/META/headers..., req.query/params/body/headers/cookies/url, ctx.query/request) or a variable assigned from one up to 10 lines above, including object destructuring. Not reported: constant header values, values passed through an encoder or sanitiser (encodeURIComponent, content-disposition, parseInt/Number/int/str(int()), urllib quote, a .replace()/re.sub() that strips characters, escape, an allow-list membership test such as ALLOWED.includes(v) or v in ALLOWED), writes to the request's own headers, other .set() receivers (Map, settings), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-644/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [644],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["header-injection", "http-headers", "cwe-644"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_gate("py", c) if {
	contains(c, "request")
	regex.match(`headers|\b(?:response|resp|res|r)\[`, c)
}

_gate("js", c) if regex.match(`setHeader|writeHead|\.(?:set|header|append|setHeaders)\(`, c)

_source := {
	"py": `\brequest\.(?:args|form|values|headers|cookies|GET|POST|META|COOKIES|query_params|path_params|data|json|get_json\(|query)\b`,
	"js": `\breq(?:uest)?\.(?:query|params|body|headers|cookies|url|originalUrl|get\(|header\()|\bctx\.(?:query|params|request|headers|get\(|querystring)`,
}

_sanitiser := `encodeURI(?:Component)?\(|contentDisposition\(|parseInt\(|parseFloat\(|Number\(|\bint\(|\bfloat\(|\bquote(?:_plus)?\(|\.replace\(|re\.sub\(|\bescape\(|sanitiz|sanitis|urlencode\(|encodeRFC5987|\.isdigit\(\)|uuid|\.includes\(|\.has\(|\bin\s+(?:ALLOWED|[A-Z][A-Z0-9_]{2,}\b)`

# ── Sinks: the header-value text ─────────────────────────────────────────

# Each pattern captures the receiver (group 1, "" when there is none) and the
# header-value text (group 2).
_sink_res := {
	"py": [
		`\b(\w+)\.headers\[\s*['"][\w-]+['"]\s*\]\s*=\s*(.+)$`,
		`\b(\w+)\.headers\.(?:add|set|setdefault|add_header|__setitem__)\(\s*['"][\w-]+['"]\s*,\s*(.+)$`,
		`\b(response|resp|res|r)\[\s*['"][\w-]+['"]\s*\]\s*=\s*(.+)$`,
		`\b(Response|make_response|HttpResponse|JSONResponse|PlainTextResponse|HTMLResponse)\(.*\bheaders\s*=\s*(\{.+)$`,
	],
	"js": [
		`\b(res|response|reply|resp)\.(?:setHeader|set|header|append|setHeaders)\(\s*(?:['"\x60][\w-]+['"\x60]\s*,\s*)?(.+)$`,
		`()\.writeHead\(\s*\d+\s*,\s*(.+)$`,
		`\b(ctx)\.(?:response\.)?set\(\s*(?:['"\x60][\w-]+['"\x60]\s*,\s*)?(.+)$`,
	],
}

_sinks(line, lang) := {v |
	some re in _sink_res[lang]
	some m in regex.find_all_string_submatch_n(re, line, 1)
	not m[1] in {"request", "req", "self"}
	v := m[2]
}

# ── Taint ────────────────────────────────────────────────────────────────

# Names assigned from a request source (not through a sanitiser) above i.
_assigned(lines, i, lang) := {v |
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := lines[j]
	regex.match(_source[lang], prev)
	not regex.match(_sanitiser, prev)
	not helpers.is_comment_line(prev)
	some v in _lhs(prev)
}

_lhs(line) := {v | v := helpers.assigned_first(line)} | _destructured(line)

_destructured(line) := {n |
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)?\s*\{([^}]*)\}\s*=`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	p := trim_space(part)
	parts := split(p, ":")
	n := trim_space(parts[count(parts) - 1])
	regex.match(`^[A-Za-z_$][\w$]*$`, n)
}

_tainted(_, _, v, lang) if regex.match(_source[lang], v)

_tainted(lines, i, v, lang) if {
	some n in _assigned(lines, i, lang)
	regex.match(concat("", [`(?:^|[^\w.$])`, n, `\b`]), v)
}

# Text inside string literals that contain a space is prose, not code.
_strip_prose(line) := c if {
	lits := [l |
		some l in regex.find_all_string_submatch_n(`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, line, -1)
		regex.match(`\s`, l[0])
		regex.match(`headers|setHeader|\.set\(`, l[0])
	]
	c := strings.replace_n({l[0]: `""` | some l in lits}, line)
}

_line_gate("py", line) if contains(line, "headers")

_line_gate("py", line) if regex.match(`\b(?:response|resp|res|r)\[`, line)

_line_gate("js", line) if regex.match(`setHeader|writeHead|\.(?:set|header|append|setHeaders)\(`, line)

# The call text: the line itself, or, when the call breaks right after its
# opening parenthesis, the line joined with the next three.
_call_text(_, _, line) := line if not regex.match(`\(\s*$`, line)

_call_text(lines, i, line) := concat(" ", array.concat([line], [trim_space(l) | some l in array.slice(lines, i + 1, i + 4)])) if regex.match(`\(\s*$`, line)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	_line_gate(lang, line)
	not helpers.is_comment_line(line)
	some v in _sinks(_strip_prose(_call_text(lines, i, line)), lang)
	not regex.match(_sanitiser, v)
	_tainted(lines, i, v, lang)
	finding := {
		"rule_id": metadata.id,
		"message": "Response header value is taken from the request without encoding: script syntax or CR/LF in it reaches every component that reads raw headers. Validate it against an allow-list or encode it (encodeURIComponent, urllib.parse.quote, content-disposition)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
