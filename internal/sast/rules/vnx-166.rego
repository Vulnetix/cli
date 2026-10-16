# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_166

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-166",
	"name": "Improper Handling of Missing Special Element",
	"description": "Reports Python and JavaScript/TypeScript code that splits request data on a delimiter and assumes the delimiter was there: an index of 1 or more into the result of .split() or .rsplit() (request.headers.get('Authorization').split(' ')[1], req.headers.authorization.split(' ')[1]), Python tuple unpacking of a split (user, pw = decoded.split(':', 1), which raises ValueError when the ':' is missing), and parts = value.split(...) followed by parts[1] with no length check. The split value must be read from the request on the same line (Flask/Django/DRF request.headers/args/form/values/cookies/COOKIES/GET/POST/META/data/json, Express/Koa req/ctx headers/query/body/params/cookies, Lambda event headers/queryStringParameters/body), or assigned from it, directly or through one intermediate assignment, in the 8 lines above. A request without the delimiter then crashes the handler (IndexError/ValueError, a 500) or carries undefined forward as a token or value. Not reported: a membership or format check of the value in the 4 lines above (' ' in h, h.includes(' '), h.startswith('Bearer '), re.match), a len(parts)/parts.length check, code inside a try block, index [0] and .pop(), str.partition(), constants and non-request data, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-166/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [166],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["special-element", "parsing", "delimiter", "cwe-166"],
}

_py_src := `\b(?:self\.)?request\.(?:headers|args|form|values|cookies|COOKIES|GET|POST|META|data|json|query_params|get_json|path|full_path|url)\b|\bevent(?:\[\s*|\.get\(\s*)["'](?:headers|queryStringParameters|body|pathParameters|multiValueHeaders)["']`

_js_src := `\b(?:req|request)\.(?:headers|query|body|params|cookies|signedCookies|path|url|originalUrl|get\s*\(|header\s*\()|\bctx\.(?:request|headers|query|cookies|params|get\s*\()|\bevent\.(?:headers|queryStringParameters|body|pathParameters)\b`

_lang_of(path) := "py" if endswith(path, ".py")

_lang_of(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
	endswith(path, ext)
}

_src("py") := _py_src

_src("js") := _js_src

_split_idx := `\.r?split\([^()]*\)\s*\[\s*[1-9]\d*\s*\]`

_files := {path: [lang, split(content, "\n")] |
	some path, content in input.file_contents
	contains(content, "split(")
	lang := _lang_of(path)
	not endswith(path, ".min.js")
	regex.match(_src(lang), content)
}

# Tainted names: assigned from the request in the 8 lines above, or from a
# line that uses such a name.
_tainted(lines, i, src) := t1 | t2 if {
	t1 := {v |
		i > 0
		some j in numbers.range(max([0, i - 8]), i - 1)
		not helpers.is_comment_line(lines[j])
		regex.match(src, lines[j])
		v := _assigned(lines[j])
	}
	t2 := {v |
		some k in numbers.range(max([0, i - 8]), i - 1)
		not helpers.is_comment_line(lines[k])
		some t in t1
		regex.match(concat("", [`=.*\b`, t, `\b`]), lines[k])
		v := _assigned(lines[k])
		v != t
	}
}

# The assigned name, including a TypeScript `const x: T = ...`.
_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s+([A-Za-z_]\w*)\s*:\s*[^=]+=[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
} else := helpers.assigned_first(line)

# The match is outside a string literal: an even number of each quote before it.
_outside_string(line, frag) if {
	off := indexof(line, frag)
	off >= 0
	pre := substring(line, 0, off)
	count(indexof_n(pre, `"`)) % 2 == 0
	count(indexof_n(pre, "'")) % 2 == 0
	count(indexof_n(pre, "`")) % 2 == 0
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# A membership/format check or a try block just above the sink.
_handled(lines, i) if {
	w := helpers.code_window(lines, i, 4, 0)
	regex.match(`['"][^'"\n]*['"]\s+(not\s+)?in\s+\w|\.(includes|indexOf|startsWith|startswith|endsWith|endswith|find|index|count)\s*\(|\bre\.(match|search|fullmatch)\s*\(|\.test\s*\(|\.match\s*\(`, w)
}

_handled(lines, i) if {
	some k in numbers.range(max([0, i - 8]), i - 1)
	regex.match(`^\s*try\s*(:|\{)`, lines[k])
	_indent(lines[k]) < _indent(lines[i])
}

_msg := "Request data is split on a delimiter and the result is indexed or unpacked as if the delimiter were always present: a request without it raises IndexError/ValueError (a 500) or passes undefined on; check that the delimiter is present (or the number of parts) first, or use partition()"

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# (1) <request expr>.split(d)[N] on one line
findings contains f if {
	some path, entry in _files
	[lang, lines] := entry
	some i, line in lines
	contains(line, "split(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`(`, _src(lang), `)[^;\n]*?`, _split_idx]), line, 1)[0]
	_outside_string(line, m[0])
	not _handled(lines, i)
	f := _finding(path, i, line)
}

# (2) <tainted name>.split(d)[N]
findings contains f if {
	some path, entry in _files
	[lang, lines] := entry
	some i, line in lines
	contains(line, "split(")
	not helpers.is_comment_line(line)
	not regex.match(_src(lang), line)
	some m in regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)`, _split_idx]), line, -1)
	m[1] in _tainted(lines, i, _src(lang))
	_outside_string(line, m[0])
	not _handled(lines, i)
	f := _finding(path, i, line)
}

# (3) Python: a, b = <request or tainted>.split(d)
findings contains f if {
	some path, entry in _files
	[lang, lines] := entry
	lang == "py"
	some i, line in lines
	contains(line, "split(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^\s*[A-Za-z_]\w*\s*(?:,\s*[A-Za-z_]\w*\s*)+=\s*(.+?)\.r?split\([^()]*\)\s*$`, line, 1)[0]
	_unpack_source(lines, i, m[1])
	not _handled(lines, i)
	f := _finding(path, i, line)
}

_unpack_source(_, _, expr) if regex.match(_py_src, expr)

_unpack_source(lines, i, expr) if {
	regex.match(`^[A-Za-z_]\w*$`, expr)
	expr in _tainted(lines, i, _py_src)
}

# (4) parts = <request or tainted>.split(d); parts[N] with no length check
findings contains f if {
	some path, entry in _files
	[lang, lines] := entry
	some k, def in lines
	contains(def, "split(")
	not helpers.is_comment_line(def)
	m := regex.find_all_string_submatch_n(`^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_]\w*)(?:\s*:\s*[\w\[\]<>]+)?\s*=\s*(.+?)\.r?split\([^()]*\)\s*;?\s*$`, def, 1)[0]
	p := m[1]
	_split_source(lines, k, m[2], lang)
	some i in numbers.range(k + 1, min([count(lines) - 1, k + 6]))
	sink := lines[i]
	regex.match(concat("", [`\b`, p, `\s*\[\s*[1-9]\d*\s*\]`]), sink)
	not helpers.is_comment_line(sink)
	not _len_checked(lines, k + 1, i, p)
	not _handled(lines, i)
	f := _finding(path, i, sink)
}

_split_source(_, _, expr, lang) if regex.match(_src(lang), expr)

_split_source(lines, k, expr, lang) if {
	regex.match(`^[A-Za-z_]\w*$`, expr)
	expr in _tainted(lines, k, _src(lang))
}

_len_checked(lines, a, b, p) if {
	some j in numbers.range(a, b)
	regex.match(concat("", [`\blen\s*\(\s*`, p, `\s*\)|\b`, p, `\.(length|size)\b|\bif\s+(not\s+)?`, p, `\b|!\s*`, p, `\b`]), lines[j])
}
