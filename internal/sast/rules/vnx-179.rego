# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_179

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-179",
	"name": "Incorrect Behavior Order: Early Validation",
	"description": "A value is checked for a dangerous sequence (\"..\", \"../\", \"/\", \"\\\\\", \"<\", \"<script\", a quote) in a condition, and then decoded or canonicalised within the next ten lines: URLDecoder.decode, urllib unquote/unquote_plus, decodeURI/decodeURIComponent, url.PathUnescape/QueryUnescape, urldecode/rawurldecode, html.unescape/html_entity_decode, Normalizer.normalize/unicodedata.normalize. A check on the raw query string, request URI or URL (Java getQueryString/getRequestURI, Python request.query_string/full_path, Express req.originalUrl/req.url, Go r.URL.RawQuery/RawPath, PHP $_SERVER['QUERY_STRING'/'REQUEST_URI']), directly or through a variable assigned from it, followed within ten lines by a decoded parameter read (getParameter, request.args, req.query/params, URL.Query().Get, FormValue, $_GET/$_REQUEST) is reported too. The encoded form (%2e%2e%2f) passes the check and becomes the sequence it rejected. Supported checks: contains/includes/indexOf/startsWith/matches, Python 'in', strings.Contains/HasPrefix/Index, strpos/stripos/str_contains/strstr, and a regular expression for '..' or '<script' (/\\.\\.\\//.test(x), re.search/re.match). Not reported: a check that also rejects '%', decoding before the check, a check on a different variable, a decoded value that is checked again within six lines, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-179/",
	"languages": ["java", "python", "node", "go", "php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [179],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["validation", "ordering", "canonicalization", "cwe-179"],
}

_exts := {"py", "js", "jsx", "mjs", "cjs", "ts", "tsx", "java", "go", "php"}

# Files that can match, computed once for both finding rules.
_cands[path] := content if {
	some path, content in input.file_contents
	parts := split(path, ".")
	_exts[parts[count(parts) - 1]]
	not contains(path, ".min.")
	_has_decode(content)
	_tok_hint(content)
}

_lit := `"[^"\n]*"|'[^'\n]*'`

_decode := `(?:URLDecoder\.decode|\bunquote(?:_plus)?|\bdecodeURI(?:Component)?|\burl\.(?:Path|Query)Unescape|\b(?:raw)?urldecode|\bhtml\.unescape|\bhtml_entity_decode|\bNormalizer\.normalize|\bunicodedata\.normalize)`

# The raw (still percent-encoded) request line, query string or path.
_raw_src := `getQueryString\(\)|getRequestURI\(\)|request\.query_string|request\.full_path|\breq\.originalUrl\b|\breq\.url\b|\br\.URL\.Raw(?:Query|Path)\b|\$_SERVER\[\s*['"](?:REQUEST_URI|QUERY_STRING)['"]\s*\]`

# A parameter read that the framework has already percent-decoded.
_param_read := `\.getParameter\s*\(|\brequest\.args\.get\s*\(|\brequest\.args\[|\breq\.(?:query|params)\b|\.Query\(\)\.Get\s*\(|\.FormValue\s*\(|\$_(?:GET|REQUEST)\s*\[`

# The raw value itself is the checked operand.
_raw_check := concat("", [
	`(?:`, _raw_src, `)\s*\.(?:contains|includes|indexOf|startsWith)\s*\(\s*`, _tok_lit_c,
	`|\b(?:strings\.(?:Contains|HasPrefix|Index)|strpos|stripos|str_contains|strstr)\s*\(\s*(?:`, _raw_src, `)\s*,\s*`, _tok_lit_c,
])

_tok_lit_c := `["'](?:\.\.(?:/|\\\\?)?|/|\\\\?|<(?:script>?)?)["']`

# A regular-expression test for "..", "../" or "<script" on a variable.
_re_test := [
	`/((?:[^/\n]|\\/)+)/[a-z]*\.test\s*\(\s*([A-Za-z_$][\w$]*)\s*\)`,
	`\bre\.(?:search|match)\s*\(\s*r?["']([^"'\n]+)["']\s*,\s*([A-Za-z_]\w*)\s*[,)]`,
]

_re_tok(p) := ".." if contains(p, `\.\.`)

_re_tok(p) := "<script" if {
	not contains(p, `\.\.`)
	contains(p, "<script")
}

# The check also rejects '%', so the encoded form cannot pass it.
_rejects_percent(line) if regex.match(`["'](?:%|%25|%2[eEfF])["']`, line)

# var, literal
_fwd := [
	concat("", [`(\$?[A-Za-z_]\w*)\.(?:contains|includes|indexOf|startsWith|matches)\s*\(\s*(`, _lit, `)`]),
	concat("", [`\bstrings\.(?:Contains|HasPrefix|Index)\s*\(\s*([A-Za-z_]\w*)\s*,\s*(`, _lit, `)`]),
	concat("", [`\b(?:strpos|stripos|str_contains|strstr)\s*\(\s*(\$\w+)\s*,\s*(`, _lit, `)`]),
]

_py_in := concat("", [`(`, _lit, `)\s+(?:not\s+)?in\s+([A-Za-z_]\w*)`])

_tok_lit := `["'](?:\.\.(?:/|\\\\?)?|/|\\\\?|<(?:script>?)?|'|")["']`

_check_pre := concat("", [`(?:contains|includes|indexOf|startsWith|matches|Contains|HasPrefix|Index|strpos|stripos|str_contains|strstr)\s*\([^()\n]{0,40}`, _tok_lit, `|`, _tok_lit, `\s+(?:not\s+)?in\s|\.test\s*\(|\bre\.(?:search|match)\s*\(`])

_decode_hint(c) if contains(c, "URLDecoder.decode")

_decode_hint(c) if contains(c, "decodeURI")

_decode_hint(c) if contains(c, "unquote")

_decode_hint(c) if contains(c, "Unescape(")

_decode_hint(c) if contains(c, "urldecode(")

_decode_hint(c) if contains(c, "html.unescape(")

_decode_hint(c) if contains(c, "html_entity_decode(")

_decode_hint(c) if contains(c, "normalize(")

_has_decode(c) if _decode_hint(c)

_has_decode(c) if _raw_hint(c)

# Cheap per-line prefilter: a quoted token or a regex test is on the line.
_tok_hint(l) if contains(l, `"..`)

_tok_hint(l) if contains(l, `'..`)

_tok_hint(l) if contains(l, `"/"`)

_tok_hint(l) if contains(l, `'/'`)

_tok_hint(l) if contains(l, `"<`)

_tok_hint(l) if contains(l, `'<`)

_tok_hint(l) if contains(l, `"\\`)

_tok_hint(l) if contains(l, `'\\`)

_tok_hint(l) if contains(l, `"'"`)

_tok_hint(l) if contains(l, `'"'`)

_tok_hint(l) if contains(l, ".test(")

_tok_hint(l) if contains(l, "re.search(")

_tok_hint(l) if contains(l, "re.match(")

_raw_hint(c) if contains(c, "getQueryString")

_raw_hint(c) if contains(c, "getRequestURI")

_raw_hint(c) if contains(c, "query_string")

_raw_hint(c) if contains(c, "full_path")

_raw_hint(c) if contains(c, "originalUrl")

_raw_hint(c) if contains(c, "req.url")

_raw_hint(c) if contains(c, "URL.Raw")

_raw_hint(c) if contains(c, "REQUEST_URI")

_raw_hint(c) if contains(c, "QUERY_STRING")

_tokens := {"..", "../", "..\\", "..\\\\", "/", "\\", "\\\\", "<", "<script", "<script>", "'", "\""}

_tok(l) := substring(l, 1, count(l) - 2)

_checks(line) := {[v, t] |
	some re in _fwd
	some m in regex.find_all_string_submatch_n(re, line, -1)
	v := m[1]
	t := _tok(m[2])
} | {[v, t] |
	some m in regex.find_all_string_submatch_n(_py_in, line, -1)
	v := m[2]
	t := _tok(m[1])
} | {[v, t] |
	some re in _re_test
	some m in regex.find_all_string_submatch_n(re, line, -1)
	v := m[2]
	t := _re_tok(m[1])
}

_esc(v) := replace(v, "$", `\$`)

_in_string(line, word) if {
	idx := indexof(line, word)
	idx >= 0
	pre := regex.replace(substring(line, 0, idx), `\\.`, "")
	count(regex.find_n(`"`, pre, -1)) % 2 == 1
}

_decoded_later(lines, i, v) if {
	_decode_hint(concat("\n", array.slice(lines, i + 1, i + 11)))
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 10]))
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(concat("", [_decode, `\s*\(\s*(?:(?:"[^"]*"|'[^']*')\s*,\s*)?`, _esc(v), `\b`]), l)
	not _rechecked(lines, j)
}

# The decoded result is validated again shortly after.
_rechecked(lines, j) if {
	w := helpers.assigned_first(lines[j])
	some k in numbers.range(j + 1, min([count(lines) - 1, j + 6]))
	some c in _checks(lines[k])
	c[0] == w
}

_raw_then_param(lines, i, v) if {
	_raw_hint(concat("\n", array.slice(lines, max([0, i - 6]), i + 1)))
	vs := helpers.tainted_vars(lines, i, 6, _raw_src)
	vs[trim_prefix(v, "$")]
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 10]))
	regex.match(_param_read, lines[j])
}

findings contains finding if {
	some path, content in _cands
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "if")
	count(line) < 1000
	_tok_hint(line)
	regex.match(_check_pre, line)
	regex.match(`\b(?:if|elif|unless)\b`, line)
	not helpers.is_comment_line(line)
	not _in_string(line, "if")
	not _rejects_percent(line)
	some c in _checks(line)
	_tokens[c[1]]
	_late(lines, i, c[0])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is checked for %q before it is decoded; the encoded form passes the check and decodes into it. Decode and canonicalise first, then validate", [c[0], c[1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The raw request line or query string is checked directly, then a decoded
# parameter is read.
findings contains finding if {
	some path, content in _cands
	_raw_hint(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "if")
	count(line) < 1000
	_raw_hint(line)
	regex.match(_raw_check, line)
	regex.match(`\b(?:if|elif|unless)\b`, line)
	not helpers.is_comment_line(line)
	not _in_string(line, "if")
	not _rejects_percent(line)
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 10]))
	regex.match(_param_read, lines[j])
	finding := {
		"rule_id": metadata.id,
		"message": "The raw, still-encoded request URL or query string is checked, then a decoded parameter is used; %2e%2e%2f passes the check and decodes into '../'. Validate the decoded value that is actually used",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_late(lines, i, v) if _decoded_later(lines, i, v)

_late(lines, i, v) if _raw_then_param(lines, i, v)
