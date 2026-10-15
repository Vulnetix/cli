# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_115

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-115",
	"name": "Misinterpretation of Input",
	"description": "A request value is converted or compared in a way that reads it as something other than what the requester sent, so the program acts on a different value than the one it checked or meant (CWE-115). Reported: JavaScript/TypeScript parseInt/Number.parseInt of request data with no radix argument (\"0x10\" is read as 16); JavaScript Boolean(x) or !!x and Python bool(x) of a string request value (req.query/params/headers/cookies; request.args/form/values/GET/POST/cookies/headers .get() or [...]), which is true for \"false\" and \"0\"; PHP loose comparison (== or !=) of request data with a token, password, hash, secret, signature, key, code or PIN (\"0e...\" magic hashes and type juggling make unequal values equal), strcmp() of request data tested with == 0 or ! (an array argument returns NULL, which equals 0), and in_array() of request data without the strict third argument. Request data is used inline or through a variable assigned from it in the 25 lines above. Not reported: parseInt with a radix, Number(), explicit comparisons such as === 'true' or .lower() == 'true', bool() of a whole collection (bool(request.args)), JSON body values in the Boolean checks (already typed), ===, hash_equals and password_verify, in_array(..., true), loose comparison with an ordinary string, and code in comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-115/",
	"languages": ["node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [115],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["misinterpretation", "type-juggling", "input", "cwe-115"],
}

_is_js(path) if {
	some ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

# Any request value (parseInt), and request values that are always strings
# (Boolean / bool checks).
_js_src := `\b(?:req|request)\.(?:query|body|params|headers|cookies)\b|\bctx\.(?:query|params|request\.body)\b`

_js_str_src := `\b(?:req|request)\.(?:query|params|headers|cookies)\b|\bctx\.(?:query|params)\b`

_py_str_src := `\brequest\.(?:args|form|values|GET|POST|cookies|headers|COOKIES|META)\s*(?:\.get\s*\(|\[)`

_php_src := `\$_(?:GET|POST|REQUEST|COOKIE)\b|\bfilter_input\s*\(|\$request->(?:input|get|query|post)\s*\(`

_assign_re := `^\s*(?:(?:var|let|const)\s+)?\$?([A-Za-z_]\w*)\s*(?::\s*[\w<>\[\]\|\. ]+?\s*)?=[^=>]`

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
}

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{\s*([A-Za-z_]\w*)`, line, 1)
	count(m) > 0
	v := m[0][1]
}

# Variables assigned straight from a source in the 25 lines above, keeping
# only assignments that do not already convert the value.
_names(lines, i, src) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	regex.match(src, l)
	not helpers.is_comment_line(l)
	not regex.match(`(?i)\b(?:parseInt|Number|parseFloat|int|float|bool|Boolean|intval|lower|toLowerCase)\s*\(|===|==\s*['"]`, l)
	v := _assigned(l)
}

_carries(lines, i, src, arg, lang) if regex.match(src, arg)

_carries(lines, i, src, arg, lang) if {
	not regex.match(src, arg)
	some n in _names(lines, i, src)
	regex.match(_use(lang, n), arg)
}

_use("php", n) := concat("", [`\$`, n, `\b`])

_use(lang, n) := concat("", [`^\s*`, n, `\b`]) if lang != "php"

_depth(s) := ((strings.count(s, "(") + strings.count(s, "[")) + strings.count(s, "{")) - ((strings.count(s, ")") + strings.count(s, "]")) + strings.count(s, "}"))

# The call's argument list up to its closing parenthesis.
_call_args(s) := substring(s, 0, min(ends)) if {
	ends := [k | some k in indexof_n(s, ")"); _depth(substring(s, 0, k)) == 0]
	count(ends) > 0
}

_top_commas(s) := [k | some k in indexof_n(s, ","); _depth(substring(s, 0, k)) == 0]

_args(lines, i, rest) := rest if trim_space(rest) != ""

_args(lines, i, rest) := concat(" ", [lines[i + 1], lines[min([i + 2, count(lines) - 1])]]) if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── JavaScript: parseInt without a radix ─────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "parseInt")
	regex.match(concat("", ["(?m)", _js_src]), content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "parseInt")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`(?:^|[^\w$.]|\bNumber\.)parseInt\s*\((.*)$`, line, 1)
	count(m) > 0
	arg := _call_args(_args(lines, i, m[0][1]))
	count(_top_commas(arg)) == 0
	_carries(lines, i, _js_src, trim_space(arg), "js")
	finding := _finding(path, i, line, "parseInt() of request data without a radix reads '0x...' as hexadecimal; pass the radix (parseInt(v, 10)) or use Number() and check the result")
}

# ── JavaScript: Boolean(x) / !!x of a string request value ───────────────

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`Boolean\s*\(|!!`, content)
	regex.match(concat("", ["(?m)", _js_str_src]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Boolean\s*\(|!!`, line)
	not helpers.is_comment_line(line)
	some re in [`(?:^|[^\w$.])Boolean\s*\(\s*([^)]*)\)`, `!!\s*\(?\s*([\w$.\[\]'"]+)`]
	some mm in regex.find_all_string_submatch_n(re, line, -1)
	_carries(lines, i, _js_str_src, trim_space(mm[1]), "js")
	finding := _finding(path, i, line, "Boolean()/!! of a request string is true for 'false' and '0'; compare the value explicitly (v === 'true')")
}

# ── Python: bool() of a string request value ─────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "bool(")
	regex.match(concat("", ["(?m)", _py_str_src]), content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "bool(")
	not helpers.is_comment_line(line)
	some mm in regex.find_all_string_submatch_n(`(?:^|[^\w.])bool\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)`, line, -1)
	_carries(lines, i, _py_str_src, trim_space(mm[1]), "py")
	finding := _finding(path, i, line, "bool() of a request string is True for 'false' and '0'; compare the value explicitly (v.lower() in ('1', 'true')) or use a typed converter")
}

# ── PHP: loose comparison with a secret, strcmp == 0, non-strict in_array ─

_secretish := `(?i)token|passw|pwd|hash|secret|signature|sig\b|hmac|api_?key|otp|nonce|csrf|\bpin\b|\$pin\b|\bcode\b|\$code\b|md5|sha1|crypt`

_php_tainted(lines, i, s) if regex.match(_php_src, s)

_php_tainted(lines, i, s) if {
	not regex.match(_php_src, s)
	some n in _names(lines, i, _php_src)
	regex.match(concat("", [`\$`, n, `\b`]), s)
}

_php_code(line) := regex.replace(regex.replace(line, `'(?:\\.|[^'\\])*'`, `''`), `"(?:\\.|[^"\\])*"`, `""`)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`[^=!<>]==[^=]|!=[^=]|strcmp|in_array`, content)
	regex.match(concat("", ["(?m)", _php_src]), content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	some msg in _php_issue(lines, i, line)
	finding := _finding(path, i, line, msg)
}

_php_issue(lines, i, line) := {msg |
	regex.match(`[^=!<>]==[^=]|!=[^=]`, line)
	some mm in regex.find_all_string_submatch_n(`([^=!<>&|(]+?)\s*(?:[^=!<>]==|!=)\s*([^=&|)][^&|)]*)`, line, -1)
	pair := concat(" ", [mm[1], mm[2]])
	not contains(pair, "strcmp")
	_php_tainted(lines, i, pair)
	regex.match(_secretish, pair)
	not regex.match(`^\s*(?:''|""|null|true|false|\d+)\s*$`, _php_code(mm[2]))
	msg := "Loose comparison (==/!=) of request data with a token, password or hash: PHP type juggling ('0e...' magic hashes, numeric strings) makes different values equal; use hash_equals() or ==="
} | {msg |
	contains(line, "strcmp")
	regex.match(`\bstrcmp\s*\([^;]*\)\s*(?:==|!=)\s*0\b|!\s*strcmp\s*\(`, line)
	some mm in regex.find_all_string_submatch_n(`\bstrcmp\s*\(([^;]*?)\)`, line, -1)
	_php_tainted(lines, i, mm[1])
	msg := "strcmp() of request data tested against 0: an array argument makes strcmp() return NULL, which == 0 treats as a match; use hash_equals() or === on strings"
} | {msg |
	contains(line, "in_array")
	some mm in regex.find_all_string_submatch_n(`\bin_array\s*\((.*)$`, line, -1)
	args := _call_args(mm[1])
	cs := _top_commas(args)
	count(cs) == 1
	_php_tainted(lines, i, substring(args, 0, cs[0]))
	msg := "in_array() of request data without strict mode compares loosely ('1abc' matches 1, '0' matches false); pass true as the third argument"
}
