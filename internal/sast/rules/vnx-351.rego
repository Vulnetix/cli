# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_351

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-351",
	"name": "Insufficient Type Distinction",
	"description": "PHP compares an untrusted value without distinguishing its type, so a value of a different type passes the check: a JSON true equals every non-empty string, and numeric strings such as '1e0' or ' 1' compare equal to numbers. Reported: in_array() and array_search() called without strict=true (the third argument), the call allowed to span the next five lines, whose needle is json_decode() output (any haystack), or a request value ($_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER, Laravel $request->input()/get()/query()/post(), Request::input()) checked against a haystack that is not provably a list of non-numeric string literals (an inline list, a variable assigned a list in the 60 lines above, or a class constant, are read; anything else counts as unknown); the needle may be inline or a variable assigned from such a source in the 15 lines above. Also reported: a loose ==, != or <> comparison on an element or property of a variable assigned from json_decode() (of anything but a file read from disk) in the 40 lines above; strcmp()/strcasecmp()/strncmp() of an uncast request value compared loosely with 0 (== 0, != 0, !strcmp(...)), which an array argument passes because strcmp() returns null; and a loose ==/!= on md5()/sha1()/hash()/hash_hmac()/crypt()/crc32() output on a line that also uses a request value (two '0e...' digests compare equal as numbers). Not reported: hash_equals(), === on hashes, strcmp() with a (string) cast or === 0, strict calls (true or strict: true as the third argument), constant needles, needles from server-side data, request strings checked against a list of non-numeric strings (a request string can only equal one of those exactly), === and !==, comparisons with null or an empty string, json_decode() of a file on disk, comments and string literals. Java class-by-name comparison, which this rule used to look for as the words 'Object' and '==', is VNX-CWE1025-AUTO's and VNX-486's concern.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-351/",
	"languages": ["php"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [351],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["insufficient-type-distinction", "cwe-351"],
}

_source_re := `\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b|\$request->(?:input|get|query|post|cookie|header|json)\(|\bRequest::(?:input|get|query|post)\(|\bjson_decode\s*\(`

_json_re := `\bjson_decode\s*\(|\$request->json\(`

_call_re := `\b(?:in_array|array_search)\s*\(`

_has_call(s) if contains(s, "in_array")

_has_call(s) if contains(s, "array_search")

# needle , haystack
_args_re := `\b(?:in_array|array_search)\s*\(\s*((?:\$\w+|\w+::\w+)(?:\[[^\]]*\]|->\w+(?:\([^)]*\))?|::\w+\([^)]*\))*|\w+\([^)]*\))\s*,\s*(\[[^\]]*\]|array\s*\([^)]*\)|\$\w+(?:->\w+|\[[^\]]*\])+|\$\w+|\w+\([^)]*\)|(?:self|static|[A-Z]\w*)::[A-Z_]\w*)`

_in_string(line, tok) if {
	prefix := substring(line, 0, indexof(line, tok))
	some q in {"\"", "'"}
	strings.count(prefix, q) % 2 == 1
}

# PHP variables assigned from `src` in the `before` lines above i.
_tainted(lines, i, before, src) := {m[1] |
	some j in numbers.range(max([0, i - before]), i - 1)
	l := lines[j]
	regex.match(src, l)
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*=[^=]`, l, 1)
}

_from(n, lines, i, src) if regex.match(src, n)

_from(n, lines, i, src) if {
	some m in regex.find_all_string_submatch_n(`^\$(\w+)`, n, 1)
	m[1] in _tainted(lines, i, 15, src)
}

_statement(text) := regex.split(`;|\{`, text)[0]

# The text of each in-file definition of a haystack, up to its `;`.
_var_defs(lines, i, hay) := {body |
	startswith(hay, "$")
	name := substring(hay, 1, -1)
	some j in numbers.range(max([0, i - 60]), i)
	regex.match(concat("", [`^\s*\$`, name, `\s*=\s*(?:\[|array\s*\()`]), lines[j])
	body := _statement(concat(" ", array.slice(lines, j, min([count(lines), j + 20]))))
}

_const_defs(lines, hay) := {body |
	contains(hay, "::")
	name := split(hay, "::")[1]
	some l in lines
	regex.match(concat("", [`\bconst\s+`, name, `\s*=`]), l)
	body := l
}

_inline_defs(hay) := {d | some d in {hay}; regex.match(`^(?:\[|array)`, d)}

_defs(lines, i, hay) := (_var_defs(lines, i, hay) | _const_defs(lines, hay)) | _inline_defs(hay)

# A list of non-numeric string literals: a request string can only match one
# of them exactly, so a loose comparison is harmless there.
_string_only(body) if {
	regex.match(`['"]`, body)
	not regex.match(`(?:[\[(,=]|=>)\s*(?:[-+]?\.?\d|true|false|null|TRUE|FALSE|NULL|\$)|['"]\s*[-+.]?\d`, substring(body, max([0, indexof(body, "=") + 1]), -1))
}

_safe_haystack(lines, i, hay) if {
	defs := _defs(lines, i, hay)
	count(defs) > 0
	every d in defs {
		_string_only(d)
	}
}

_risky(needle, hay, lines, i) if _from(needle, lines, i, _json_re)

_risky(needle, hay, lines, i) if {
	_from(needle, lines, i, _source_re)
	not _safe_haystack(lines, i, hay)
}

# ── in_array / array_search without strict ──────────────────────────────
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	_has_call(content)
	lines := split(content, "\n")
	some i, line in lines
	_has_call(line)
	regex.match(_call_re, line)
	not helpers.is_comment_line(line)
	tok := regex.find_n(_call_re, line, 1)[0]
	not _in_string(line, tok)
	text := concat(" ", array.slice(lines, i, min([count(lines), i + 6])))
	rest := substring(text, indexof(text, tok), -1)
	stmt := _statement(rest)
	not regex.match(`,\s*(?:strict\s*:\s*)?(?:true|TRUE|True)\s*\)`, stmt)
	some m in regex.find_all_string_submatch_n(_args_re, rest, 1)
	_risky(m[1], m[2], lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s compares a request value loosely against a list that may hold numbers or booleans, so a value of another type (a JSON true, '1e0', ' 1') can match. Pass true as the third argument for a strict comparison", [trim_space(trim_right(tok, "("))]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── loose comparison on json_decode() output ────────────────────────────
_file_read(l) if {
	contains(l, "file_get_contents(")
	not contains(l, "php://input")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "json_decode")
	lines := split(content, "\n")
	jvars := [[j, m[1]] |
		some j, l in lines
		contains(l, "json_decode")
		not helpers.is_comment_line(l)
		not _file_read(l)
		some m in regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*=\s*json_decode\s*\(`, l, 1)
	]
	count(jvars) > 0
	some i, line in lines
	contains(line, "$")
	regex.match(`[^=!<>]==[^=]|!=[^=]|<>`, line)
	not helpers.is_comment_line(line)
	some jv in jvars
	jv[0] < i
	i - jv[0] <= 40
	v := jv[1]
	some m in regex.find_all_string_submatch_n(concat("", [`\$`, v, `(?:\[[^\]]+\]|->\w+)+\s*(?:==|!=|<>)\s*([^=\s][^)&|;]*)|([^\s(!][^(&|;=]*?)\s*[^=!<>](?:==|!=)\s*\$`, v, `(?:\[[^\]]+\]|->\w+)+`]), line, -1)
	other := trim_space(concat("", [m[1], m[2]]))
	not regex.match(`^(?:null|NULL|''|""|\$\w+\s*===?)$`, other)
	not _in_string(line, m[0])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("A json_decode() value from the request ($%s) is compared with a loose ==/!=, so a JSON true or a number matches values of another type. Check the type and compare with ===", [v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── strcmp() family compared loosely with 0 ─────────────────────────────
# strcmp() of an array returns null, and null == 0 and !null are true, so a
# request value sent as password[]= passes. A (string) cast or === 0 is safe.
_strcmp_re := `\bstrn?(?:case)?cmp\s*\(`

_loose_zero_re := `\bstrn?(?:case)?cmp\s*\([^;]*\)\s*(?:==|!=)\s*0\b|\b0\s*(?:==|!=)\s*strn?(?:case)?cmp\s*\(|!\s*strn?(?:case)?cmp\s*\(`

# A request value reaches the call as an uncast argument.
_uncast_request_arg(line, lines, i) if {
	some m in regex.find_all_string_submatch_n(`\bstrn?(?:case)?cmp\s*\(\s*([^,]+?)\s*,\s*([^,)]+)`, line, 1)
	some a in [m[1], m[2]]
	not regex.match(`^\(\s*string\s*\)`, a)
	_from(a, lines, i, _source_re)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "cmp")
	regex.match(_loose_zero_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "cmp")
	not helpers.is_comment_line(line)
	regex.match(_loose_zero_re, line)
	tok := regex.find_n(_strcmp_re, line, 1)[0]
	not _in_string(line, tok)
	_uncast_request_arg(line, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "strcmp() of a request value is compared loosely with 0: an array argument makes it return null, which == 0, so the check passes. Cast the value to string and compare with === 0, or use hash_equals()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── a hash compared loosely ─────────────────────────────────────────────
# md5()/sha1()/hash() output compared with ==/!=: two '0e<digits>' strings are
# equal as numbers ("magic hashes"), so a chosen input matches a stored hash.
_hash_call := `\b(?:md5|sha1|hash|hash_hmac|crypt|crc32)\s*\(`

_hash_loose_re := concat("", [_hash_call, `[^;]*?\)\s*(?:==|!=)[^=]|[^=!<>](?:==|!=)\s*`, _hash_call])

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	_has_hash_call(content)
	regex.match(`(?m)(?:md5|sha1|hash|hash_hmac|crypt|crc32)\s*\([^;\n]*\)\s*[!=]=[^=]|[!=]=\s*(?:md5|sha1|hash|hash_hmac|crypt|crc32)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "=")
	regex.match(_hash_loose_re, line)
	not helpers.is_comment_line(line)
	tok := regex.find_n(_hash_call, line, 1)[0]
	not _in_string(line, tok)
	_request_on_line(line, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "A hash is compared with a loose ==/!=: two '0e…' digests compare equal as numbers, so a chosen input can match a stored hash. Use hash_equals() (or password_verify() for passwords)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_request_on_line(line, _, _) if regex.match(_source_re, line)

_request_on_line(line, lines, i) if {
	some m in regex.find_all_string_submatch_n(`\$(\w+)`, line, -1)
	m[1] in _tainted(lines, i, 15, _source_re)
}

_has_hash_call(content) if contains(content, "md5(")

_has_hash_call(content) if contains(content, "sha1(")

_has_hash_call(content) if contains(content, "hash(")

_has_hash_call(content) if contains(content, "hash_hmac(")

_has_hash_call(content) if contains(content, "crypt(")

_has_hash_call(content) if contains(content, "crc32(")
