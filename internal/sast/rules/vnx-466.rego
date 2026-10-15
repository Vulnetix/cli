# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_466

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-466",
	"name": "Return of Pointer Value Outside of Expected Range",
	"description": "A C or C++ function returns a pointer offset from the result of a search function (strchr, strrchr, memchr, memrchr, strstr, strcasestr, strpbrk) without checking that result for NULL: `return strchr(s, '=') + 1;`, or `p = strchr(s, ':');` followed within 20 lines by `return p + 2;` or `return &p[1];` (directly or through one plain copy `q = p;`) with no NULL test in between. When the character is absent the search returns NULL and the caller receives NULL + n, a pointer outside any object, which a NULL check by the caller cannot catch. Not reported: a result tested for NULL (`if (!p)`, `p == NULL`, `p ? p + 1 : s`, `if ((p = strchr(...)) != NULL)`, an assert) before the return, a pointer reassigned after the search, offsets returned from pointers that did not come from a search (whose range cannot be judged line by line), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-466/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [466],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["return-of-pointer-outside-range", "null-offset", "cwe-466"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_search := `(?:std::)?(?:strchr|strrchr|memchr|memrchr|strstr|strcasestr|strpbrk)\s*\(`

# String literals are blanked so a quoted "return strchr(...) + 1" is not code.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# Shape 1: return strchr(...) + n;
_direct(code) if regex.match(concat("", [`^\s*return\s+\(?\s*(?:\([^()]*\*\s*\)\s*)?`, _search, `[^;]*\)\s*\)?\s*\+`]), code)

# Shape 2: return p + n; / return &p[n];
_returned_ptr(code) := v if {
	m := regex.find_all_string_submatch_n(`^\s*return\s+\(?\s*([A-Za-z_]\w*)\s*\+\s*[^;]+;`, code, 1)
	count(m) > 0
	v := m[0][1]
}

_returned_ptr(code) := v if {
	m := regex.find_all_string_submatch_n(`^\s*return\s+&\s*([A-Za-z_]\w*)\s*\[`, code, 1)
	count(m) > 0
	v := m[0][1]
}

_assigns(line, v) if regex.match(concat("", [`(?:^|[^\w.>])`, v, `\s*=[^=]`]), line)

# The nearest assignment of v above the return, within 20 lines.
_last_assign(lines, i, v) := j if {
	js := [j |
		some j in numbers.range(max([0, i - 20]), i - 1)
		_assigns(lines[j], v)
		not helpers.is_comment_line(lines[j])
	]
	count(js) > 0
	j := max(js)
}

_null_check(line, v) if {
	some p in [
		concat("", [`\b`, v, `\s*[!=]=`]),
		concat("", [`[!=]=\s*`, v, `\b`]),
		concat("", [`!\s*\(?\s*`, v, `\b`]),
		concat("", [`\b(?:if|while)\s*\(\s*`, v, `\s*\)`]),
		concat("", [`\b`, v, `\s*(?:&&|\|\||\?)`]),
		concat("", [`(?:&&|\|\|)\s*`, v, `\b`]),
		concat("", [`(?i)assert\w*\s*\(\s*`, v, `\b`]),
		concat("", [`\(\s*`, v, `\s*=[^=][^;]*\)\s*(?:[!=]=|&&|\|\||\))`]),
	]
	regex.match(p, line)
}

_unchecked(lines, j, i, v) if {
	not _checked_between(lines, j, i, v)
}

_checked_between(lines, j, i, v) if {
	some k in numbers.range(j, i)
	_null_check(lines[k], v)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	regex.match(`(?:strchr|strrchr|memchr|memrchr|strstr|strcasestr|strpbrk)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "return")
	not helpers.is_comment_line(line)
	code := _code(line)
	_direct(code)
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	regex.match(`(?:strchr|strrchr|memchr|memrchr|strstr|strcasestr|strpbrk)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "return")
	not helpers.is_comment_line(line)
	code := _code(line)
	v := _returned_ptr(code)
	j := _last_assign(lines, i, v)
	regex.match(concat("", [`(?:^|[^\w.>])`, v, `\s*=\s*(?:\([^()]*\*\s*\)\s*)?`, _search]), _code(lines[j]))
	_unchecked(lines, j, i, v)
	finding := _finding(path, i, line)
}

# One alias hop: q = strchr(...); p = q; return p + 1; with neither tested.
findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	regex.match(`(?:strchr|strrchr|memchr|memrchr|strstr|strcasestr|strpbrk)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "return")
	not helpers.is_comment_line(line)
	code := _code(line)
	v := _returned_ptr(code)
	j := _last_assign(lines, i, v)
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.>])`, v, `\s*=\s*([A-Za-z_]\w*)\s*;`]), _code(lines[j]), 1)
	count(m) > 0
	w := m[0][1]
	w != v
	j2 := _last_assign(lines, j, w)
	regex.match(concat("", [`(?:^|[^\w.>])`, w, `\s*=\s*(?:\([^()]*\*\s*\)\s*)?`, _search]), _code(lines[j2]))
	_unchecked(lines, j2, i, w)
	_unchecked(lines, j, i, v)
	finding := _finding(path, i, line)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Pointer offset from an unchecked strchr/memchr/strstr result is returned: when the search fails the caller gets NULL + n, a pointer outside any object. Test the result for NULL before adding the offset",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
