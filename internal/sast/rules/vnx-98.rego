# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_98

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-98",
	"name": "PHP Remote File Inclusion",
	"description": "A PHP include, include_once, require or require_once statement (with or without parentheses) whose path carries request data: a superglobal ($_GET, $_POST, $_REQUEST, $_COOKIE, $_FILES), php://input, filter_input() or a Laravel/Symfony $request->input/get/query/post accessor, inline, interpolated, or through a variable assigned from one (or from such a variable) in the 25 lines above. str_replace() blacklists of ../ or http:// still count, because they are bypassable. That is Local File Inclusion, and Remote File Inclusion where allow_url_include is on; both run attacker-chosen code. Not reported: a path passed through basename(), intval() or an (int) cast, a variable checked against an allowlist (in_array, array_key_exists, isset($map[$x]), preg_match, ctype_*, is_numeric) between the read and the include, a path looked up in an application array by the request value ($routes[$_GET['p']]) or chosen by a match() on it, includes of constants, __DIR__ paths and variables not derived from the request in this file, and statements in comments or string literals. A path that crosses files (assigned in one, included in another) is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-98/",
	"languages": ["php"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [98],
	"capec": ["CAPEC-253"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["rfi", "file-inclusion", "php", "cwe-98"],
}

_src := `\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|php://input|\bfilter_input\s*\(|\$request->(?:input|get|query|post|all|route)\s*\(|\$this->request->(?:get|getQuery|getPost|getParam)\s*\(`

_sink := `(?:^|[^\w$>:\\])(?:include|include_once|require|require_once)\b\s*\(?(.*)$`

_sanitised := `\bbasename\s*\(|\bintval\s*\(|\(int\)|\babs\s*\(`

_guard_fn := `\b(?:in_array|array_key_exists|preg_match|ctype_\w+|is_numeric)\s*\(|\bisset\s*\(\s*\$[A-Za-z]\w*\s*\[`

# A value looked up in an application array by a request key, or chosen by a
# match/switch on it, is one of the program's own paths.
_lookup_assign := `^\s*\$\w+\s*=\s*(?:\$[A-Za-z]\w*\s*\[|match\s*\()`

# Single-quoted literals do not interpolate in PHP; blank them so a name in
# one is not a use.
_blank_sq(s) := regex.replace(s, `'(?:\\.|[^'\\])*'`, `''`)

_blank(s) := regex.replace(_blank_sq(s), `"(?:\\.|[^"\\])*"`, `""`)

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*\$([A-Za-z_]\w*)\s*(?:\.=|\?\?=|=)[^=>]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_t1(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	regex.match(_src, l)
	not helpers.is_comment_line(l)
	not regex.match(_sanitised, l)
	not regex.match(_lookup_assign, l)
	v := _assigned(l)
}

_t2(lines, i, n1) := {v |
	i > 0
	count(n1) > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	v := _assigned(l)
	not v in n1
	not regex.match(_sanitised, l)
	some n in n1
	regex.match(concat("", [`=.*\$`, n, `\b`]), _blank_sq(l))
	not helpers.is_comment_line(l)
}

_guarded(lines, i, n) if {
	some k in numbers.range(max([0, i - 25]), i - 1)
	l := lines[k]
	regex.match(_guard_fn, l)
	regex.match(concat("", [`\$`, n, `\b`]), l)
	not helpers.is_comment_line(l)
}

_tainted(lines, i, arg) if regex.match(_src, arg)

_tainted(lines, i, arg) if {
	not regex.match(_src, arg)
	n1 := _t1(lines, i)
	names := n1 | _t2(lines, i, n1)
	some n in names
	regex.match(concat("", [`\$`, n, `\b`]), arg)
	not _guarded(lines, i, n)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`(?:include|require)`, content)
	regex.match(concat("", ["(?m)", _src]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\b(?:include|require)`, line)
	not helpers.is_comment_line(line)
	regex.match(_sink, _blank(line))
	m := regex.find_all_string_submatch_n(_sink, line, 1)
	count(m) > 0
	arg := _blank_sq(m[0][1])
	not regex.match(_sanitised, arg)
	not regex.match(`^\s*\(?\s*\$[A-Za-z]\w*\s*\[(?:[^\[\]]|\[[^\]]*\])*\]\s*(?:\?\?\s*'[^']*'\s*)?\)?\s*;`, arg)
	_tainted(lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "PHP file inclusion: request data chooses the file that include/require loads and executes; map the request value to a fixed allowlist of files instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
