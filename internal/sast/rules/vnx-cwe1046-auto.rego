# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1046

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1046",
	"name": "Creation of Immutable Text Using String Concatenation",
	"description": "A String is built up by concatenation inside a loop, so every iteration copies the whole text into a new immutable object: the work grows with the square of the length (a request that controls the loop count controls the CPU time), and each discarded copy of a password, token or key stays on the heap until it is collected. Reported in Java and C#: an `s += ...`, `s = s + ...` or Java `s = s.concat(...)` statement inside the body of a for, foreach, while or do loop (braced, Allman-style, a single unbraced statement or on the loop's own line) where s is a local declared String/string (or C# var initialised with a string literal or string.Empty) before the loop. Not reported: StringBuilder/StringBuffer/StringJoiner appends, String.join and Collectors.joining, concatenation after the loop ends, numeric += on int/long/double variables (also when an earlier method declared the same name as a String), a String declared inside the loop body (rebuilt each iteration rather than accumulated), fields and variables not declared in the enclosing 100 lines, Kotlin and other JVM languages, test code, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1046/",
	"languages": ["java", "csharp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1046],
	"capec": ["CAPEC-204"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["java", "csharp", "string-concatenation", "stringbuilder", "memory", "cwe-1046"],
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "cs" if endswith(path, ".cs")

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)src/(test|it)/|(?:^|/)[^/]*\.Tests?/|Tests?\.cs$`, path)

_indent(line) := count(line) - count(trim_left(line, " \t"))

_decl_re := {
	"java": `\b(?:final\s+)?String\s+([A-Za-z_]\w*)\s*(?:=|;)`,
	"cs": `\b(?:string|String)\s+([A-Za-z_]\w*)\s*(?:=|;)|\bvar\s+([A-Za-z_]\w*)\s*=\s*(?:\$|@)?"|\bvar\s+([A-Za-z_]\w*)\s*=\s*(?:string|String)\.Empty\b`,
}

_decl_needle := {"java": "String ", "cs": "tring "}

# Names declared as a String on a line.
_declared(line, lang) := {n |
	some m in regex.find_all_string_submatch_n(_decl_re[lang], line, -1)
	some n in array.slice(m, 1, count(m))
	n != ""
}

_loop_re := `^\s*(?:\}\s*)?(?:(?:for|foreach|while)\s*\(|do\s*(?:\{\s*)?$)`

# The accumulated variable on a line: `s += x` or `s = s + x`.
_acc(code) := m[1] if {
	some m in regex.find_all_string_submatch_n(`(?:^\s*|[;{)]\s*)([A-Za-z_]\w*)\s*\+=`, code, -1)
}

_acc(code) := m[1] if {
	some m in regex.find_all_string_submatch_n(`(?:^\s*|[;{)]\s*)([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\+`, code, -1)
	m[1] == m[2]
}

# Java String.concat returns a new String too: s = s.concat(x).
_acc(code) := m[1] if {
	some m in regex.find_all_string_submatch_n(`(?:^\s*|[;{)]\s*)([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\.concat\s*\(`, code, -1)
	m[1] == m[2]
}

_blank(line) := regex.replace(regex.replace(line, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, `""`), `\s//.*$`, "")

# Line k is inside the body of the loop headed at h.
_in_loop(lines, h, k) if h == k

_in_loop(lines, h, k) if {
	h < k
	ind := _indent(lines[h])
	_indent(lines[k]) > ind
	count([m |
		some m in helpers.span(h + 1, k - 1)
		m > h
		m < k
		not _body_line(lines[m], ind)
	]) == 0
}

_body_line(line, _) if trim_space(line) == ""

_body_line(line, ind) if _indent(line) > ind

_body_line(line, ind) if {
	_indent(line) == ind
	trim_space(line) == "{"
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_acc_cand(content)
	contains(content, _decl_needle[lang])
	regex.match(`\b(?:for|foreach|while)\s*\(`, content)
	not _is_test(path)
	lines := split(content, "\n")
	some k, line in lines
	_acc_cand(line)
	not helpers.is_comment_line(line)
	code := _blank(line)
	v := _acc(code)
	some h in numbers.range(max([0, k - 40]), k)
	regex.match(_loop_re, lines[h])
	_in_loop(lines, h, k)
	_header_ok(lines[h], k, h, v)
	some d in numbers.range(max([0, h - 100]), h - 1)
	contains(lines[d], v)
	v in _declared(lines[d], lang)
	not _redeclared(lines, d, k, v, lang)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s is a String built by concatenation inside a loop, so each iteration copies the whole text into a new immutable object (quadratic time, and every copy of its contents stays on the heap until collected); use a StringBuilder, String.join or a joining collector", [v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": line,
	}
}

# A statement on the loop's own line must follow the loop's parentheses.
_header_ok(_, k, h, _) if k != h

_header_ok(header, k, k, v) if regex.match(concat("", [`\)\s*\{?\s*`, v, `\s*(?:\+=|=)`]), _blank(header))

# The name is declared again after d, inside the loop or a later scope.
_redeclared(lines, d, k, v, lang) if {
	some e in numbers.range(d + 1, k)
	contains(lines[e], v)
	v in _declared(lines[e], lang)
}

# ... or declared with another type (long total = 0 in a later method).
_redeclared(lines, d, k, v, _) if {
	some e in numbers.range(d + 1, k)
	contains(lines[e], v)
	some m in regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_][\w.]*(?:<[^;=()]*>)?(?:\[\])*\??)\s+`, v, `\s*(?:=[^=]|;|:)`]), lines[e], -1)
	not m[1] in {"return", "throw", "yield", "case", "else", "new", "await", "in", "out", "ref", "String", "string", "var", "final"}
}

_acc_cand(s) if contains(s, "+")

_acc_cand(s) if contains(s, ".concat(")
