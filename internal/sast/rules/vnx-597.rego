# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_597

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-597",
	"name": "String compared with == or != instead of equals()/strcmp()",
	"description": "In Java, == and != on two Strings compare references, so a check against a string literal or another String passes or fails depending on interning, not on content; in C, comparing a char pointer with a string literal compares addresses and is never a content comparison. Reported: a Java expression comparing anything with a string literal by == or != (role == \"admin\", request.getParameter(\"a\") == \"x\", also with the literal on the next line), a Java comparison of two variables both declared String within the 60 lines above, and in .c files a comparison of an expression with a string literal. Not reported: equals/equalsIgnoreCase/Objects.equals/strcmp, comparisons with null, char literals ('a'), C++ files (std::string overloads ==), Kotlin (== is equals there), and operators inside comments or string literals. Comparisons of boxed numbers and other objects are VNX-595.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-597/",
	"languages": ["java", "c"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [597],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["java", "c", "string-comparison", "cwe-597"],
}

# String literals become "" and char literals '' so operators quoted in a
# message are not code, and a char comparison is not a string comparison.
_code(line) := regex.replace(regex.replace(line, `'(?:[^'\\]|\\.)'`, `''`), `"(?:[^"\\]|\\.)*"`, `""`)

_lit_cmp := `(?:[=!]=\s*""|""\s*[=!]=)`

_msg_java := "String compared with == or !=: this compares references, not content. Use equals() (or Objects.equals / \"literal\".equals(x))"

_msg_c := "A char pointer is compared with a string literal by == or !=: this compares addresses, not content. Use strcmp/strncmp"

_ext(path) := "java" if endswith(path, ".java")

_ext(path) := "c" if endswith(path, ".c")

findings contains finding if {
	some path, content in input.file_contents
	lang := _ext(path)
	_file_gate(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "=")
	_candidate(lang, line)
	not helpers.is_comment_line(line)
	c := _strip_trailing_comment(_code(line))
	_reports(lang, lines, i, c)
	finding := {
		"rule_id": metadata.id,
		"message": _msg(lang),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# C: the literal on the operator's own line only (the multi-line form is Java).
_file_gate("c", content) if regex.match(`[=!]=[ \t]*"|"[ \t]*[=!]=`, content)

_file_gate("java", content) if {
	contains(content, "String")
	regex.match(`[=!]=`, content)
}

_candidate(_, line) if {
	contains(line, "\"")
	regex.match(`[=!]=\s*"|"\s*[=!]=`, line)
}

_candidate(_, line) if {
	endswith(trim_right(line, " \t\r"), "=")
	regex.match(`[=!]=\s*$`, line)
}

_candidate("java", line) if regex.match(`\w\s*[=!]=\s*\w`, line)

# Literals are already blanked, so a // or /* left in the line opens a comment.
_strip_trailing_comment(c) := regex.replace(c, `\s*(?://|/\*).*$`, "")

_msg("java") := _msg_java

_msg("c") := _msg_c

# x == "literal", "literal" != x
_reports(_, _, _, c) if regex.match(_lit_cmp, c)

# x ==
#     "literal"
_reports(_, lines, i, c) if {
	regex.match(`[=!]=\s*$`, c)
	i + 1 < count(lines)
	regex.match(`^\s*""`, _code(lines[i + 1]))
}

# Two String variables.
_reports("java", lines, i, c) if {
	some m in regex.find_all_string_submatch_n(`(^|[^\w.])([A-Za-z_]\w*)\s*(?:==|!=)\s*([A-Za-z_]\w*)\s*(?:[^\w\s.(\[]|$)`, c, -1)
	a := m[2]
	b := m[3]
	a != b
	not _keyword(a)
	not _keyword(b)
	win := _window(lines, i)
	_declared_string(win, a)
	_declared_string(win, b)
}

_keyword(v) if v in {"null", "this", "true", "false", "super", "class"}

_window(lines, i) := concat("\n", [_code(lines[k]) |
	some k in numbers.range(max([0, i - 60]), i)
	not helpers.is_comment_line(lines[k])
])

_declared_string(win, v) if {
	regex.match(concat("", [`\bString\s+`, v, `\s*[=;,)]`]), win)
	not regex.match(concat("", [`\b(?:int|long|short|byte|char|double|float|boolean|var|Integer|Long|Object)\s+`, v, `\b`]), win)
}
