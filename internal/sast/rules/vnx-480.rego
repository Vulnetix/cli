# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_480

import rego.v1

metadata := {
	"id": "VNX-480",
	"name": "Use of Incorrect Operator",
	"description": "Reports operators that compile but do not do what the line means. Java: a String compared with == or != against a string literal (reference identity, not content) and a BigDecimal compared by reference with BigDecimal.ZERO/ONE/TEN. C: a char pointer compared with == or != against a string literal (address comparison; use strcmp). C/C++: a bit mask tested as flags & MASK == value, which parses as flags & (MASK == value). C/C++/Java: the transposed compound assignment x =+ n / x =- n (an assignment of +n, not an increment). Not reported: equals()/compareTo()/strcmp, comparisons with null, char literals, std::string compared with a literal in C++ (operator== compares content; a .h header that uses std::, class, namespace or template counts as C++), parenthesised masks ((flags & MASK) == value), x = -n written with a space, and operators inside strings and comments. Assignment used as a condition (if (x = y)) is VNX-481.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-480/",
	"languages": ["c", "cpp", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [480],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["wrong-operator", "cwe-480"],
}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$)|#)`, line)

# String literals collapse to "S" and char literals to 'C', so an operator
# inside a literal is never seen and a literal operand stays recognisable.
# A trailing // comment is dropped.
_code(line) := c if {
	s := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `"S"`)
	t := regex.replace(s, `'(?:[^'\\]|\\.)+'`, `'C'`)
	c := regex.replace(regex.replace(t, `/\*.*?(?:\*/|$)`, ""), `//.*$`, "")
}

_cpp_exts := {".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_kind(path, _) := "java" if endswith(path, ".java")

_kind(path, _) := "c" if endswith(path, ".c")

# A .h header is C++ when it uses C++ (std::, a class, a namespace, a
# template): there a literal compared with a std::string compares content.
_kind(path, content) := "c" if {
	endswith(path, ".h")
	not _cpp_header(content)
}

_kind(path, content) := "cpp" if {
	endswith(path, ".h")
	_cpp_header(content)
}

_kind(path, _) := "cpp" if {
	some e in _cpp_exts
	endswith(path, e)
}

_cpp_header(content) if regex.match(`std::|(?m)^\s*(?:class|namespace|template)\b|#include\s*<(?:string|string_view|iostream|vector|memory)>`, content)

_str_cmp := `(?:[\w\])]\s*[!=]=\s*"S"|"S"\s*[!=]=\s*[A-Za-z_(])`

_shape("java", c) := "String compared with ==/!= against a literal compares references, not content; use \"literal\".equals(s)" if {
	regex.match(_str_cmp, c)
	not regex.match(`\bnull\s*[!=]=\s*"S"|"S"\s*[!=]=\s*null\b`, c)
}

_shape("java", c) := "BigDecimal compared by reference; use compareTo() == 0 (or signum() for ZERO)" if {
	regex.match(`[!=]=\s*BigDecimal\.(?:ZERO|ONE|TEN)\b|\bBigDecimal\.(?:ZERO|ONE|TEN)\s*[!=]=`, c)
}

_shape("c", c) := "char pointer compared with ==/!= against a string literal compares addresses; use strcmp()" if {
	regex.match(_str_cmp, c)
}

_shape(k, c) := "bit mask tested as 'x & MASK == v': == binds tighter than &, so this is x & (MASK == v); write (x & MASK) == v" if {
	k in {"c", "cpp"}
	regex.match(`[\w\])]\s*[&|]\s*(?:[A-Za-z_]\w*|0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*)\s*[!=]=\s*[\w(]`, c)
	regex.match(`\b(?:if|while|return)\b|[?]`, c)
}

_shape(k, c) := "'=+' / '=-' assigns +n or -n instead of adding or subtracting; did you mean += or -=?" if {
	k in {"c", "cpp", "java"}
	regex.match(`[\w\])]\s*=[+-]\s+[\w(]`, c)
}

findings contains finding if {
	some path, content in input.file_contents
	k := _kind(path, content)
	regex.match(`[!=]=|=[+-]\s`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`[!=]=|=[+-]\s`, line)
	not _is_comment(line)
	c := _code(line)
	some msg in {m | m := _shape(k, c)}
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
