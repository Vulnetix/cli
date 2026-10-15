# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1335

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1335",
	"name": "Incorrect Bitwise Shift of Integer",
	"description": "A C or C++ shift whose amount is a constant at or past the width of the operand, or negative, which is undefined behaviour (compilers fold it to any value, often the unshifted operand): an integer literal with no suffix or a U suffix (32-bit int/unsigned) shifted by 32 or more, a literal with an L/LL/UL/ULL suffix shifted by 64 or more, a value cast to a 32-bit or narrower type ((uint32_t)v, (int)x, (unsigned)x, static_cast<uint32_t>(v)) and then shifted by 32 or more, a variable declared nearby as a 32-bit or narrower integer (uint32_t, int, unsigned, DWORD, u32...) shifted or shift-assigned by 32 or more, and any shift by a negative constant. Not reported: suffixed or widened operands within their width (1ULL << 40, (uint64_t)1 << 63, UINT64_C(1) << 40), 64-bit variables, an amount that is part of a larger expression (1 << 32 - 1), shifts by a variable amount, C++ stream insertion (std::cout << x << 64), comments, strings and macro parameters. The type of a variable is known only from a declaration within 60 lines above the shift.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1335/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1335],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["incorrect-bitwise-shift", "undefined-behavior", "integer", "cwe-1335"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

# Strings, character literals and trailing comments are not code.
_strip(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|/\*.*?\*/|//.*$`, `""`)

# The shift amount must end the operand: `1 << 32 - 1` shifts by 31.
_tail := `(?:\s*(?:[^\s\w.+\-*/%]|$))`

# literal [suffix] << amount, with the literal not the right operand of a
# tighter-binding operator.
_lit_re := concat("", [`(?:^|[^\w.)\]+\-*/%<>]\s*|[(=,|&^?:~!]\s*)(0[xX][0-9a-fA-F]+|\d+)([uUlL]*)\s*(?:<<|>>)\s*(\d+)`, _tail])

_too_wide(suffix, amount) if {
	not contains(lower(suffix), "l")
	to_number(amount) >= 32
}

_too_wide(suffix, amount) if {
	contains(lower(suffix), "l")
	to_number(amount) >= 64
}

_narrow := `(?:u?int(?:8|16|32)_t|uint(?:8|16|32)|[us](?:8|16|32)|__u32|__s32|DWORD|UINT32|INT32|UINT|unsigned\s+int|unsigned\s+short|unsigned\s+char|unsigned|short|int|char)`

_cast_re := concat("", [`\(\s*(?:const\s+)?`, _narrow, `\s*\)\s*[A-Za-z_][\w]*(?:(?:->|\.)[A-Za-z_]\w*|\[[^\]]*\])*\s*(?:<<|>>)\s*(\d+)`, _tail])

# The variable is the whole left operand: not a cast's operand, a member or
# an element.
_var_re := concat("", [`(?:^|[^\w\s).>\]]|\breturn\b)\s*([A-Za-z_]\w*)\s*(?:<<|>>)=?\s*(\d+)`, _tail])

_bad(_, _, code) if {
	some m in regex.find_all_string_submatch_n(_lit_re, code, -1)
	_too_wide(m[2], m[3])
}

_bad(_, _, code) if {
	some m in regex.find_all_string_submatch_n(_cast_re, code, -1)
	to_number(m[1]) >= 32
}

# static_cast<uint32_t>(v) << 32 and (uint32_t)(expr) << 32
_cast2_re := concat("", [`(?:\bstatic_cast\s*<\s*(?:const\s+)?`, _narrow, `\s*>|\(\s*(?:const\s+)?`, _narrow, `\s*\))\s*\([^()]*\)\s*(?:<<|>>)\s*(\d+)`, _tail])

_bad(_, _, code) if {
	some m in regex.find_all_string_submatch_n(_cast2_re, code, -1)
	to_number(m[1]) >= 32
}

# C++ stream insertion (std::cout << 1 << 40) is not a shift.
_streamish(l) if regex.match(`\bstd::(?:cout|cerr|clog|wcout|endl)\b|\b(?:cout|cerr|clog|wcout|os|out|oss|ss|stream|qDebug\(\)|qWarning\(\))\s*<<|<<\s*(?:std::endl|endl\b|"|')|(?:<<|>>)\s*\d+\s*<<`, l)

_bad(_, _, code) if regex.match(`(?:<<|>>)=?\s*-\s*\d`, code)

_bad(lines, i, code) if {
	some m in regex.find_all_string_submatch_n(_var_re, code, -1)
	to_number(m[2]) >= 32
	v := m[1]
	not regex.match(`^\d`, v)
	_declared_narrow(lines, i, v)
}

_any_type := concat("", [`(?:`, _narrow, `|\w+_t|long(?:\s+long)?(?:\s+(?:unsigned\s+)?int)?|unsigned\s+long(?:\s+long)?|double|float|bool|[us]64|u?int64|QWORD|ULONGLONG|auto)`])

# The nearest declaration of v above (a local or a parameter) is a 32-bit or
# narrower integer.
_declared_narrow(lines, i, v) if {
	decl_re := concat("", [`(?:^|[(,;{]|\s)(?:const\s+)?`, _any_type, `\s+\**`, v, `\s*[;,=)\[]`])
	decls := [j |
		some j in numbers.range(max([0, i - 60]), i)
		contains(lines[j], v)
		regex.match(decl_re, lines[j])
	]
	count(decls) > 0
	l := lines[max(decls)]
	regex.match(concat("", [`(?:^|[(,;{]|\s)(?:const\s+)?`, _narrow, `\s+`, v, `\s*[;,=)\[]`]), l)
	not regex.match(concat("", [`\blong\s+(?:long\s+)?(?:unsigned\s+|signed\s+)?(?:int\s+)?`, v, `\b`]), l)
	not regex.match(concat("", [`\bunsigned\s+long\b[^;]*\b`, v, `\b`]), l)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	regex.match(`(?:<<|>>)=?\s*(?:3[2-9]|[4-9]\d|\d{3}|-\s*\d)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:<<|>>)=?\s*(?:3[2-9]|[4-9]\d|\d{3}|-\s*\d)`, line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*#\s*(?:include|pragma|error|warning)`, line)
	not _streamish(line)
	code := _strip(line)
	_bad(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": "Shift amount is negative or not less than the width of the shifted operand; this is undefined behaviour in C/C++. Widen the operand first (1ULL << n, (uint64_t)v >> 32) or bound the amount",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
