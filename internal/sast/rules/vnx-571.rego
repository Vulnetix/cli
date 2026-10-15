# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_571

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-571",
	"name": "Expression is Always True",
	"description": "A comparison that is always true, in C, C++, Go and Java, so the check it was meant to make (a bounds, error or loop-termination check) never rejects anything. Five shapes are reported: a length or size compared with zero from above (len(x) >= 0, s.length() >= 0, a.length >= 0, list.size() >= 0, sizeof(x) >= 0, strlen(s) >= 0, and 0 <= len(x)); an unsigned variable compared >= 0 (a C/C++ unsigned, size_t or uintN_t variable, or a Go uint variable, declared above in the same file with no later signed redeclaration), which also makes for (size_t i = n; i >= 0; i--) loop forever; the same operand required to differ from one of two different constants (x != 1 || x != 2); two ranges on one operand that cover every value (x > 10 || x < 20); and an operand compared with itself (a == a, n >= n). Not reported: a constant condition written on purpose (if (true), while (1), for (;;)), x != x and v == v on a float or double declared above (the NaN tests), a cast operand ((int)n >= 0), a member of another object (p->n), comparisons inside string literals or comments, and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-571/",
	"languages": ["c", "cpp", "go", "java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [571],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["always-true", "cwe-571"],
}

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_line_filter := `>=\s*0|0\s*<=|!=[^|]*\|\|[^=]*!=|[<>]=?\s*-?\d[^|]*\|\|[^<>]*[<>]|[<>=]=`

# String and character literals blanked, trailing // comment removed.
_code(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), `//.*$`, "")

_end := `\s*(?:[)&|;?:,{]|$)`

# ── length/size from above zero ──────────────────────────────────────────

# A field named size or length (w.size) is an ordinary integer: only Go's
# len(), Java's array .length and the library calls are sizes.
_args := `\([^()]*(?:\([^()]*\)[^()]*)*\)`

_size_expr := {
	"go": concat("", [`\blen`, _args]),
	"java": `\.length(?:\(\))?|\.size\(\)`,
	"c": concat("", [`\.(?:length|size)\(\)|\b(?:sizeof|strlen|wcslen)\s*`, _args]),
}

_size_head := {
	"go": `len\(`,
	"java": `[\w.\[\]()]*\.(?:length\b|size\(\))`,
	"c": `(?:sizeof\b|strlen\(|wcslen\(|[\w.\[\]()]*\.(?:length|size)\(\))`,
}

_hit(_, _, lang, c) if regex.match(concat("", [`(?:`, _size_expr[lang], `)\s*>=\s*0`, _end]), c)

_hit(_, _, lang, c) if regex.match(concat("", [`(?:^|[^\w.])0\s*<=\s*`, _size_head[lang]]), c)

# ── unsigned variable >= 0 ───────────────────────────────────────────────

_unsigned_decl := {
	"c": `\b(?:unsigned(?:\s+(?:int|long|short|char))*|size_t|uint(?:8|16|32|64)?_t|u_?int(?:8|16|32|64)?|UINT|DWORD|WORD|ULONG)\s+\**\s*NAME\s*(?:[=;,)\[]|$)`,
	"go": `\bNAME\s+uint(?:8|16|32|64|ptr)?\b|\bNAME\s*:?=\s*uint(?:8|16|32|64|ptr)?\(`,
}

_signed_decl := {
	"c": `\b(?:int|long|short|signed|ssize_t|off_t|ptrdiff_t|intptr_t|int(?:8|16|32|64)_t|float|double|auto|char)\s+\**\s*NAME\b`,
	"go": `\bNAME\s+(?:int(?:8|16|32|64)?|float(?:32|64))\b|\bNAME\s*(?:,\s*\w+\s*)*:=\s*[^u]|,\s*NAME\s*(?:,\s*\w+\s*)*:=`,
}

# The operand compared >= 0 is a plain variable whose nearest declaration
# above (or in the same for statement) is unsigned.
_hit(lines, i, lang, c) if {
	lang in {"c", "go"}
	contains(c, "0")
	some cm in regex.find_all_string_submatch_n(concat("", [`(?:^|[(\s!&|,;])([A-Za-z_]\w*)\s*>=\s*0`, _end]), c, -1)
	v := cm[1]
	re := replace(_unsigned_decl[lang], "NAME", v)
	some j in numbers.range(max([0, i - 60]), i)
	contains(lines[j], v)
	regex.match(re, lines[j])
	not _redeclared_signed(lines, j, i, lang, v)
}

_redeclared_signed(lines, j, i, lang, v) if {
	j + 1 <= i
	re := replace(_signed_decl[lang], "NAME", v)
	some k in numbers.range(j + 1, i)
	contains(lines[k], v)
	regex.match(re, lines[k])
}

# ── one operand differing from one of two constants ──────────────────────

_lit := `(?:-?\d+(?:\.\d+)?[uUlLfF]*|0[xX][0-9a-fA-F]+|''|""|true|false|nil|null|NULL|(?:[A-Z]\w*\.)?[A-Z][A-Z0-9_]+)`

_lhs_prefix := `(?:^|[(,;?:=]|&&|\|\||\breturn\b|\bif\b)\s*`

_hit(_, _, _, c) if {
	contains(c, "||")
	re := concat("", [_lhs_prefix, `([\w.]+)\s*!=\s*(`, _lit, `)\s*\|\|\s*([\w.]+)\s*!=\s*(`, _lit, `)`, _end])
	some m in regex.find_all_string_submatch_n(re, c, -1)
	m[1] == m[3]
	m[2] != m[4]
	not "''" in {m[2], m[4]}
	not "\"\"" in {m[2], m[4]}
}

# ── two ranges covering every value ──────────────────────────────────────

_num := `(-?\d+(?:\.\d+)?)`

# x > a || x < b
_hit(_, _, _, c) if {
	contains(c, "||")
	re := concat("", [_lhs_prefix, `([\w.]+)\s*(>=?)\s*`, _num, `\s*\|\|\s*([\w.]+)\s*(<=?)\s*`, _num, _end])
	some m in regex.find_all_string_submatch_n(re, c, -1)
	m[1] == m[4]
	_covers(m[2], to_number(m[3]), m[5], to_number(m[6]))
}

# x < b || x > a
_hit(_, _, _, c) if {
	contains(c, "||")
	re := concat("", [_lhs_prefix, `([\w.]+)\s*(<=?)\s*`, _num, `\s*\|\|\s*([\w.]+)\s*(>=?)\s*`, _num, _end])
	some m in regex.find_all_string_submatch_n(re, c, -1)
	m[1] == m[4]
	_covers(m[5], to_number(m[6]), m[2], to_number(m[3]))
}

_covers(_, lo, _, hi) if hi > lo

_covers(">=", lo, _, hi) if hi == lo

_covers(_, lo, "<=", hi) if hi == lo

# ── operand compared with itself ─────────────────────────────────────────

_hit(lines, i, _, c) if {
	re := concat("", [`(?:^|[(,;?:=]|&&|\|\||\breturn\b|\bif\b)\s*([A-Za-z_][\w.]*)\s*(==|<=|>=)\s*([A-Za-z_][\w.]*)`, _end])
	some m in regex.find_all_string_submatch_n(re, c, -1)
	m[1] == m[3]
	not m[1] in {"true", "false", "nil", "null", "NULL"}
	not _floating(lines, i, m[1])
}

# v == v on a floating-point value is the NaN test (false only for NaN), so a
# name declared float or double in the 60 lines above is not reported.
_floating(lines, i, v) if {
	n := regex.replace(v, `\.`, `\.`)
	re := concat("", [`\b(?:float|double|float32|float64|Float|Double)\b[^;]*\b`, n, `\b|\b`, n, `\s*:?=\s*(?:float(?:32|64)\(|math\.)`])
	some j in numbers.range(max([0, i - 60]), i)
	contains(lines[j], v)
	regex.match(re, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	_candidate_file(content, lang)
	lines := split(content, "\n")
	some i, line in lines
	_cheap(line)
	regex.match(_line_filter, line)
	not helpers.is_comment_line(line)
	c := _code(line)
	_hit(lines, i, lang, c)
	finding := {
		"rule_id": metadata.id,
		"message": "This comparison is always true, so the check it was meant to make never rejects anything (and a loop it controls never ends)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Substring tests before any regular expression on a line.
_cheap(line) if contains(line, "||")

_cheap(line) if contains(line, "=")

# ── whole-file gates ─────────────────────────────────────────────────────
# Each gate starts with a literal, so a large file is searched rather than
# stepped through, and only a file holding a candidate is split into lines.

_size_gates := {
	"go": [`len\([^\n;]*>=\s*0`],
	"java": [`\.length[^\n;]*>=\s*0`, `\.size\(\)\s*>=\s*0`],
	"c": [`sizeof[^\n;]*>=\s*0`, `strlen[^\n;]*>=\s*0`, `wcslen[^\n;]*>=\s*0`, `\.size\(\)\s*>=\s*0`, `\.length\(\)\s*>=\s*0`],
}

_candidate_file(content, lang) if {
	some re in _size_gates[lang]
	regex.match(re, content)
}

_candidate_file(content, _) if {
	some s in {"0 <=", "0<="}
	contains(content, s)
	regex.match(`0\s*<=\s*(?:len\(|sizeof|strlen|wcslen|[\w.\[\]()]*\.(?:length|size))`, content)
}

# `!= A || v != B` with A != B, where the file also has `v != A ||`.
_candidate_file(content, _) if {
	contains(content, "||")
	some m in regex.find_all_string_submatch_n(concat("", [`!=\s*(`, _lit, `)\s*\|\|\s*([\w.]+)\s*!=\s*(`, _lit, `)`]), content, -1)
	m[1] != m[3]
	regex.match(concat("", [regex.replace(m[2], `\.`, `\.`), `\s*!=\s*`, regex.replace(m[1], `([.\-])`, `\$1`), `\s*\|\|`]), content)
}

# `|| v < N` where the file also has `v > M || v <`.
_candidate_file(content, _) if {
	contains(content, "||")
	some m in regex.find_all_string_submatch_n(`\|\|\s*([\w.]+)\s*[<>]=?\s*-?\d`, content, -1)
	v := regex.replace(m[1], `\.`, `\.`)
	regex.match(concat("", [v, `\s*[<>]=?\s*-?\d[\d.]*\s*\|\|\s*`, v, `\s*[<>]`]), content)
}

# `v == v`, `v >= v`: the right-hand operand repeats the left.
_candidate_file(content, _) if {
	some op in {"==", ">=", "<="}
	contains(content, op)
	names := {m[1] | some m in regex.find_all_string_submatch_n(concat("", [op, `\s*([A-Za-z_][\w.]*)\s*(?:[)&|;?:,{]|$)`]), content, -1)}
	some name in names
	v := regex.replace(name, `\.`, `\.`)
	regex.match(concat("", [v, `\s*`, op, `\s*`, v, `\b`]), content)
}

# An unsigned declaration whose name the file also compares >= 0.
_c_decls := [
	`unsigned(?:\s+(?:int|long|short|char))*\s+\**\s*([A-Za-z_]\w*)`,
	`size_t\s+\**\s*([A-Za-z_]\w*)`,
	`uint(?:8|16|32|64)?_t\s+\**\s*([A-Za-z_]\w*)`,
	`u_int(?:8|16|32|64)?(?:_t)?\s+\**\s*([A-Za-z_]\w*)`,
]

_candidate_file(content, "c") if {
	contains(content, ">=")
	names := {m[1] |
		some re in _c_decls
		some m in regex.find_all_string_submatch_n(re, content, -1)
	}
	some v in names
	some sfx in {" >= 0", ">= 0", ">=0", " >=0"}
	contains(content, concat("", [v, sfx]))
}

_candidate_file(content, "go") if {
	contains(content, "uint")
	contains(content, ">=")
}
