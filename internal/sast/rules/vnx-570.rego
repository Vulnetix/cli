# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_570

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-570",
	"name": "Expression is Always False",
	"description": "A comparison that can never be true, in C, C++, Go and Java, so the branch it guards is dead and the check it was meant to make (a bounds, error or range check) never happens. Four shapes are reported: a length or size compared below zero (len(x) < 0, s.length() < 0, a.length < 0, list.size() < 0, sizeof(x) < 0, strlen(s) < 0, and 0 > len(x)); an unsigned variable compared below zero (a C/C++ unsigned, size_t or uintN_t variable, or a Go uint variable, declared above in the same file with no later signed redeclaration); the same operand required to equal two different constants at once (x == 1 && x == 2, kind == A && kind == B); and an empty numeric range on one operand (x > 10 && x < 5). Not reported: a constant condition written on purpose (if (false), if (0), #if 0, do { } while (0)), a cast operand ((int)n < 0), a member of another object (p->n), comparisons inside string literals or comments, and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-570/",
	"languages": ["c", "cpp", "go", "java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [570],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["always-false", "dead-code", "cwe-570"],
}

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

# Whole-file gates: a shape that can only be a hit, or an operand compared
# below zero that the file also declares unsigned.

_line_filter := `<\s*0|0\s*>|==[^&]*&&[^=]*==|[<>]=?\s*-?\d[^&]*&&[^<>]*[<>]`

# String and character literals blanked, trailing // comment removed.
_code(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), `//.*$`, "")

# ── length/size below zero ───────────────────────────────────────────────

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

_hit(_, _, lang, c) if regex.match(concat("", [`(?:`, _size_expr[lang], `)\s*<\s*0\s*(?:[)&|;?:,{]|$)`]), c)

_hit(_, _, lang, c) if regex.match(concat("", [`(?:^|[^\w.])0\s*>\s*`, _size_head[lang]]), c)

# ── unsigned variable below zero ─────────────────────────────────────────

_unsigned_decl := {
	"c": `\b(?:unsigned(?:\s+(?:int|long|short|char))*|size_t|uint(?:8|16|32|64)?_t|u_?int(?:8|16|32|64)?|UINT|DWORD|WORD|ULONG)\s+\**\s*NAME\s*(?:[=;,)\[]|$)`,
	"go": `\bNAME\s+uint(?:8|16|32|64|ptr)?\b|\bNAME\s*:?=\s*uint(?:8|16|32|64|ptr)?\(`,
}

_signed_decl := {
	"c": `\b(?:int|long|short|signed|ssize_t|off_t|ptrdiff_t|intptr_t|int(?:8|16|32|64)_t|float|double|auto|char)\s+\**\s*NAME\b`,
	"go": `\bNAME\s+(?:int(?:8|16|32|64)?|float(?:32|64))\b|\bNAME\s*(?:,\s*\w+\s*)*:=\s*[^u]|,\s*NAME\s*(?:,\s*\w+\s*)*:=`,
}

# The operand compared below zero is a plain variable whose nearest
# declaration above is unsigned.
_hit(lines, i, lang, c) if {
	lang in {"c", "go"}
	contains(c, "0")
	some cm in regex.find_all_string_submatch_n(`(?:^|[(\s!&|,;])([A-Za-z_]\w*)\s*<\s*0\s*(?:[)&|;?:,{]|$)`, c, -1)
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

# ── one operand equal to two constants ───────────────────────────────────

_lit := `(?:-?\d+(?:\.\d+)?[uUlLfF]*|0[xX][0-9a-fA-F]+|''|""|true|false|nil|null|NULL|(?:[A-Z]\w*\.)?[A-Z][A-Z0-9_]+)`

_lhs_prefix := `(?:^|[(,;?:=]|&&|\|\||\breturn\b|\bif\b)\s*`

_hit(_, _, _, c) if {
	contains(c, "&&")
	re := concat("", [_lhs_prefix, `([\w.]+)\s*==\s*(`, _lit, `)\s*&&\s*([\w.]+)\s*==\s*(`, _lit, `)\s*(?:[)&|;?:{]|$)`])
	some m in regex.find_all_string_submatch_n(re, c, -1)
	m[1] == m[3]
	m[2] != m[4]
	not "''" in {m[2], m[4]}
	not "\"\"" in {m[2], m[4]}
}

# ── empty numeric range ──────────────────────────────────────────────────

_num := `(-?\d+(?:\.\d+)?)`

# x > a && x < b, x >= a && x <= b ...
_hit(_, _, _, c) if {
	contains(c, "&&")
	re := concat("", [_lhs_prefix, `([\w.]+)\s*(>=?)\s*`, _num, `\s*&&\s*([\w.]+)\s*(<=?)\s*`, _num, `\s*(?:[)&|;?:{]|$)`])
	some m in regex.find_all_string_submatch_n(re, c, -1)
	m[1] == m[4]
	_empty(m[2], to_number(m[3]), m[5], to_number(m[6]))
}

# x < b && x > a
_hit(_, _, _, c) if {
	contains(c, "&&")
	re := concat("", [_lhs_prefix, `([\w.]+)\s*(<=?)\s*`, _num, `\s*&&\s*([\w.]+)\s*(>=?)\s*`, _num, `\s*(?:[)&|;?:{]|$)`])
	some m in regex.find_all_string_submatch_n(re, c, -1)
	m[1] == m[4]
	_empty(m[5], to_number(m[6]), m[2], to_number(m[3]))
}

_empty(_, lo, _, hi) if hi < lo

_empty(">", lo, _, hi) if hi == lo

_empty(_, lo, "<", hi) if hi == lo

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
		"message": "This comparison can never be true, so the branch it guards never runs and the check it was meant to make does not happen",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Substring tests before any regular expression on a line.
_cheap(line) if contains(line, "&&")

_cheap(line) if contains(line, "< 0")

_cheap(line) if contains(line, "<0")

_cheap(line) if contains(line, "0 >")

_cheap(line) if contains(line, "0>")

# Each gate starts with a literal, so the scan of a large file is a fast
# substring search rather than a regular expression tried at every offset.
_size_gates := {
	"go": [`len\([^\n;]*<\s*0`],
	"java": [`\.length[^\n;]*<\s*0`, `\.size\(\)\s*<\s*0`],
	"c": [`sizeof[^\n;]*<\s*0`, `strlen[^\n;]*<\s*0`, `wcslen[^\n;]*<\s*0`, `\.size\(\)\s*<\s*0`, `\.length\(\)\s*<\s*0`],
}

# `== A && v == B` with A != B, where the file also has `v == A &&`.
_candidate_file(content, _) if {
	contains(content, "&&")
	some m in regex.find_all_string_submatch_n(concat("", [`==\s*(`, _lit, `)\s*&&\s*([\w.]+)\s*==\s*(`, _lit, `)`]), content, -1)
	m[1] != m[3]
	regex.match(concat("", [regex.replace(m[2], `\.`, `\.`), `\s*==\s*`, regex.replace(m[1], `([.\-])`, `\$1`), `\s*&&`]), content)
}

# `&& v < N` where the file also has `v > M &&` (either direction).
_candidate_file(content, _) if {
	contains(content, "&&")
	some m in regex.find_all_string_submatch_n(`&&\s*([\w.]+)\s*[<>]=?\s*-?\d`, content, -1)
	v := regex.replace(m[1], `\.`, `\.`)
	regex.match(concat("", [v, `\s*[<>]=?\s*-?\d[\d.]*\s*&&\s*`, v, `\s*[<>]`]), content)
}

_candidate_file(content, lang) if {
	some re in _size_gates[lang]
	regex.match(re, content)
}

_candidate_file(content, _) if {
	some s in {"0 >", "0>"}
	contains(content, s)
	regex.match(`0\s*>\s*(?:len\(|sizeof|strlen|wcslen|[\w.\[\]()]*\.(?:length|size))`, content)
}

# An unsigned declaration whose name the file also compares below zero. Each
# expression starts with a literal so the file is searched, not stepped.
_c_decls := [
	`unsigned(?:\s+(?:int|long|short|char))*\s+\**\s*([A-Za-z_]\w*)`,
	`size_t\s+\**\s*([A-Za-z_]\w*)`,
	`uint(?:8|16|32|64)?_t\s+\**\s*([A-Za-z_]\w*)`,
	`u_int(?:8|16|32|64)?(?:_t)?\s+\**\s*([A-Za-z_]\w*)`,
]

_candidate_file(content, "c") if {
	some s in {"< 0", "<0"}
	contains(content, s)
	names := {m[1] |
		some re in _c_decls
		some m in regex.find_all_string_submatch_n(re, content, -1)
	}
	some v in names
	some sfx in {" < 0", "< 0", "<0", " <0"}
	contains(content, concat("", [v, sfx]))
}

_candidate_file(content, "go") if {
	contains(content, "uint")
	some s in {"< 0", "<0"}
	contains(content, s)
}
