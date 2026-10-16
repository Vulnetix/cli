# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_192

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-192",
	"name": "Integer Coercion Error",
	"description": "A number parsed from text is forced into a narrower or differently signed integer type without a range check, so an out-of-range input silently truncates or flips sign and a later size, index, port or limit check sees a different value from the one supplied. Reported: Go conversions int8/int16/int32/rune/uint8/byte/uint16/uint32/uint/uint64(v) of a value from strconv.Atoi, ParseInt or ParseUint whose bit size is wider than the target or whose sign the target drops; Java casts (byte)/(short)/(char)/(int) of Integer.parseInt/valueOf, Long.parseLong/valueOf or Short.parseShort, inline or through a variable, and a narrowing byteValue()/shortValue()/intValue() on the boxed result (Integer.valueOf(s).byteValue()); C and C++ declarations of a narrower or unsigned type (char, short, int8_t..uint32_t, unsigned, size_t) initialised from atoi/atol/atoll/strtol/strtoul/strtoll/strtoull, and casts of such a variable to a narrower or unsigned type. Not reported: a conversion preceded by a comparison of the value (limit > math.MaxInt32, level > Byte.MAX_VALUE, v > UCHAR_MAX), Math.toIntExact, conversions to the same or a wider type (int64(n), (long) parseInt, int i = atoi(s)), ParseInt/ParseUint whose bit size already fits the target, and comments. JavaScript, PHP, Python and Ruby were dropped: their integers do not coerce this way.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-192/",
	"languages": ["go", "java", "c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [192],
	"capec": ["CAPEC-128"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["integer-coercion", "truncation", "sign-conversion", "cwe-192"],
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}
_needles := {
	"go": {"strconv.Atoi", "strconv.ParseInt", "strconv.ParseUint"},
	"java": {"Integer.parseInt", "Integer.valueOf", "Long.parseLong", "Long.valueOf", "Short.parseShort"},
	"c": {"atoi(", "atol(", "atoll(", "strtol(", "strtoul(", "strtoll(", "strtoull("},
}

_has_needle(s, lang) if {
	some n in _needles[lang]
	contains(s, n)
}





# [width, signed]
_go_types := {
	"int8": [8, true], "int16": [16, true], "int32": [32, true], "rune": [32, true],
	"uint8": [8, false], "byte": [8, false], "uint16": [16, false], "uint32": [32, false],
	"uint": [64, false], "uint64": [64, false],
}

_java_types := {"byte": [8, true], "short": [16, true], "char": [16, false], "int": [32, true]}

_java_sources := {
	"Integer.parseInt": [32, true], "Integer.valueOf": [32, true],
	"Long.parseLong": [64, true], "Long.valueOf": [64, true],
	"Short.parseShort": [16, true],
}

_c_sources := {
	"atoi": [32, true], "atol": [64, true], "atoll": [64, true], "strtol": [64, true],
	"strtoll": [64, true], "strtoul": [64, false], "strtoull": [64, false],
}

_c_type(t) := w if {
	norm := regex.replace(trim_space(t), `\s+`, " ")
	w := {
		"char": [8, true], "signed char": [8, true], "unsigned char": [8, false],
		"short": [16, true], "short int": [16, true], "unsigned short": [16, false], "unsigned short int": [16, false],
		"int": [32, true], "signed": [32, true], "signed int": [32, true], "unsigned": [32, false], "unsigned int": [32, false],
		"int8_t": [8, true], "uint8_t": [8, false], "int16_t": [16, true], "uint16_t": [16, false],
		"int32_t": [32, true], "uint32_t": [32, false], "uint64_t": [64, false], "size_t": [64, false],
		"u_char": [8, false], "u_short": [16, false], "u_int": [32, false], "BYTE": [8, false], "WORD": [16, false], "DWORD": [32, false],
	}[norm]
}

_c_type_re := `unsigned\s+short(?:\s+int)?|unsigned\s+char|unsigned\s+int|signed\s+char|short(?:\s+int)?|unsigned|signed(?:\s+int)?|u?int(?:8|16|32|64)_t|size_t|u_char|u_short|u_int|BYTE|WORD|DWORD|char|int`

# The target loses information: narrower, or drops the sign.
_loses(src, dst) if dst[0] < src[0]

_loses(src, dst) if {
	src[1]
	not dst[1]
}

# ── Sources: the variable a parse result lands in ────────────────────────

_go_bits(fn, _) := 64 if fn == "Atoi"

_go_bits(fn, args) := b if {
	fn != "Atoi"
	parts := split(args, ",")
	count(parts) == 3
	n := to_number(trim_space(parts[2]))
	b := _bits_or_64(n)
}

_go_bits(fn, args) := 64 if {
	fn != "Atoi"
	parts := split(args, ",")
	count(parts) == 3
	not regex.match(`^\s*\d+\s*$`, parts[2])
}

_bits_or_64(0) := 64

_bits_or_64(n) := n if n != 0

_source(line, "go") := [m[0][1], [_go_bits(m[0][2], m[0][3]), m[0][2] != "ParseUint"]] if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*,\s*\w+\s*:?=\s*strconv\.(Atoi|ParseInt|ParseUint)\s*\((.*)\)\s*$`, line, 1)
	count(m) > 0
}

_source(line, "java") := [m[0][1], _java_sources[m[0][2]]] if {
	m := regex.find_all_string_submatch_n(`^\s*(?:final\s+)?(?:int|long|short|Integer|Long|Short|var)\s+([A-Za-z_]\w*)\s*=\s*((?:Integer|Long|Short)\.(?:parseInt|valueOf|parseLong|parseShort))\s*\(`, line, 1)
	count(m) > 0
}

_source(line, "c") := [m[0][1], _c_sources[m[0][2]]] if {
	m := regex.find_all_string_submatch_n(`^\s*(?:const\s+)?(?:long\s+long|unsigned\s+long\s+long|unsigned\s+long|long|intmax_t|int64_t|ssize_t|int)\s+([A-Za-z_]\w*)\s*=\s*(?:(?:std)?::)?(atoi|atol|atoll|strtol|strtoll|strtoul|strtoull)\s*\(`, line, 1)
	count(m) > 0
}

# ── Sinks: a narrowing use of that variable ──────────────────────────────

_narrowing(line, "go", v, src) if {
	m := regex.find_all_string_submatch_n(concat("", [`\b(int8|int16|int32|rune|uint8|byte|uint16|uint32|uint|uint64)\s*\(\s*`, v, `\s*\)`]), line, -1)
	some k
	_loses(src, _go_types[m[k][1]])
}

_narrowing(line, "java", v, src) if {
	m := regex.find_all_string_submatch_n(concat("", [`\(\s*(byte|short|char|int)\s*\)\s*\(?\s*`, v, `\b`]), line, -1)
	some k
	_loses(src, _java_types[m[k][1]])
}

_narrowing(line, "c", v, src) if {
	m := regex.find_all_string_submatch_n(concat("", [`\(\s*(`, _c_type_re, `)\s*\)\s*\(?\s*`, v, `\b`]), line, -1)
	some k
	_loses(src, _c_type(m[k][1]))
}

# A comparison of v, or a checked conversion, between source and sink.
_checked(lines, j, i, v) if {
	some k in numbers.range(j, i)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(concat("", [`\b`, v, `\b`]), l)
	regex.match(`[<>]=?\s*[\w(.-]|\bmath\.(?:Max|Min)|MAX_VALUE|MIN_VALUE|toIntExact|_MAX\b|_MIN\b|\bclamp`, replace(replace(l, "->", ""), "<<", ""))
}

_msg := "A parsed number is converted to a narrower or unsigned type without a range check, so an out-of-range input truncates or flips sign. Check the value against the target type's limits first (or parse with the target's bit size)"

# One pass: every line that parses a number is a source; the finding is the
# line itself (an inline narrowing) or a later narrowing of its variable.
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_needle(content, lang)
	srcs := {m[0] | some m in regex.find_all_string_submatch_n(_src_line_re[lang], content, -1)}
	count(srcs) > 0
	lines := split(content, "\n")
	some j, src_line in lines
	src_line in srcs
	not helpers.is_comment_line(src_line)
	some i in _hits(lines, j, src_line, lang)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}

# The lines that parse a number, found in one pass over the content and then
# matched by equality, so other lines cost one set lookup.
_src_line_re := {
	"go": `(?m)^.*\bstrconv\.(?:Atoi|ParseInt|ParseUint)\b.*$`,
	"java": `(?m)^.*\b(?:Integer|Long|Short)\.(?:parseInt|valueOf|parseLong|parseShort)\b.*$`,
	"c": `(?m)^.*\b(?:atoi|atol|atoll|strtol|strtoll|strtoul|strtoull)\s*\(.*$`,
}

_hits(lines, j, src_line, lang) := array.concat([k | some k in [j]; _inline(src_line, lang)], [i |
	[v, src] := _source(src_line, lang)
	some i in numbers.range(j + 1, min([count(lines) - 1, j + 30]))
	line := lines[i]
	contains(line, v)
	not helpers.is_comment_line(line)
	_narrowing(line, lang, v, src)
	not _checked(lines, j + 1, i - 1, v)
	not _checked_same_line(line, v)
])

_checked_same_line(line, v) if regex.match(`\?|\bmin\s*\(|\bmax\s*\(`, line)

_inline(line, "java") if {
	m := regex.find_all_string_submatch_n(`\(\s*(byte|short|char|int)\s*\)\s*\(?\s*((?:Integer|Long|Short)\.(?:parseInt|valueOf|parseLong|parseShort))\s*\(`, line, -1)
	some k
	_loses(_java_sources[m[k][2]], _java_types[m[k][1]])
}

# Integer.valueOf(s).byteValue(), Long.valueOf(s).intValue(): a narrowing
# accessor on the boxed parse result.
_inline(line, "java") if {
	contains(line, "Value(")
	m := regex.find_all_string_submatch_n(`\b((?:Integer|Long|Short)\.(?:parseInt|valueOf|parseLong|parseShort))\s*\((?:[^()]|\([^()]*\))*\)\s*\.\s*(byte|short|int)Value\s*\(`, line, -1)
	some k
	_loses(_java_sources[m[k][1]], _java_types[m[k][2]])
}

_inline(line, "c") if {
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:const\s+|static\s+)*(`, _c_type_re, `)\s+([A-Za-z_]\w*)\s*=\s*(?:\(\s*\w+\s*\)\s*)?(?:(?:std)?::)?(atoi|atol|atoll|strtol|strtoll|strtoul|strtoull)\s*\(`]), line, 1)
	count(m) > 0
	_loses(_c_sources[m[0][3]], _c_type(m[0][1]))
}
