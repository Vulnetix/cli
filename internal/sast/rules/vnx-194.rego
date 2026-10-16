# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_194

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-194",
	"name": "Unexpected Sign Extension",
	"description": "A signed byte is widened to int and keeps its sign, so bytes 0x80-0xFF become negative numbers. Reported: in C and C++, a <ctype.h> classifier or converter (isalnum, isalpha, isascii, isblank, iscntrl, isdigit, isgraph, islower, isprint, ispunct, isspace, isupper, isxdigit, tolower, toupper, std:: forms included) called with a plain char: a variable declared char, or *p / p[i] where p is declared char * or char[] (const included); a negative value there is undefined behaviour and indexes the classification table out of bounds. In Java, a line that shifts and combines bytes (<<, |) or multiplies one by 256 and adds the next (b[0] * 256 + b[1]) where an element of an array declared byte[] is used without & 0xff (or Byte.toUnsignedInt), which smears the sign bit across the upper bits of the result ((b[0] << 8) | b[1]). Not reported: an argument cast to (unsigned char), variables declared unsigned char or int (a getc() result), masked bytes, an unmasked byte shifted by 24 into the top of an int, arrays of other types, and comments. Go and the other languages listed before were dropped: Go has no implicit sign extension, and JavaScript, PHP, Python and Ruby have no signed byte type.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-194/",
	"languages": ["c", "cpp", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [194],
	"capec": ["CAPEC-128"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["sign-extension", "integer", "ctype", "cwe-194"],
}

_is_c(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_ctype := `(?:isalnum|isalpha|isascii|isblank|iscntrl|isdigit|isgraph|islower|isprint|ispunct|isspace|isupper|isxdigit|tolower|toupper)`

_ctype_line_re := `(?m)^.*\b(?:is(?:al(?:num|pha)|ascii|blank|cntrl|digit|graph|lower|print|punct|space|upper|xdigit)|to(?:lower|upper))\s*\(.*$`

# A call whose argument is *p, p[i], c (optionally with ++/--), uncast.
_call_re := concat("", [`\b(?:std::)?`, _ctype, `\s*\(\s*(\*\s*)?([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*(?:\+\+|--)?\s*\)`])

_msg_c := "A plain char is passed to a <ctype.h> function; bytes 0x80-0xFF are negative there, which is undefined behaviour and reads outside the classification table. Cast the argument: isspace((unsigned char)*p)"

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "char")
	regex.match(_call_re, content)
	srcs := {m[0] | some m in regex.find_all_string_submatch_n(_ctype_line_re, content, -1)}
	count(srcs) > 0
	lines := split(content, "\n")
	some i, line in lines
	line in srcs
	not _comment(line)
	code := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)
	some m in regex.find_all_string_submatch_n(_call_re, code, -1)
	_plain_char(_nearest_decl(lines, i, m[2]), m[2], _kind(m))
	finding := {
		"rule_id": metadata.id,
		"message": _msg_c,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_kind(m) := "ptr" if concat("", [m[1], m[3]]) != ""

_kind(m) := "val" if concat("", [m[1], m[3]]) == ""

# char *p / const char *p / char p[N]
_plain_char(decl, v, "ptr") if {
	some d in regex.find_all_string_submatch_n(concat("", [`(\w+\s+)?\bchar\s*(?:const\s*)?(?:\*\s*(?:const\s+)?|\s)`, v, `\s*[\[;,=)]`]), decl, -1)
	not regex.match(`^unsigned\s+$`, d[1])
	contains(d[0], "*")
}

_plain_char(decl, v, "ptr") if {
	some d in regex.find_all_string_submatch_n(concat("", [`(\w+\s+)?\bchar\s+`, v, `\s*\[`]), decl, -1)
	not regex.match(`^unsigned\s+$`, d[1])
}

# char c; / char *p, c; / char c = ...
_plain_char(decl, v, "val") if {
	some d in regex.find_all_string_submatch_n(concat("", [`(\w+\s+)?\bchar\s+(?:[\w\s,*\[\]]*,\s*)?`, v, `\s*[;,=)]`]), decl, -1)
	not regex.match(`^unsigned\s+$`, d[1])
	not regex.match(concat("", [`\*\s*`, v, `\s*[;,=)]$`]), d[0])
}

# ── Java: bytes combined without a mask ──────────────────────────────────

# Bytes are combined by shifting, or by b[0] * 256 + b[1].
_combines(content) if contains(content, "<<")

_combines(content) if regex.match(`\]\s*\*\s*(?:256|0x100)\b`, content)

_byte_arrays(content) := {n |
	some m in regex.find_all_string_submatch_n(`\bbyte\s*\[\s*\]\s*([A-Za-z_]\w*)|\bbyte\s+([A-Za-z_]\w*)\s*\[\s*\]`, content, -1)
	n := concat("", [m[1], m[2]])
}

# An element, with what masks it (before or after) captured when present.
_elem_re := `(toUnsigned\w*\s*\(\s*|0x[fF]{2}\s*&\s*|255\s*&\s*)?\b([A-Za-z_]\w*)\s*\[[^\[\]]+\](\s*&\s*(?:0x[fF]{2}|255)\b|\s*<<\s*24\b)?`

_msg_java := "A byte from a byte[] is combined into a wider value without & 0xff, so a byte of 0x80 or more sign-extends and sets every upper bit of the result. Mask each byte: ((b[0] & 0xff) << 8) | (b[1] & 0xff)"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	_combines(content)
	contains(content, "byte")
	arrays := _byte_arrays(content)
	count(arrays) > 0
	srcs := {m[0] | some m in regex.find_all_string_submatch_n(`(?m)^.*(?:<<|\]\s*\*\s*(?:256|0x100)\b).*$`, content, -1)}
	lines := split(content, "\n")
	some i, line in lines
	line in srcs
	regex.match(`\]\s*(?:<<|\||\+)|(?:\||\+)\s*\w+\s*\[`, line)
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_elem_re, line, -1)
	m[2] in arrays
	m[1] == ""
	m[3] == ""
	finding := {
		"rule_id": metadata.id,
		"message": _msg_java,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The closest declaration of v at or above line i (within 80 lines): the one
# in scope, so a `char c` in another function does not decide an `int c`
# here.
_decl_line_re(v) := concat("", [`\b(?:char|int|short|long|unsigned|signed|auto|size_t|ssize_t|wchar_t|wint_t|u?int\d+_t|u_char|uchar|BYTE|bool|sds)\b[^;(=]*?[\s*&]`, v, `\s*(?:[;,=)\[]|$)`])

_nearest_decl(lines, i, v) := lines[j] if {
	re := _decl_line_re(v)
	cands := [k |
		some k in numbers.range(max([0, i - 80]), i)
		contains(lines[k], v)
		regex.match(re, lines[k])
		not _comment(lines[k])
	]
	count(cands) > 0
	j := cands[count(cands) - 1]
}

# A line is a comment, except that `*p = tolower(*p);` starts with a dereference
# and helpers.is_comment_line takes a leading `*` for a block-comment body.
_comment(line) if {
	helpers.is_comment_line(line)
	not regex.match(`^\s*\*[A-Za-z_(]`, line)
}
