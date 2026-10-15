# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_681

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-681",
	"name": "Incorrect Conversion between Numeric Types",
	"description": "A length, size or file offset is converted to a type too narrow to hold it, so a large value silently wraps and the truncated number is then used for a copy, an allocation or a seek. Reported in C and C++: a variable declared as an 8- or 16-bit type (char, short, uint8_t, uint16_t, BYTE, WORD, USHORT and similar) initialised from strlen, wcslen, strnlen, ftell, ftello, lseek, read, recv, recvfrom, fread or a C++ .size()/.length() call, or such a call cast to one of those types; an int or unsigned int initialised from, or a cast to int of, ftell/ftello/lseek (file offsets beyond 2 GiB); and (c = getc(fp)) != EOF, getchar or fgetc in the same loop test, where c is declared char in the 40 lines above, so the int result is narrowed before the EOF test (byte 0xFF ends the loop, or EOF is never seen). A plain char c = getchar() without the EOF test is not reported. Reported in Java: a cast to int, short, byte or char of a long-valued size or time: Files.size(), getContentLengthLong(), getSize() and getCompressedSize() (ZipEntry, MultipartFile, Part), length() on a receiver named like a file or a new File(...), size()/position() on a channel, System.currentTimeMillis() and System.nanoTime(). Not reported: int from strlen (or the (int)strlen idiom for printf precision), conversions to size_t, long, off_t or uint32_t and wider, Math.toIntExact, casts of int-valued size()/length() calls on collections and strings, casts of arithmetic results, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-681/",
	"languages": ["c", "cpp", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [681],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["numeric-truncation", "cwe-681"],
}

_is_c(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_blank(s) := regex.replace(regex.replace(s, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_narrow := `(?:unsigned\s+short(?:\s+int)?|signed\s+short|short(?:\s+int)?|unsigned\s+char|signed\s+char|char|u?int8_t|u?int16_t|u8|u16|s8|s16|__u8|__u16|BYTE|WORD|USHORT|UCHAR|guint8|guint16|gushort|guchar)`

_c_size_src := `(?:(?:^|[^\w.>])(?:strlen|wcslen|strnlen|ftell|ftello|lseek|lseek64|read|recv|recvfrom|fread)\s*\(|\.(?:size|length)\s*\(\s*\))`

_c_off_src := `(?:^|[^\w.>])(?:ftell|ftello|lseek|lseek64|_ftelli64)\s*\(`

_c_size_call := `(?:\b(?:strlen|wcslen|strnlen|ftell|ftello|lseek|lseek64|read|recv|recvfrom|fread)\s*\(|[\w\]\)]\.(?:size|length)\s*\(\s*\))`

_c_off_call := `\b(?:ftell|ftello|lseek|lseek64|_ftelli64)\s*\(`

_c_res := [
	concat("", [`^\s*(?:(?:const|static|register)\s+)*`, _narrow, `\s+\w+\s*=[^=;\[]*?`, _c_size_src]),
	concat("", [`\(\s*`, _narrow, `\s*\)\s*`, _c_size_call]),
	concat("", [`^\s*(?:(?:const|static|register)\s+)*(?:unsigned(?:\s+int)?|signed(?:\s+int)?|int)\s+\w+\s*=[^=;\[]*?`, _c_off_src]),
	concat("", [`\(\s*(?:unsigned\s+)?int\s*\)\s*`, _c_off_call]),
]

_j_src := `(?:Files\.size\s*\(|\.getContentLengthLong\s*\(\s*\)|\.getSize\s*\(\s*\)|\.getCompressedSize\s*\(\s*\)|\b\w*(?i:file)\w*\.length\s*\(\s*\)|new\s+File\s*\([^()]*\)\.length\s*\(\s*\)|\b\w*(?i:channel)\w*\.(?:size|position)\s*\(\s*\)|System\.(?:currentTimeMillis|nanoTime)\s*\(\s*\))`

_j_re := concat("", [`\(\s*(?:int|short|byte|char)\s*\)\s*(?:[\w.]+(?:\([^()]*\))?)?`, _j_src])

_c_line := `strlen|wcslen|strnlen|ftell|lseek|read\s*\(|recv|\.size\s*\(|\.length\s*\(`

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(_c_line, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_c_line, line)
	not helpers.is_comment_line(line)
	code := _blank(line)
	some re in _c_res
	regex.match(re, code)
	finding := _finding(path, i, line)
}

# (c = getc(fp)) != EOF where c is declared char: the int result is narrowed
# before the EOF test, so byte 0xFF ends the loop early (signed char) or EOF
# is never seen (unsigned char).
_eof_re := `\(\s*(\w+)\s*=\s*(?:getchar|fgetc|getc|getc_unlocked|fgetc_unlocked|getchar_unlocked)\s*\([^()]*\)\s*\)\s*!=\s*EOF\b`

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "EOF")
	regex.match(`(?:getchar|getc|fgetc)\w*\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "EOF")
	not helpers.is_comment_line(line)
	some g in regex.find_all_string_submatch_n(_eof_re, _blank(line), 1)
	v := g[1]
	win := helpers.code_window(lines, i, 40, 0)
	regex.match(concat("", [`(?m)^\s*(?:(?:static|register|signed|unsigned)\s+)*char\s+(?:[^;=(){}*]*,\s*)?`, v, `\s*[;=,]`]), win)
	not regex.match(concat("", [`(?m)^\s*(?:(?:static|register|const|unsigned|signed)\s+)*(?:int|wint_t|long)\s+(?:[^;(){}]*,\s*)?`, v, `\s*[;=,]`]), win)
	finding := _finding(path, i, line)
}

_j_line :=`\(\s*(?:int|short|byte|char)\s*\)`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(_j_line, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_j_line, line)
	not helpers.is_comment_line(line)
	regex.match(_j_re, _blank(line))
	finding := _finding(path, i, line)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "A size, length or file offset is converted to a narrower numeric type and can silently truncate. Keep it in size_t/off_t/long, or check the range (Math.toIntExact in Java) before narrowing",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
