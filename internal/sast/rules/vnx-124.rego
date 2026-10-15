# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_124

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-124",
	"name": "Buffer Underwrite ('Buffer Underflow')",
	"description": "Reports C/C++ writes that land before the start of a buffer when a length is zero or negative: (1) buf[strlen(buf) - 1] = ... with no check that the string is non-empty (the fgets newline-strip idiom; an empty line writes buf[-1]); (2) buf[len - 1] = ... where len was assigned from strlen() a few lines above and is never compared before the write; (3) a terminator write buf[n] = '\\0' (or 0, NUL, '\\n', '\\r'; also buf[n - 1]) where n is the return value of read(), recv(), recvfrom(), recvmsg(), pread() or readlink(), which is -1 on error, and n is never compared before the write; (4) a write through a literal negative index into an array declared in the same function. Not reported: guarded writes (len > 0, *s &&, n < 0, n == -1, an assignment inside a while/if comparison), reads such as s[n - 1] == '\\n', negative indexes on pointers into the middle of an allocation (sds-style headers), strcspn()-based stripping, comments. Flows across functions are out of scope.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-124/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [124],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["buffer-underwrite", "memory", "cwe-124"],
}

_exts := {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}

_is_c(path) if {
	some ext in _exts
	endswith(path, ext)
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# A comparison or truth test of identifier v.
_compares(line, v) if regex.match(concat("", [`\b`, v, `\s*(>|>=|<|<=|==|!=|&&|\|\|)|(>|<|==|!=|>=|<=|!)\s*`, v, `\b|\(\s*`, v, `\s*\)\s*(\{|$)`]), line)

_guarded(lines, from, to, v) if {
	some k in numbers.range(from, to)
	not helpers.is_comment_line(lines[k])
	_compares(lines[k], v)
}

# Whole-file literal gates, one per check (regexes over a whole C file are
# far slower than substring searches).
_gate1(content) if contains(content, "[strlen(")

_gate1(content) if contains(content, "[ strlen(")

_gate2(content) if contains(content, "- 1]")

_gate2(content) if contains(content, "-1]")

_gate3(content) if {
	some fn in {"read(", "recv(", "recvfrom(", "recvmsg(", "readlink("}
	contains(content, fn)
	some term in {"] = '\\0'", "]='\\0'", "] = 0;", "]=0;", "] = NUL"}
	contains(content, term)
}

_gate4(content) if contains(content, "[-")

_gate4(content) if contains(content, "[ -")




# (1) buf[strlen(buf) - 1] = x
findings contains f if {
	some path, content in input.file_contents
	_is_c(path)
	_gate1(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "strlen")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_][\w\.>-]*)\s*\[\s*strlen\s*\(\s*([A-Za-z_][\w\.>-]*)\s*\)\s*-\s*1\s*\]\s*=[^=]`, line, 1)[0]
	m[1] == m[2]
	v := m[1]
	win := helpers.code_window(lines, i, 3, 0)
	not regex.match(concat("", [`(\(|&&|\|\||!)\s*\*\s*`, v, `\b|\*\s*`, v, `\s*(&&|!=|==)|\b`, v, `\s*\[\s*0\s*\]|strn?len\s*\(\s*`, v, `\s*\)\s*(>|>=|!=|&&)`]), win)
	f := _finding(path, i, line, sprintf("%s[strlen(%s) - 1] is written without checking that the string is non-empty: an empty string writes one byte before the buffer; check the length first or strip with strcspn()", [v, v]))
}

# (2) len = strlen(buf); buf[len - 1] = x
findings contains f if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "strlen(")
	_gate2(content)
	lines := split(content, "\n")
	some j, def in lines
	contains(def, "strlen")
	not helpers.is_comment_line(def)
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?strlen\s*\(\s*([A-Za-z_][\w\.>-]*)\s*\)\s*;`, def, 1)[0]
	l := m[1]
	buf := m[2]
	some i in numbers.range(j + 1, min([count(lines) - 1, j + 10]))
	sink := lines[i]
	regex.match(concat("", [`\b`, buf, `\s*\[\s*`, l, `\s*-\s*1\s*\]\s*=[^=]`]), sink)
	not helpers.is_comment_line(sink)
	not _guarded(lines, j + 1, i, l)
	f := _finding(path, i, sink, sprintf("%s[%s - 1] is written but %s comes from strlen() and is never checked for zero: an empty string writes before the buffer", [buf, l, l]))
}

# (3) n = read(...); buf[n] = x  (n is -1 on error)
findings contains f if {
	some c in _read_cands
	[path, j] := c
	lines := _read_lines[path]
	def := lines[j]
	regex.match(`\b(read|recv|recvfrom|recvmsg|pread|readlink)\s*\(`, def)
	not helpers.is_comment_line(def)
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?(read|recv|recvfrom|recvmsg|pread|readlink)\s*\(`, def, 1)[0]
	n := m[1]
	# `if ((n = read(...)) <= 0)` and `while ((n = read(...)) > 0)` check on the spot
	not regex.match(`\)\s*\)\s*(<|>|==|!=|<=|>=)`, def)
	some i in numbers.range(j + 1, min([count(lines) - 1, j + 10]))
	sink := lines[i]
	mm := regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_][\w\.>-]*)\s*\[\s*`, n, `\s*(-\s*1\s*)?\]\s*=\s*(?:'\\0'|0|NUL|'\\n'|'\\r')\s*;`]), sink, 1)[0]
	not helpers.is_comment_line(sink)
	not _guarded(lines, j + 1, i, n)
	f := _finding(path, i, sink, sprintf("%s is indexed with %s, the unchecked return value of %s(): on error it is -1 and the write lands before the buffer; check %s < 0 first", [mm[1], n, m[2], n]))
}

# (4) literal negative index into a declared array
findings contains f if {
	some c in _neg_cands
	[path, i] := c
	lines := _neg_lines[path]
	line := lines[i]
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`(?:^|[^\w\)\]])([A-Za-z_]\w*)\s*\[\s*-\s*\d+\s*\]\s*=[^=]`, line, 1)[0]
	v := m[1]
	some k in numbers.range(max([0, i - 50]), i - 1)
	regex.match(concat("", [`^\s*(?:static\s+|const\s+|unsigned\s+|signed\s+)*[A-Za-z_]\w*\s+`, v, `\s*\[\s*\w+\s*\]\s*(;|=)`]), lines[k])
	f := _finding(path, i, line, sprintf("Write to %s at a negative index: %s is an array, so this writes before its first element", [v, v]))
}

# Candidate lines located by substring offset rather than by testing every
# line of every C file: [path, line index].
_line_of(content, off) := count(indexof_n(substring(content, 0, off), "\n"))

_read_cands contains [path, _line_of(content, off)] if {
	some path, content in input.file_contents
	_is_c(path)
	_gate3(content)
	some lit in {"read(", "recv(", "recvfrom(", "recvmsg(", "readlink("}
	some off in indexof_n(content, lit)
}

_read_lines := {path: split(input.file_contents[path], "\n") | some c in _read_cands; path := c[0]}

_neg_cands contains [path, _line_of(content, off)] if {
	some path, content in input.file_contents
	_is_c(path)
	_gate4(content)
	some lit in {"[-", "[ -"}
	some off in indexof_n(content, lit)
}

_neg_lines := {path: split(input.file_contents[path], "\n") | some c in _neg_cands; path := c[0]}
