# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_547

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-547",
	"name": "Use of Hard-coded, Security-relevant Constants",
	"description": "A buffer's size is written out twice as a bare number: the buffer is declared with a literal length (char line[256]; uint8_t key[32]; byte[] b = new byte[512];) and a bounded read, copy or format call on that buffer, within 60 lines of its nearest declaration, passes a literal bound equal to that length (or larger than it) instead of sizeof(buf), buf.length or a named constant. A local's declaration must be in the same function as the call (no column-0 closing brace between them); a struct member (strncpy(u->name, src, 32) for char name[32];) is matched when every declaration of that member name in the file has the same length. When either number is edited and the other is not, the bound silently stops matching the buffer and the call overflows it. Reported in C and C++ for fgets, snprintf, vsnprintf, strncpy, strncat, memcpy, memmove, memset, bzero, getcwd, read, recv and fread (std:: forms and calls split over lines included), and in Java for InputStream/Reader read(buf, off, N) on a byte[] or char[] (byte[] b or C-style byte b[]) created with a literal length. Not reported: sizeof/sizeof()/.length bounds, a named constant or macro used for the bound, a smaller bound that uses part of the buffer (memcpy(buf, 'inf', 3) on a 128-byte buffer), hexadecimal lengths compared with decimal bounds, buffers whose declaration is not a literal or not in the file (parameters), comments and string literals. Other hard-coded security values (keys, passwords, IVs, iteration counts) are reported by the dedicated rules for those weaknesses.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-547/",
	"languages": ["c", "cpp", "java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [547],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["hardcoded", "buffer-size", "magic-number", "cwe-547"],
}

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_lang(path) := "java" if endswith(path, ".java")

_num := `(0[xX][0-9a-fA-F]+|\d+)[uUlL]*`

# String and character literals blanked, so a call quoted in a message is not a call.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# Buffers declared with a literal length, with the line they are declared on.
_c_buffers(lines) := {[name, size, k] |
	some k, line in lines
	contains(line, "[")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:(?:static|const|volatile|unsigned|signed|struct\s+\w+)\s+)*(?:std::)?(?:char|wchar_t|u?int\d+_t|u_char|BYTE|byte|int|long|short|float|double|size_t)\s*\*?\s*([A-Za-z_]\w*)\s*\[\s*`, _num, `\s*\]\s*[;=,]`]), line, 1)
	count(m) > 0
	name := m[0][1]
	size := lower(m[0][2])
}

# Call name -> [buffer argument index, size argument index].
_c_calls := {
	"fgets": [0, 1], "snprintf": [0, 1], "vsnprintf": [0, 1], "bzero": [0, 1], "getcwd": [0, 1],
	"strncpy": [0, 2], "strncat": [0, 2], "memcpy": [0, 2], "memmove": [0, 2], "memset": [0, 2],
	"read": [1, 2], "recv": [1, 2], "fread": [0, 2],
}

_arg := `\s*(?:[^,()]|\([^()]*\))+?\s*`

_c_call_re(fn) := re if {
	pos := _c_calls[fn]
	parts := [p |
		some k in numbers.range(0, pos[1])
		p := _c_part(k, pos)
	]
	re := concat("", [`(?:^|[^\w.>])(?:std::)?`, fn, `\s*\(`, concat(",", parts), `\s*[,)]`])
}

# The buffer argument: a name, or a struct member reached through -> or .
# (u->name, cfg.path); the member path is captured separately.
_c_part(k, pos) := `\s*&?\s*((?:[A-Za-z_]\w*(?:\[[^\]]*\])?\s*(?:->|\.)\s*)*)([A-Za-z_]\w*)(?:\s*\[\s*0\s*\])?\s*` if k == pos[0]

_c_part(k, pos) := concat("", [`\s*`, _num, `\s*`]) if {
	k == pos[1]
	k != pos[0]
}

_c_part(k, pos) := _arg if {
	k != pos[0]
	k != pos[1]
}

# The call text, with up to two continuation lines when its parentheses are open.
_stmt(lines, i) := t if {
	last := min([count(lines) - 1, i + 2])
	ends := [k |
		some k in numbers.range(i, last)
		seg := concat(" ", array.slice(lines, i, k + 1))
		strings.count(seg, "(") <= strings.count(seg, ")")
	]
	e := min(array.concat(ends, [last]))
	t := _code(concat(" ", array.slice(lines, i, e + 1)))
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "c"
	contains(content, "[")
	regex.match(`\b(fgets|snprintf|bzero|getcwd|strncpy|strncat|memcpy|memmove|memset|read|recv|fread)\s*\(`, content)
	lines := split(content, "\n")
	bufs := _c_buffers(lines)
	count(bufs) > 0
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	some fn, _ in _c_calls
	contains(line, fn)
	m := regex.find_all_string_submatch_n(_c_call_re(fn), _stmt(lines, i), 1)
	count(m) > 0
	_fread_unit(fn, m[0][0])
	_c_repeats(lines, bufs, m[0][1], m[0][2], lower(m[0][3]), i)
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "java"
	regex.match(`new\s+(byte|char)\s*\[`, content)
	contains(content, ".read(")
	lines := split(content, "\n")
	bufs := {[name, size, k] |
		some k, line in lines
		contains(line, "new ")
		m := regex.find_all_string_submatch_n(concat("", [`\b(?:byte|char)\s*(?:\[\s*\]\s*)?([A-Za-z_]\w*)\s*(?:\[\s*\]\s*)?=\s*new\s+(?:byte|char)\s*\[\s*`, _num, `\s*\]`]), line, 1)
		count(m) > 0
		name := m[0][1]
		size := lower(m[0][2])
	}
	count(bufs) > 0
	some i, line in lines
	contains(line, ".read(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`\.read\s*\(\s*([A-Za-z_]\w*)\s*,`, _arg, `,\s*`, _num, `\s*\)`]), _code(line), 1)
	count(m) > 0
	_repeats(bufs, m[0][1], lower(m[0][2]), i)
	finding := _finding(path, i, line)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "The bound passed to this call is a bare number that repeats the buffer's declared length. If either is changed without the other, the call reads or writes past the buffer. Use sizeof(buf) (buf.length in Java) or one named constant for both",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# The nearest declaration of the name in the 60 lines above the call (the
# function's own local; a parameter of the same name elsewhere is not it) has
# the same literal length, or a smaller one (a bound already past the end). A
# smaller bound (memcpy(buf, "inf", 3), read(fd, buf, 1)) is a partial use,
# not a repeat.
_repeats(bufs, name, lit, i) if {
	idxs := [p[2] | some p in bufs; p[0] == name; p[2] < i; p[2] >= i - 60]
	count(idxs) > 0
	d := max(idxs)
	some p in bufs
	p[0] == name
	p[2] == d
	_bound_hits(lit, p[1])
}

_bound_hits(lit, size) if lit == size

_bound_hits(lit, size) if {
	regex.match(`^\d+$`, lit)
	regex.match(`^\d+$`, size)
	to_number(lit) > to_number(size)
}

# A plain local: its nearest declaration above, in the same function (an
# indented declaration is a local, and a closing brace in column 0 between it
# and the call means the call is in another function, where the name is a
# parameter or another variable).
_c_repeats(lines, bufs, "", name, lit, i) if {
	idxs := [p[2] | some p in bufs; p[0] == name; p[2] < i; p[2] >= i - 60]
	count(idxs) > 0
	d := max(idxs)
	not _left_function(lines, d, i)
	_repeats(bufs, name, lit, i)
}

_left_function(lines, d, i) if {
	regex.match(`^\s+\S`, lines[d])
	some j in numbers.range(d + 1, i - 1)
	startswith(lines[j], "}")
}

# A struct member (u->name): every declaration of that member name in the
# file has one literal length, and the bound hits it.
_c_repeats(_, bufs, prefix, name, lit, _) if {
	prefix != ""
	sizes := {p[1] | some p in bufs; p[0] == name}
	count(sizes) == 1
	some size in sizes
	_bound_hits(lit, size)
}

# fread(buf, size, count, f) bounds the buffer only when the element size is 1.
_fread_unit(fn, _) if fn != "fread"

_fread_unit("fread", call) if regex.match(`fread\s*\(\s*&?\s*\w+(?:\s*\[\s*0\s*\])?\s*,\s*(1|sizeof\s*\(?\s*(unsigned\s+)?char\s*\)?)\s*,`, call)
