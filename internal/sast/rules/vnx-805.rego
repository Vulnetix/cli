# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_805

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-805",
	"name": "Buffer Access with Incorrect Length Value",
	"description": "A C/C++ call writes into a byte buffer with a length that does not come from that buffer. Reported: (1) memcpy, memmove, memset, strncpy, read, recv, pread, fgets, snprintf, vsnprintf or fread (element size 1) into a char/unsigned char/uint8_t/u_char array declared with a numeric size (a literal or a #define of a literal) in the 80 lines above, either in the same function or at file scope, whose length is a larger number or #define, or sizeof() of another, larger array that is not the copy's source (that shape is VNX-806); (2) memcpy, memmove, memset, strncpy, read, recv or pread whose length is a conversion result: a network or text conversion (ntohs, ntohl, be16toh/be32toh/le16toh/le32toh, atoi, atol, atoll, strtol, strtoul, strtoll, strtoull, std::stoi/stol/stoul/stoull) written inline as the length, or a variable (optionally plus, minus or times a constant) assigned from one in the ten lines above, with no clamp on the assignment itself (MIN/min/clamp or a ternary), no comparison of that variable (<, >, MIN/min) between the conversion and the call, and no allocation of the destination sized by it. Not reported: lengths written as sizeof(dst), equal or smaller numeric lengths, non-byte arrays (an int[10] memset by 40 bytes is correct), an array declared in another function (a pointer parameter of the same name), counts whose size cannot be resolved in the file, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-805/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [805],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["buffer-access-incorrect-length-value", "cwe-805", "memory-safety"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_c_file(path) if {
	some ext in _exts
	endswith(path, ext)
}

_sink_re := `\b(?:std::)?(memcpy|memmove|memset|strncpy|read|recv|pread|fgets|snprintf|vsnprintf|fread)\s*\(`

# (destination argument, length argument) for each sink.
_pos("memcpy") := [0, 2]

_pos("memmove") := [0, 2]

_pos("memset") := [0, 2]

_pos("strncpy") := [0, 2]

_pos("read") := [1, 2]

_pos("recv") := [1, 2]

_pos("pread") := [1, 2]

_pos("fgets") := [0, 1]

_pos("snprintf") := [0, 1]

_pos("vsnprintf") := [0, 1]

_pos("fread") := [0, 2]

# Sinks whose length can come from an untrusted conversion (shape 2).
_copy_sinks := {"memcpy", "memmove", "memset", "strncpy", "read", "recv", "pread"}

_byte_type := `(?:unsigned\s+char|signed\s+char|char|uint8_t|int8_t|u_char|u8|BYTE|gchar|guchar)`

_source_re := `\b(?:std::)?(?:ntohs|ntohl|be16toh|be32toh|be64toh|le16toh|le32toh|atoi|atol|atoll|strtol|strtoul|strtoll|strtoull|stoi|stol|stoul|stoull)\s*\(`

_call_text(lines, i) := t if {
	end := min([count(lines) - 1, i + 2])
	t := concat(" ", [lines[k] | some k in numbers.range(i, end)])
}

_call(text) := [fn, args] if {
	m := regex.find_all_string_submatch_n(concat("", [_sink_re, `(.*)`]), text, 1)
	fn := m[0][1]
	args := [trim_space(a) | some a in split(m[0][2], ",")]
	count(args) >= 3
}

# A numeric token: a decimal literal, or a #define of one in this file.
_num(tok, _) := n if {
	regex.match(`^\d+$`, tok)
	n := to_number(tok)
}

_num(tok, content) := n if {
	regex.match(`^[A-Za-z_]\w*$`, tok)
	m := regex.find_all_string_submatch_n(concat("", [`(?m)^\s*#\s*define\s+`, tok, `\s+\(?\s*(\d+)\s*\)?\s*$`]), content, 1)
	count(m) > 0
	n := to_number(m[0][1])
}

# The declared capacity of a byte array named `name` in the 80 lines above.
_capacity(lines, i, name, content) := n if {
	re := concat("", [`\b`, _byte_type, `\s+`, name, `\s*\[\s*(\w+)\s*\]`])
	caps := [c |
		some j in numbers.range(max([0, i - 80]), i - 1)
		contains(lines[j], name)
		m := regex.find_all_string_submatch_n(re, lines[j], 1)
		count(m) > 0
		c := _num(m[0][1], content)
		not _local_out_of_scope(lines, j, i)
	]
	count(caps) > 0
	n := caps[count(caps) - 1]
}

# The length argument's value in bytes, where it can be resolved.
_length(cnt, _, _, content, _) := n if n := _num(cnt, content)

_length(cnt, lines, i, content, src) := n if {
	m := regex.find_all_string_submatch_n(`^sizeof\s*\(?\s*([A-Za-z_]\w*)\s*\)?$`, cnt, 1)
	count(m) > 0
	other := m[0][1]
	other != src
	n := _capacity(lines, i, other, content)
}

_c_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:[\w:]+[\s*]+)*([A-Za-z_]\w*)\s*=[^=]`, line, 1)
	v := m[0][1]
}

_untrusted_len(lines, i, cnt) if {
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	regex.match(_source_re, l)
	not helpers.is_comment_line(l)
	_c_assigned(l) == cnt
	not regex.match(`\b(?:MIN|MAX|min|max|clamp|std::min|std::clamp)\s*\(|\?`, l)
	not _len_checked(lines, j, i, cnt)
}

# The variable is compared or clamped between the conversion and the call
# (including on the call line), or bounds an allocation of the destination.
_len_checked(lines, j, i, v) if {
	some k in numbers.range(j + 1, i)
	l := replace(lines[k], "->", ".")
	not helpers.is_comment_line(l)
	re := concat("", [`\b`, v, `\s*[<>]|[<>]=?\s*(?:\([\w\s]+\)\s*)?`, v, `\b|\b(?:MIN|MAX|min|max|clamp)\s*\([^)]*\b`, v, `\b`])
	regex.match(re, l)
}

_len_checked(lines, j, i, v) if {
	some k in numbers.range(j + 1, i)
	re := concat("", [`=\s*(?:\([^)]*\)\s*)?\w*(?:alloc|new)\w*\s*\(?[^;]*\b`, v, `\b`])
	regex.match(re, lines[k])
}

_message(1) := "Length larger than the destination buffer: the call writes past the declared array. Use sizeof(dst) or the array's own size constant as the bound"

_message(2) := "Length taken from untrusted data (a network or text conversion) is used to write into a buffer without being checked against the buffer's size. Compare it with sizeof(dst) before the call"

findings contains finding if {
	some f in _findings
	finding := {
		"rule_id": metadata.id,
		"message": _message(f[2]),
		"artifact_uri": f[0],
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": f[1] + 1,
		"snippet": f[3],
	}
}

# Shape 1: the length exceeds the destination's declared capacity.
_findings contains [path, i, 1, line] if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`\b\w+\s*\[\s*\w+\s*\]`, content)
	regex.match(`(?:memcpy|memmove|memset|strncpy|read|recv|fgets|snprintf|fread)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_sink_re, line)
	not helpers.is_comment_line(line)
	c := _call(_call_text(lines, i))
	p := _pos(c[0])
	args := c[1]
	_fread_bytes(c[0], args)
	dst := args[p[0]]
	regex.match(`^[A-Za-z_]\w*$`, dst)
	cap := _capacity(lines, i, dst, content)
	src := _src_arg(c[0], args)
	n := _length(_clean(args[p[1]]), lines, i, content, src)
	n > cap
}

# Shape 2: the length comes from an unchecked conversion, through a variable
# (optionally with arithmetic: len - 4) or written inline as the length.
_findings contains [path, i, 2, line] if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(_source_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_sink_re, line)
	not helpers.is_comment_line(line)
	c := _call(_call_text(lines, i))
	_copy_sinks[c[0]]
	p := _pos(c[0])
	_untrusted_count(lines, i, trim_space(c[1][p[1]]))
}

_untrusted_count(lines, i, arg) if {
	m := regex.find_all_string_submatch_n(`^\(?\s*([A-Za-z_]\w*)\s*(?:[-+*]\s*\w+\s*)?\)*\s*(?:;.*)?$`, _clean(arg), 1)
	count(m) > 0
	_untrusted_len(lines, i, m[0][1])
}

_untrusted_count(_, _, arg) if regex.match(concat("", [`^`, _source_re]), arg)

# The argument text up to the end of the call: a last argument carries the
# closing parenthesis and whatever followed it on the joined lines.
_clean(a) := t if {
	t0 := trim_right(trim_space(split(a, ";")[0]), ") ")
	_balanced(t0)
	t := t0
}

_clean(a) := concat("", [t0, ")"]) if {
	t0 := trim_right(trim_space(split(a, ";")[0]), ") ")
	not _balanced(t0)
}

_balanced(t) if count(indexof_n(t, "(")) == count(indexof_n(t, ")"))

_fread_bytes(fn, _) if fn != "fread"

_fread_bytes("fread", args) if regex.match(`^(?:1|sizeof\s*\(\s*(?:char|unsigned char|uint8_t)\s*\))$`, args[1])

_src_arg(fn, args) := args[1] if {
	fn in {"memcpy", "memmove", "strncpy"}
}

_src_arg(fn, _) := "" if {
	not fn in {"memcpy", "memmove", "strncpy"}
}

# A function body closes (a `}` in column 0) between the declaration and the
# call: the array belonged to another function.
_fn_end_between(lines, j, i) if {
	some k in helpers.span(j + 1, i - 1)
	startswith(lines[k], "}")
}

# A local (indented) declaration is out of scope once its function closes;
# a file-scope array (column 0) stays visible.
_local_out_of_scope(lines, j, i) if {
	regex.match(`^\s`, lines[j])
	_fn_end_between(lines, j, i)
}
