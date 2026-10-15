# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_130

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-130",
	"name": "Improper Handling of Length Parameter Inconsistency",
	"description": "Reports C/C++ code that trusts a length field taken from a message: a value decoded from wire byte order (ntohs, ntohl, be16toh/be32toh/le16toh/le32toh, get_unaligned_be16/be32/le16/le32, OpenSSL's n2s/n2l, or bytes combined as (p[0] << 8) | p[1]) is used as the length argument of memcpy, memmove, strncpy or strncat, or as the size of read/recv/recvfrom/fread, with no comparison of that length against the destination or the received size in between (the Heartbleed shape). The conversion written directly in the length argument (memcpy(dst, src, ntohs(h->len))) is reported too. Not reported: a length compared in an if/while/assert or a ternary, or clamped with MIN()/min() before the copy; constant or sizeof lengths; values decoded but never used as a copy length; host-to-network conversions (htons, htonl); comments. Lengths that reach the copy through another function are out of scope.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-130/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [130],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["length", "buffer", "cwe-130"],
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

_conv := `(?:ntohs|ntohl|be16toh|be32toh|be64toh|le16toh|le32toh|le64toh|get_unaligned_(?:be|le)(?:16|32|64))`

_gate := `\b(?:ntoh[sl]|[bl]e(?:16|32|64)toh|get_unaligned_|n2s|n2l)\s*\(|\[\s*\d+\s*\]\s*<<\s*8`

_sink_gate := `\b(?:memcpy|memmove|strncpy|strncat|read|recv|recvfrom|fread)\s*\(`

_gate_lit(s) if {
	some lit in {"ntohs(", "ntohl(", "toh(", "get_unaligned_", "n2s(", "n2l(", "] << 8", "]<<8"}
	contains(s, lit)
}

_def_lit(s) if contains(s, "toh")

_def_lit(s) if contains(s, "unaligned")

_def_lit(s) if contains(s, "n2")

_def_lit(s) if contains(s, "<<")

_conv_lit(s) if contains(s, "toh")

_conv_lit(s) if contains(s, "unaligned")

_sink_lit(s) if {
	some lit in {"memcpy(", "memmove(", "strncpy(", "strncat(", "read(", "recv(", "recvfrom("}
	contains(s, lit)
}

# Names a line decodes from wire data.
_wire_names(line) := {v |
	m := regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?`, _conv, `\s*\(`]), line, -1)
	some x in m
	v := x[1]
} | {v |
	m := regex.find_all_string_submatch_n(`\bn2[sl]\s*\(\s*[^,]+,\s*([A-Za-z_]\w*)\s*\)`, line, -1)
	some x in m
	v := x[1]
} | {v |
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*\(*\s*(?:\([\w ]+\)\s*)?[A-Za-z_]\w*\s*\[\s*\d+\s*\]\s*<<\s*(?:8|16|24)`, line, -1)
	some x in m
	v := x[1]
}

# v is the length argument of a copy or read on this line.
_length_arg(line, v) if regex.match(concat("", [`\b(?:memcpy|memmove|strncpy|strncat)\s*\([^;]*,\s*(?:\([\w ]+\)\s*)?`, v, `\b[^,;]*\)\s*;`]), line)

_length_arg(line, v) if regex.match(concat("", [`\b(?:read|recv|recvfrom)\s*\([^,;]+,[^,;]+,\s*(?:\([\w ]+\)\s*)?`, v, `\b\s*[,)]`]), line)

_length_arg(line, v) if regex.match(concat("", [`\bfread\s*\([^,;]+,\s*(?:1|sizeof\s*\(?\s*char\s*\)?)\s*,\s*`, v, `\b\s*,`]), line)

_length_arg(line, v) if regex.match(concat("", [`\bfread\s*\([^,;]+,\s*`, v, `\b\s*,\s*1\s*,`]), line)

_checked(lines, from, to, v) if {
	from <= to
	some k in numbers.range(from, to)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(concat("", [`\b`, v, `\b`]), l)
	_compare_or_clamp(l)
}

_compare_or_clamp(l) if {
	regex.match(`\b(if|while|assert\w*)\s*\(|\?`, l)
	regex.match(`[^-<>]>|<[^<]|>=|<=`, l)
}

_compare_or_clamp(l) if regex.match(`\b(MIN|min|std::min|MIN_T|min_t)\s*\(`, l)

# (A) the conversion written directly in the length argument
findings contains f if {
	some path, content in input.file_contents
	_is_c(path)
	_gate_lit(content)
	_sink_lit(content)
	lines := split(content, "\n")
	some i, line in lines
	_conv_lit(line)
	_sink_lit(line)
	regex.match(_sink_gate, line)
	regex.match(concat("", [`\b(?:memcpy|memmove|strncpy|strncat)\s*\([^;]*,\s*(?:\([\w ]+\)\s*)?`, _conv, `\s*\([^;]*\)\s*\)\s*;`]), line)
	not helpers.is_comment_line(line)
	f := _finding(path, i, line, "The copy length is taken straight from a field of the message (decoded from network byte order) and never compared with the destination or the received size: a forged length reads or writes past the buffers; validate it first")
}

# (B) a decoded length variable reaching the copy unchecked
findings contains f if {
	some path, content in input.file_contents
	_is_c(path)
	_gate_lit(content)
	_sink_lit(content)
	lines := split(content, "\n")
	some j, def in lines
	_def_lit(def)
	regex.match(_gate, def)
	not helpers.is_comment_line(def)
	some v in _wire_names(def)
	some i in numbers.range(j + 1, min([count(lines) - 1, j + 25]))
	sink := lines[i]
	_sink_lit(sink)
	regex.match(_sink_gate, sink)
	not helpers.is_comment_line(sink)
	_length_arg(_call_text(lines, i), v)
	not _checked(lines, j + 1, i - 1, v)
	f := _finding(path, i, sink, sprintf("%s is a length read from the message on line %d and is used as the copy length without being compared with the destination or the received size: a forged length reads or writes past the buffers; validate %s first", [v, j + 1, v]))
}

# The sink call's text: the line itself, or the line joined with the next three
# when the call is broken across lines (`memmove(dst,\n src,\n len);`).
_call_text(lines, i) := lines[i] if contains(lines[i], ";")

_call_text(lines, i) := concat(" ", array.slice(lines, i, min([count(lines), i + 4]))) if not contains(lines[i], ";")
