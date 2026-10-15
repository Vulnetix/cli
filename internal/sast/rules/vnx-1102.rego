# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1102

import rego.v1


metadata := {
	"id": "VNX-1102",
	"name": "Reliance on Machine-Dependent Data Representation",
	"description": "C and C++ code writes or reads the in-memory representation of a multi-byte value or a struct straight to or from a socket, file or stream: send/sendto/recv/recvfrom/write/read/pwrite/pread, fwrite/fread (including the fwrite(&x, 1, sizeof x, f) form and std:: or :: qualified calls), or an iostream .write/.read through reinterpret_cast, where the buffer is the address of a variable (&n) or a pointer and the size is sizeof of that variable, of a multi-byte scalar type (int, long, short, uint16_t/uint32_t/uint64_t, float, double, size_t) or of a struct. The bytes on the wire or on disk then depend on the host's byte order, type widths, alignment and struct padding, so another machine reads a different value. Reported: the call line. Not reported: a byte-order conversion of the same variable within a few lines (htonl/ntohl, htobe64/le64toh, bswap, cpu_to_le32, memrev), single-byte values (char, uint8_t, bool, sizeof(char)), byte buffers sized by sizeof(buf), constant counts such as write(fd, &c, 1), host-local kernel interfaces read and written in native order by design (eventfd, signalfd, timerfd, inotify, self-pipe wakeups, judged by the descriptor's name, and descriptors the same file creates with pipe()/pipe2() or socketpair()), and calls inside comments or strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1102/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1102],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["portability", "endianness", "serialization", "cwe-1102"],
}

_c_file(path) if regex.match(`\.(?:c|h|cc|cpp|cxx|hpp|hh|hxx)$`, path)

_posix_re := `(?:^|[^\w.>:])(?:std::|::)?(?:send|sendto|recv|recvfrom|write|read|pwrite|pread)\s*\(\s*([^,()]+?(?:\[[^\]]*\])?)\s*,\s*([^,]+?)\s*,\s*(sizeof\b[^,;]*)`

_stdio_re := `(?:^|[^\w.>:])(?:std::|::)?(?:fwrite|fread)\s*\(\s*([^,]+?)\s*,\s*(?:1\s*,\s*)?(sizeof\b[^,;]*?)\s*,`

_stream_re := `(?:\.|->)(?:write|read)\s*\(\s*((?:reinterpret_cast\s*<[^>]*>|\(\s*(?:const\s+)?(?:unsigned\s+)?char\s*\*\s*\))\s*\(?\s*&?\s*[A-Za-z_][\w.\->\[\]]*\s*\)?)\s*,\s*(sizeof\b[^,;]*)`

_call_line_re := `(?:\b(?:send|sendto|recv|recvfrom|write|read|pwrite|pread|fwrite|fread)\s*\(|(?:\.|->)(?:write|read)\s*\(\s*(?:reinterpret_cast|\())`

# [descriptor, buffer, size] for each recognised call in the text.
_calls(text) := {[m[1], m[2], m[3]] | some m in regex.find_all_string_submatch_n(_posix_re, text, -1)} | {["", m[1], m[2]] | some m in regex.find_all_string_submatch_n(_stdio_re, text, -1)} | {["", m[1], m[2]] | some m in regex.find_all_string_submatch_n(_stream_re, text, -1)}

# The operand of sizeof: sizeof(T), sizeof x, sizeof(*p).
_sizeof_inner(size) := trim_space(m[0][1]) if {
	m := regex.find_all_string_submatch_n(`sizeof\s*\(\s*([^()]*?)\s*\)`, size, 1)
	count(m) > 0
}

_sizeof_inner(size) := m[0][1] if {
	not regex.match(`sizeof\s*\(`, size)
	m := regex.find_all_string_submatch_n(`sizeof\s+(\*?[A-Za-z_][\w.\->\[\]]*)`, size, 1)
	count(m) > 0
}

_byte_type(t) if regex.match(`^(?:const\s+)?(?:(?:unsigned|signed)\s+)?char$|^(?:std::)?u?int8_t$|^(?:bool|_Bool|BYTE|byte|gboolean)$`, t)

_multi_type(t) if {
	regex.match(`^(?:const\s+)?(?:(?:std::)?u?int(?:16|32|64)_t|(?:(?:unsigned|signed)\s+)?(?:int|long(?:\s+long)?|short)(?:\s+int)?|unsigned|float|double|long\s+double|size_t|ssize_t|off_t|time_t|struct\s+\w+)$`, t)
}

# The variable whose bytes are transferred: &x inside the buffer argument, or
# a bare pointer whose size is sizeof(*p).
_obj(buf) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`&\s*([A-Za-z_][\w.\->\[\]]*)`, buf, 1)
	count(m) > 0
}

_ident(buf) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*\)?\s*$`, buf, 1)
	count(m) > 0
}

_root(x) := split(regex.replace(x, `->`, "."), ".")[0]

# Host-local kernel interfaces whose payload is native-endian by definition.
_local_fd(fd) if regex.match(`(?i)(?:event|efd|pipe|signal|sfd|timer|tfd|wake|notif|inotify)`, fd)

# A descriptor created in this file by pipe()/pipe2() or socketpair(): both
# ends belong to this host (fork error reporting, worker control channels).
_pair_fd(content, fd) if {
	r := trim_space(regex.replace(fd, `\[.*$`, ""))
	regex.match(`^[A-Za-z_]\w*$`, r)
	regex.match(concat("", [`\b(?:pipe2?\s*\(\s*|socketpair\s*\([^;]*?,\s*)&?`, r, `\b`]), content)
}

_declared_byte(lines, i, x) if {
	r := _root(x)
	some j in numbers.range(max([0, i - 40]), i)
	contains(lines[j], r)
	regex.match(concat("", [`\b(?:(?:unsigned|signed)\s+)?char\s+(?:[^;=]*,\s*)?\*?`, r, `\b|\b(?:u?int8_t|bool|_Bool|BYTE|uchar|u_char)\s+(?:[^;=]*,\s*)?\*?`, r, `\b`]), lines[j])
}

_converted(lines, i, x) if {
	r := _root(x)
	some j in numbers.range(max([0, i - 6]), min([count(lines) - 1, i + 6]))
	contains(lines[j], r)
	not _comment(lines[j])
	regex.match(`\b(?:hton[sl]l?|ntoh[sl]l?|hto[bl]e(?:16|32|64)|[bl]e(?:16|32|64)toh|bswap_?(?:16|32|64)|__builtin_bswap(?:16|32|64)|_byteswap_\w+|cpu_to_[bl]e(?:16|32|64)|[bl]e(?:16|32|64)_to_cpu|memrev(?:16|32|64)(?:ifbe)?|intrev(?:16|32|64)(?:ifbe)?|OSSwap\w+|boost::endian::\w+|std::byteswap)\s*\(`, lines[j])
}

# &x with sizeof(x), sizeof(T) or sizeof x, where x is not a single byte.
_native(lines, i, buf, inner) if {
	x := _obj(buf)
	_multi_type(inner)
	not _converted(lines, i, x)
}

_native(lines, i, buf, inner) if {
	x := _obj(buf)
	inner == x
	not _declared_byte(lines, i, x)
	not _converted(lines, i, x)
}

# A pointer with sizeof(struct S), sizeof(uint32_t), sizeof(*p).
_native(lines, i, buf, inner) if {
	not _obj(buf)
	_multi_type(inner)
	p := _ident(buf)
	not _converted(lines, i, p)
}

_native(lines, i, buf, inner) if {
	not _obj(buf)
	p := _ident(buf)
	inner == concat("", ["*", p])
	not _declared_byte(lines, i, p)
	not _converted(lines, i, p)
}

# A whole-line C comment. `*out = v;` is code, so a bare leading `*` is not
# enough (the shared helper treats it as a block-comment continuation).
_comment(line) if regex.match(`^\s*(?://|/\*|\*/|\*\s|\*$)`, line)

_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$|/\*.*?\*/`, "")

_text(lines, i, line) := line if contains(line, "sizeof")

# A call broken over lines: join the next two when the parenthesis is open.
_text(lines, i, line) := concat(" ", [line, lines[i + 1], lines[i + 2]]) if {
	not contains(line, "sizeof")
	count(indexof_n(line, "(")) > count(indexof_n(line, ")"))
	i + 2 < count(lines)
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	contains(content, "sizeof")
	regex.match(`\b(?:send|sendto|recv|recvfrom|write|read|pwrite|pread|fwrite|fread)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_call_line_re, line)
	not _comment(line)
	text := _code(_text(lines, i, line))
	some c in _calls(text)
	not _local_fd(c[0])
	not _pair_fd(content, c[0])
	inner := _sizeof_inner(c[2])
	not _byte_type(inner)
	_native(lines, i, c[1], inner)
	finding := {
		"rule_id": metadata.id,
		"message": "The raw in-memory bytes of a multi-byte value or struct are sent, written or read; byte order, type width and padding differ between machines. Serialise each field explicitly in a fixed byte order (htonl/htobe64 or a byte-by-byte encoder)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
