# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_806

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-806",
	"name": "Buffer Access Using Size of Source Buffer",
	"description": "A C/C++ copy into a destination buffer is bounded by the size of the SOURCE instead of the destination, so a long source overruns the destination: memcpy, memmove, strncpy, strncat, strlcpy, strlcat, wcsncpy, wcsncat, wmemcpy or wmemmove whose count is strlen(src), wcslen(src) or sizeof(src) of the same expression passed as the source (optionally + 1), a variable assigned from one of those in the ten lines above, or, for a C++ string, s.size()/s.length() with s.c_str()/s.data() as the source. Calls broken across up to three lines are read whole. Not reported: a destination allocated in the twelve lines above (malloc/calloc/realloc/alloca/strdup/new[]/kmalloc, sized from the source), a destination that is itself a container's buffer (v.data(), &s[0]), a length compared with something (a <, >, <= or >= on strlen(src), the length variable or sizeof(dst)) in the twelve lines above or on the call line, a count wrapped in MIN/min, a string-literal or address-of (&x) source, calls spelled inside string literals, and comments. Reading from a source pointer, an unknown destination capacity and cross-function flows are out of scope.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-806/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [806],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["buffer-access-source-size", "cwe-806", "memory-safety"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_sink_re := `\b(?:std::)?(memcpy|memmove|strncpy|strncat|strlcpy|strlcat|wcsncpy|wcsncat|wmemcpy|wmemmove)\s*\(`

_c_file(path) if {
	some ext in _exts
	endswith(path, ext)
}

# Regex-escape an expression such as `s->name` or `buf[i]`.
_esc(s) := regex.replace(s, `([\[\]().*+?|{}^$\\])`, `\$1`)

_nospace(s) := regex.replace(s, `\s+`, "")

# The call text: the sink line plus up to two continuation lines, so a call
# broken after a comma is read whole.
_call_text(lines, i) := t if {
	end := min([count(lines) - 1, i + 2])
	t := concat(" ", [lines[k] | some k in numbers.range(i, end)])
}

_args(text) := args if {
	m := regex.find_all_string_submatch_n(concat("", [_sink_re, `(.*)`]), text, 1)
	args := split(m[0][2], ",")
	count(args) >= 3
}

# A source expression we can reason about: an identifier or member access,
# not a literal, an address-of or a cast.
_fn(line) := m[0][1] if m := regex.find_all_string_submatch_n(_sink_re, line, 1)

_plain_src(s) if regex.match(`^[A-Za-z_][\w]*(?:(?:\.|->)[A-Za-z_]\w*|\[[\w]+\])*$`, s)

_len_prefixes(src) := {
	concat("", ["strlen(", src, ")"]),
	concat("", ["std::strlen(", src, ")"]),
	concat("", ["wcslen(", src, ")"]),
	concat("", ["std::wcslen(", src, ")"]),
}

_sizeof_prefixes(src) := {
	concat("", ["sizeof(", src, ")"]),
	concat("", ["sizeof", src]),
}

_size_prefixes(src) := _len_prefixes(src) | _sizeof_prefixes(src)

_bounded_by(cnt, prefix) if {
	startswith(cnt, prefix)
	rest := substring(cnt, count(prefix), -1)
	regex.match(`^(?:$|[)+\-*/;])`, rest)
}

# The count is the source's string length, inline (not for memmove, whose
# usual strlen(src) + 1 use shifts a string down inside its own buffer).
_source_sized(fn, cnt, src, _, _, _, _) if {
	fn != "memmove"
	some p in _len_prefixes(src)
	_bounded_by(cnt, p)
}

# The count is sizeof(src), and both arrays are declared above with the same
# element type and the source is the larger: sizeof of equal-sized arrays
# (memcpy(node->ip, ip, sizeof(ip))) is an ordinary whole-array copy.
_source_sized(_, cnt, src, dst, lines, i, content) if {
	some p in _sizeof_prefixes(src)
	_bounded_by(cnt, p)
	s := _decl(lines, i, src, content)
	d := _decl(lines, i, dst, content)
	s[0] == d[0]
	s[1] > d[1]
}

# The count is a variable assigned from the source's string length above.
_source_sized(fn, cnt, src, _, lines, i, _) if {
	fn != "memmove"
	some v in _len_vars(lines, i, src)
	_bounded_by(cnt, v)
}

# [element type, element count] of an array declared in the 80 lines above.
_decl(lines, i, name, content) := d if {
	regex.match(`^[A-Za-z_]\w*$`, name)
	re := concat("", [`\b((?:unsigned\s+|signed\s+|const\s+)*[A-Za-z_]\w*)\s+`, name, `\s*\[\s*(\w+)\s*\]`])
	ds := [[regex.replace(m[0][1], `\s+`, " "), n] |
		some j in numbers.range(max([0, i - 80]), i - 1)
		contains(lines[j], name)
		m := regex.find_all_string_submatch_n(re, lines[j], 1)
		count(m) > 0
		n := _num(m[0][2], content)
	]
	count(ds) > 0
	d := ds[count(ds) - 1]
}

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

# The destination is a cursor advanced by the copied length right after the
# copy: serialisation into a buffer whose total size was computed up front.
_cursor(lines, i, dst) if {
	re := concat("", [`(?:^|[^\w.>])`, _esc(dst), `\s*\+=`])
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 3]))
	regex.match(re, lines[k])
}

_len_vars(lines, i, src) := {v |
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	ns := _nospace(l)
	some p in _len_prefixes(src)
	contains(ns, concat("", ["=", p]))
	m := regex.find_all_string_submatch_n(`^\s*(?:[\w:]+[\s*]+)*([A-Za-z_]\w*)\s*=[^=]`, l, 1)
	v := m[0][1]
}

_window(lines, i) := [l |
	some j in numbers.range(max([0, i - 12]), i)
	l := lines[j]
	not helpers.is_comment_line(l)
]

# The destination was allocated just above (typically sized from the source).
_allocated(lines, i, dst) if {
	re := concat("", [`(?:^|[^\w.>])`, _esc(dst), `\s*=[^=].*\b(?:malloc|calloc|realloc|alloca|xmalloc|zmalloc|g_malloc0?|strdup|strndup|kmalloc|kzalloc|new\s+\w+\s*\[)`])
	some l in _window(lines, i)
	regex.match(re, l)
}

# A length comparison guards the copy.
_guarded(lines, i, src, dst, _) if {
	some l in _window(lines, i)
	ns := replace(_nospace(l), "->", ".")
	regex.match(`[<>]`, ns)
	some p in {
		replace(concat("", ["strlen(", src, ")"]), "->", "."),
		replace(concat("", ["sizeof(", dst, ")"]), "->", "."),
		replace(concat("", ["sizeof", dst]), "->", "."),
	}
	contains(ns, p)
}

_guarded(lines, i, src, _, cnt) if {
	some v in _len_vars(lines, i, src)
	startswith(cnt, v)
	re := concat("", [`\b`, v, `\s*[<>]|[<>]=?\s*`, v, `\b`])
	some l in _window(lines, i)
	regex.match(re, replace(l, "->", "."))
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`(?:memcpy|memmove|strncpy|strncat|strlcpy|strlcat|wcsncpy|wcsncat|wmemcpy|wmemmove)\s*\(`, content)
	regex.match(`\b(?:strlen|wcslen|sizeof)\b|\.(?:size|length)\(\)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_sink_re, _strip(line))
	not helpers.is_comment_line(line)
	args := _args(_strip(_call_text(lines, i)))
	dst := trim_space(args[0])
	src := trim_space(args[1])
	_usable_src(src, dst)
	cnt := _nospace(args[2])
	not regex.match(`^(?:MIN|min|std::min|MIN2)\(`, cnt)
	_source_sized(_fn(lines[i]), cnt, src, dst, lines, i, content)
	dst != src
	not _allocated(lines, i, dst)
	not _cursor(lines, i, dst)
	not _guarded(lines, i, src, dst, cnt)
	finding := {
		"rule_id": metadata.id,
		"message": "Copy bounded by the size of the source, not the destination: a long source overruns the destination buffer. Bound the copy by the destination's capacity (sizeof(dst) or its allocated length) and terminate it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# String literals removed, so a call spelled inside a string is not a call.
_strip(s) := regex.replace(s, `"(?:[^"\\\n]|\\.)*"`, `""`)

_usable_src(src, _) if _plain_src(src)

_usable_src(src, dst) if {
	_cxx_buf(src)
	_plain_src(dst)
}

# A C++ string's buffer: s.c_str() / s.data(), whose bound is s.size().
_cxx_buf(src) if regex.match(`^[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*)*(?:\.|->)(?:c_str|data)\(\)$`, src)

_source_sized(_, cnt, src, _, _, _, _) if {
	_cxx_buf(src)
	obj := regex.replace(src, `(?:\.|->)(?:c_str|data)\(\)$`, "")
	some m in ["size", "length"]
	_bounded_by(cnt, concat("", [_nospace(obj), ".", m, "()"]))
}

_source_sized(_, cnt, src, _, _, _, _) if {
	_cxx_buf(src)
	obj := regex.replace(src, `(?:\.|->)(?:c_str|data)\(\)$`, "")
	some m in ["size", "length"]
	_bounded_by(cnt, concat("", [_nospace(obj), "->", m, "()"]))
}
