# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_191

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-191",
	"name": "Integer Underflow (Wrap or Wraparound)",
	"description": "A C or C++ length is reduced by subtraction with no check that it is large enough, and the result sizes a memory operation, so a short input wraps the unsigned length to a huge value and the copy or read runs far past the buffer. Reported: a size argument of memcpy/memmove/memset/memcmp/strncpy/strncat/strncmp/malloc/calloc/realloc/alloca/read/recv/recvfrom/fread/fwrite/write/send/bzero (std:: forms included, arguments spread over several lines included) written as len - x where len is a length-like name (len, size, count, total, remain, avail, bytes, n...); an unsigned declaration (size_t, unsigned, uintN_t, DWORD, uN) initialised as a - b, or a compound len -= x on a variable declared unsigned in the file, whose result reaches such a call within 8 lines; and buf[strlen(buf) - 1], which writes before the buffer when the string is empty. Not reported: a subtraction preceded within 10 lines by a comparison of the minuend (if (len < HDR) return, if (off <= total)) or by an if/while on the sink's own line that compares it (if (n > HDR) memcpy(..., n - HDR)), a ternary or min() on the same line, a constant minuend (sizeof(buf) - 1, a numeric or upper-case macro), pointer differences (end - start), signed arithmetic that does not reach a size argument, strings and comments. Go and Java were dropped: Go panics on an out-of-range slice and Java has no unsigned lengths, so neither has a line-level underflow-to-overflow shape.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-191/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [191],
	"capec": ["CAPEC-92"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["integer-underflow", "arithmetic", "buffer", "cwe-191"],
}

_is_c(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_sink_re := `(?:^|[^\w.>])(?:std::)?(?:memcpy|memmove|memset|memcmp|strncpy|strncat|strncmp|malloc|calloc|realloc|alloca|read|recv|recvfrom|fread|fwrite|write|send|bzero|explicit_bzero)\s*\(`

_sink_needles := {"mem", "strn", "alloc", "read", "recv", "write", "send", "bzero"}

# A length-like minuend.
_lenish_re := `(?i)(?:^|[>._])(?:\w*len|\w*length|\w*size|sz|\w*count|cnt|num\w*|\w*total|remain\w*|left|avail\w*|\w*bytes|n)$`

_esc(s) := replace(replace(replace(s, ".", `\.`), "(", `\(`), ")", `\)`)

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `'x'`)

_has_any(s, ns) if {
	some n in ns
	contains(s, n)
}

# A comparison of `name` in a condition within 10 lines above.
_guarded(lines, i, name) if {
	re := concat("", [`(?:^|[^\w>.])`, _esc(name), `(?:[^\w]|$)`])
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(re, l)
	_is_comparison(l)
}

_is_comparison(l) if {
	s := replace(replace(replace(l, "->", ""), "<<", ""), ">>", "")
	regex.match(`[<>]|!=|==`, s)
	regex.match(`\b(?:if|while|assert\w*|for|return)\b|\?|&&|\|\|`, s)
}

# The statement starting at line i, up to its semicolon (at most 4 lines).
_statement(lines, i) := s if {
	ends := [j | some j in numbers.range(i, min([count(lines) - 1, i + 3])); contains(lines[j], ";")]
	e := min(array.concat(ends, [min([count(lines) - 1, i + 3])]))
	s := concat(" ", array.slice(lines, i, e + 1))
}

_constant(a) if regex.match(`^(?:\d+|[A-Z][A-Z0-9_]*)$`, a)

_msg := "This length is reduced by subtraction with no check that it is large enough; an input shorter than the amount subtracted wraps the unsigned result to a huge size and the memory operation runs past the buffer. Check the length first (if (len < HDR) return -1;)"

_strlen_msg := "strlen(s) - 1 wraps to SIZE_MAX when the string is empty, so this index writes or reads far outside the buffer. Check that the string is non-empty first"

# One pass over each file's lines; each shape gates on a cheap substring.
findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "-")
	lines := split(content, "\n")
	some i, line in lines
	_line_gate(line)
	not helpers.is_comment_line(line)
	some msg in _underflow(lines, i, line, content)
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_underflow(lines, i, line, content) := {m | some m in [_msg]; _sink_shape(lines, i, line)} | {m | some m in [_msg]; _unsigned_shape(lines, i, line, content)} | {m | some m in [_strlen_msg]; _strlen_shape(lines, i, line)}

# (1) a sink whose size argument is len - x
_sink_shape(lines, i, line) if {
	_has_any(line, _sink_needles)
	regex.match(_sink_re, line)
	stmt := _code(_statement(lines, i))
	m := regex.find_all_string_submatch_n(`[,(]\s*([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*-\s*(?:sizeof\s*\([^()]*\)|\w+(?:(?:->|\.)\w+)*(?:\s*\([^()]*\))?)\s*[,)]`, stmt, -1)
	some k
	a := m[k][1]
	regex.match(_lenish_re, a)
	not _constant(a)
	not regex.match(`\?|\b(?:MIN|min|std::min)\s*\(`, stmt)
	not _guarded(lines, i, a)
	not _guarded_inline(line, a)
	_untrusted_length(lines, i, a)
}

# if (n > HDR) memcpy(out, in + HDR, n - HDR); compares on the sink's own line.
_guarded_inline(line, a) if {
	regex.match(`^\s*(?:\}\s*)?(?:else\s+)?(?:if|while)\s*\(`, line)
	s := replace(replace(replace(line, "->", ""), "<<", ""), ">>", "")
	e := _esc(a)
	regex.match(concat("", [`\b`, e, `\s*(?:[<>]=?|[!=]=)|(?:[<>]=?|[!=]=)\s*`, e, `\b`]), s)
}

_unsigned_type := `(?:size_t|unsigned(?:\s+(?:int|long|short|char))*|u?int(?:8|16|32|64)_t|uint\d*|ulong|DWORD|ULONG|u(?:8|16|32|64)|uint_fast\d+_t)`

# (2) an unsigned result of a subtraction (declaration or -=) that sizes a sink
_unsigned_shape(lines, i, line, content) if {
	regex.match(`-=|=[^=;]*[\w)]\s*-\s*[\w(]`, line)
	c := _code(line)
	[v, a] := _unsigned_subtraction(content, c)
	not _constant(a)
	not regex.match(`\?|\b(?:MIN|min|std::min)\s*\(`, c)
	not _guarded(lines, i, a)
	_untrusted_length(lines, i, a)
	_reaches_sink(lines, i, v)
}

_unsigned_subtraction(_, c) := [m[0][1], m[0][2]] if {
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:const\s+)?`, _unsigned_type, `\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*-\s*[\w(][\w>.()-]*\s*;`]), c, 1)
	count(m) > 0
}

_unsigned_subtraction(content, c) := [m[0][1], m[0][1]] if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*-=\s*[^;]+;`, c, 1)
	count(m) > 0
	regex.match(concat("", ["(?m)", _unsigned_type, `\s+(?:\w+\s*,\s*)*\*?`, m[0][1], `\b`]), content)
}

_reaches_sink(lines, i, v) if {
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_sink_re, l)
	regex.match(concat("", [`[,(]\s*`, v, `\s*[,)]`]), _statement(lines, j))
}

# (3) buf[strlen(buf) - 1] on a string that may be empty
_strlen_shape(lines, i, line) if {
	contains(line, "strlen")
	m := regex.find_all_string_submatch_n(`([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*\[\s*strlen\s*\(\s*([^()]+?)\s*\)\s*-\s*1\s*\]`, line, -1)
	some k
	m[k][1] == m[k][2]
	pre := split(line, "strlen")[0]
	not _non_empty_checked(lines, i, m[k][1], pre)
}

_non_empty_checked(_, _, s, pre) if {
	regex.match(concat("", [`\*\s*`, _esc(s), `\b|`, _esc(s), `\s*\[\s*0\s*\]|\bstrlen\s*\(\s*`, _esc(s), `\s*\)\s*(?:>|!=)|&&|\?`]), pre)
}

_non_empty_checked(lines, i, s, _) if {
	some j in numbers.range(max([0, i - 3]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(`\b(?:if|while)\b|&&`, l)
	regex.match(concat("", [`\*\s*`, _esc(s), `\b|`, _esc(s), `\s*\[\s*0\s*\]|\bstrlen\s*\(\s*`, _esc(s), `\s*\)|\b`, _esc(s), `\b`]), l)
}

# ── Where the minuend came from ──────────────────────────────────────────
# A length handed in by the caller (a parameter of the enclosing function) or
# decoded from a message a few lines up. Lengths a data structure maintains
# itself (node->size, a local computed from its own invariants) are not
# judged: their bounds live in code a line-level rule cannot see.

_fn_header_re := `^[A-Za-z_][\w \t\*:&<>,]*?\b[A-Za-z_][\w:~]*\s*\(`

_untrusted_length(lines, i, a) if {
	not contains(a, ">")
	not contains(a, ".")
	heads := [j | some j in numbers.range(max([0, i - 200]), i); regex.match(_fn_header_re, lines[j]); not regex.match(`;\s*$`, lines[j])]
	count(heads) > 0
	h := heads[count(heads) - 1]
	sig := concat(" ", array.slice(lines, h, min([i, h + 5]) + 1))
	params := split(split(sig, "(")[1], ")")[0]
	regex.match(concat("", [`\b`, a, `\b`]), params)
}

_decoded_re := `\b(?:ntoh[sl]|be(?:16|32|64)toh|le(?:16|32|64)toh|bswap_(?:16|32|64)|__builtin_bswap\d+|get_?u?(?:int)?(?:8|16|32|64)\w*|read_?u?(?:int)?(?:8|16|32|64)\w*|strtou?ll?|atoi|atol)\s*\(|\b(?:hdr|header|pkt|packet|msg|frame|req|rec|record)\s*(?:->|\.)\s*\w*(?:len|length|size)\b`

_untrusted_length(lines, i, a) if {
	not contains(a, ">")
	not contains(a, ".")
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	helpers.assigned_first(l) == a
	regex.match(_decoded_re, l)
}

# A field of a decoded message is itself the untrusted length.
_untrusted_length(_, _, a) if regex.match(`^(?:hdr|header|pkt|packet|msg|frame|req|rec|record)(?:->|\.)\w*(?:len|length|size)$`, a)

_line_gate(line) if regex.match(`[\w)\]]\s*-(?:[\s\w(]|=)`, line)

# A sink call whose arguments continue on the next lines.
_line_gate(line) if {
	contains(line, ",")
	endswith(trim_right(line, " \t\r"), ",")
	_has_any(line, _sink_needles)
	not regex.match(`[\w)\]]\s*-(?:[\s\w(]|=)`, line)
}
