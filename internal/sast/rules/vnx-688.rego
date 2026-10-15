# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_688

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-688",
	"name": "Function Call With Incorrect Variable or Reference as Argument",
	"description": "A C or C++ bounded write takes its size from sizeof of a different array than the one it writes, so the bound describes the wrong buffer and a smaller destination overflows. Reported: snprintf, vsnprintf, fgets, getcwd, gethostname, bzero, explicit_bzero, strncpy, strlcpy, strncat, strlcat, memset, memcpy, memmove, read, recv, recvfrom, pread and readlink whose destination array and the array named in the sizeof size argument (optionally minus a constant) are different arrays (char, wide char, integer or floating-point element types) both declared in the file (locals, globals or struct members, compared by their final name so c->host and c->url differ). For memcpy and memmove a size taken from the source array is not reported, since copying a whole source into a destination of the same declared type is common; strncpy, strlcpy, strncat and strlcat bounded by the source are reported. Not reported: a size from the destination itself, sizeof of a type or of *ptr, a pointer destination (its target is unknown), non-sizeof sizes, calls split over lines, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-688/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [688],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["wrong-buffer-size", "cwe-688"],
}

_is_c(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_blank(s) := regex.replace(regex.replace(s, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_pre := `(?:^|[^\w.>])(?:std::)?`

_ref := `((?:\w+(?:\.|->))*\w+)`

_dst := concat("", [`&?\s*`, _ref, `\s*`])

_size := concat("", [`sizeof\s*(?:\(\s*`, _ref, `\s*\)|\s+`, _ref, `)\s*(?:-\s*\d+\s*)?[,)]`])

# [regex, has a source argument that may legitimately size the copy]
_shapes := [
	[concat("", [_pre, `(?:snprintf|vsnprintf|fgets|getcwd|gethostname|bzero|explicit_bzero)\s*\(\s*`, _dst, `,\s*()`, _size]), false],
	[concat("", [_pre, `(?:strncpy|strlcpy|strncat|strlcat|memset)\s*\(\s*`, _dst, `,\s*[^,]+,\s*()`, _size]), false],
	[concat("", [_pre, `(?:memcpy|memmove)\s*\(\s*`, _dst, `,\s*&?\s*`, _ref, `\s*,\s*`, _size]), true],
	[concat("", [_pre, `(?:read|recv|recvfrom|pread|readlink)\s*\(\s*[^,]+,\s*`, _dst, `,\s*()`, _size]), false],
]

_last(ref) := parts[count(parts) - 1] if {
	parts := regex.split(`\.|->`, ref)
}

# The name is declared as an array in the file (a local, a global or a struct
# member; one of several declarators on the line counts). Only asked for the
# few calls whose destination and sizeof name differ.
_array_decl(name, content) if {
	contains(content, concat("", [name, "["]))
	regex.match(concat("", [`\b(?:char|wchar_t|u?int(?:8|16|32|64)_t|BYTE|TCHAR|WCHAR|u_char|guchar|gchar|int|short|long|unsigned|float|double|size_t)\s+(?:[^;=(){}]*,\s*)?\**\s*`, name, `\s*\[[^\]]+\]`]), content)
}

# The destination and the sizeof'd array when they differ.
_pair(code) := [d, s] if {
	some shape in _shapes
	m := regex.find_all_string_submatch_n(shape[0], code, 1)
	count(m) > 0
	g := m[0]
	d := _last(g[1])
	s := _last(concat("", [g[3], g[4]]))
	d != s
	not _from_source(shape[1], g[2], s)
}

_from_source(true, src, s) if _last(src) == s

_call_re := `(?:printf|fgets|getcwd|gethostname|bzero|cpy|cat|memset|memmove|read|recv|recvfrom|readlink)\s*\([^;]*sizeof`

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "sizeof")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "sizeof")
	regex.match(_call_re, line)
	not helpers.is_comment_line(line)
	pr := _pair(_blank(line))
	_array_decl(pr[0], content)
	_array_decl(pr[1], content)
	finding := {
		"rule_id": metadata.id,
		"message": "The size argument is sizeof a different array than the destination this call writes, so the bound describes the wrong buffer. Use sizeof of the destination",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
