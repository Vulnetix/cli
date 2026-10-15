# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_468

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-468",
	"name": "Incorrect Pointer Scaling",
	"description": "Pointer arithmetic in C or C++ that scales an offset by sizeof() a second time on a pointer whose element is wider than one byte: `p + i * sizeof(int)`, `p += sizeof(struct hdr)`, `*(p + n * sizeof *p)`, `arr[i * sizeof(int)]`, where p or arr is declared in the file (nearest declaration above the line, parameter or local) as a pointer to, or array of, int, long, short, float, double, a fixed-width or other *_t integer, or a struct/union, and the same through a cast such as `(uint32_t *)buf + n * sizeof(uint32_t)`. The compiler already multiplies by the element size, so the offset lands sizeof(T) times too far, past the end of the buffer. Pointers to pointers (char **argv, void **slots) and std:: fixed-width types count as wide. Not reported: the same arithmetic on char, signed/unsigned char, int8_t/uint8_t, u_char or void pointers (byte offsets, where sizeof scaling is correct), casts to such a byte pointer, sizeof inside an allocation or length argument (malloc(n * sizeof(int)), memset(p, 0, n * sizeof *p)), member expressions whose type cannot be read from the line (s->buf + sizeof x), typedef'd pointer types the file does not spell out, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-468/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [468],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["incorrect-pointer-scaling", "pointer-arithmetic", "cwe-468"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_type := `(?:(?:const|volatile|unsigned|signed|static|register)\s+)*(?:std::)?(char|void|u_char|uchar|BYTE|byte|u8|guchar|gchar|int|long(?:\s+long)?|short|float|double|size_t|ssize_t|off_t|ptrdiff_t|wchar_t|bool|[A-Za-z_]\w*_t|(?:struct|union)\s+[A-Za-z_]\w*)`

_byte_types := {"char", "void", "u_char", "uchar", "BYTE", "byte", "u8", "guchar", "gchar", "int8_t", "uint8_t", "u_int8_t", "char8_t", "bool"}

# Declarations of pointers and arrays: `int *p`, `uint32_t *dst,`, `struct rec *r =`, `long arr[16]`.
_ptr_decl_re := concat("", [`(?:^|[\s(,;{])`, _type, `\s*(\*+)\s*(?:const\s+)?([A-Za-z_]\w*)\s*(?:[,;=)\[]|$)`])

# `char **argv` and `void **slots` point at pointers, which are wide.
_elem(d) := "pointer" if count(d[2]) > 1

_elem(d) := d[1] if count(d[2]) == 1

_arr_decl_re := concat("", [`(?:^|[\s(,;{])`, _type, `\s+([A-Za-z_]\w*)\s*\[`])

_decls(lines) := [[j, d[3], _elem(d)] |
	some j, l in lines
	contains(l, "*")
	not helpers.is_comment_line(l)
	some d in regex.find_all_string_submatch_n(_ptr_decl_re, _code(l), -1)
]

_arr_decls(lines) := [[j, d[2], d[1]] |
	some j, l in lines
	contains(l, "[")
	not helpers.is_comment_line(l)
	some d in regex.find_all_string_submatch_n(_arr_decl_re, _code(l), -1)
]

_norm(t) := regex.replace(t, `\s+`, " ")

_wide(t) if not _byte_types[_norm(t)]

# The nearest declaration of name at or above line i is a wide element type.
_wide_at(decls, name, i) if {
	ds := [d | some d in decls; d[1] == name; d[0] <= i]
	count(ds) > 0
	idx := max([d[0] | some d in ds])
	some d in ds
	d[0] == idx
	_wide(d[2])
}

# name + i * sizeof(..), name + sizeof(..), name += sizeof(..), name - n*sizeof
_scaled_ops := `(?:^|[^\w.>)\]*&])([A-Za-z_]\w*)\s*(?:\+|-|\+=|-=)\s*\(?\s*(?:[A-Za-z_]\w*\s*\*\s*|\(\s*[^()]*\)\s*\*\s*)?sizeof\b`

_scaled_index := `(?:^|[^\w.>)\]])([A-Za-z_]\w*)\s*\[\s*[A-Za-z_]\w*\s*\*\s*sizeof\b`

_cast_scaled := concat("", [`\(\s*`, _type, `\s*\*\s*\)\s*\(?\s*[A-Za-z_][\w.>-]*\s*\)?\s*(?:\+|-)\s*\(?\s*(?:[A-Za-z_]\w*\s*\*\s*)?sizeof\b`])

# Casts are removed before the plain-pointer test so `(char *)p + sizeof x`
# is judged by its cast, not by p's declaration.
# sizeof(void *) is an operand, not a cast, so it is folded first.
_uncast(code) := regex.replace(regex.replace(code, `\bsizeof\s*\([^()]*\)`, "sizeof SZ"), `\(\s*(?:(?:const|volatile|unsigned|signed|struct|union)\s+)*[A-Za-z_]\w*\s*\*+\s*\)\s*`, "CAST_")

_bad(code, _, _, _) if {
	some m in regex.find_all_string_submatch_n(_cast_scaled, code, -1)
	_wide(m[1])
}

_bad(code, decls, _, i) if {
	some m in regex.find_all_string_submatch_n(_scaled_ops, _uncast(code), -1)
	not startswith(m[1], "CAST_")
	_wide_at(decls, m[1], i)
}

_bad(code, decls, arrs, i) if {
	some m in regex.find_all_string_submatch_n(_scaled_index, _uncast(code), -1)
	_wide_at(array.concat(decls, arrs), m[1], i)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	contains(content, "sizeof")
	regex.match(`(?m)(?:[+-]=?|\[)\s*\(?\s*(?:\w+\s*\*\s*|\([^()]*\)\s*\*\s*)?sizeof\b`, content)
	lines := split(content, "\n")
	decls := _decls(lines)
	arrs := _arr_decls(lines)
	some i, line in lines
	contains(line, "sizeof")
	not helpers.is_comment_line(line)
	code := _code(line)
	_bad(code, decls, arrs, i)
	finding := {
		"rule_id": metadata.id,
		"message": "sizeof() scaling applied to arithmetic on a typed (non-byte) pointer: the compiler already scales by the element size, so the offset is sizeof(T) times too large. Add the element count, or do byte arithmetic on a char/uint8_t pointer",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
