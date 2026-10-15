# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_823

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-823",
	"name": "Use of Out-of-range Pointer Offset",
	"description": "Reports C and C++ pointer offsets and indexes that are out of range by construction: an array indexed at its own size or element count (buf[sizeof(buf)], buf[sizeof buf], names[ARRAY_SIZE(names)] / _countof / std::size / N_ELEMENTS, slots[sizeof(slots) / sizeof(slots[0])], one element past the end); a pointer or array of a non-byte type offset by a sizeof value (values + sizeof(values), hdr + sizeof(struct header), words + sizeof(uint32_t) * n), which pointer arithmetic scales a second time by the element size; and a for loop whose condition is i <= sizeof(arr), i <= ARRAY_SIZE(arr) / _countof(arr) / std::size(arr), or i <= v.size() / v.length() and whose header or next eight lines index that same array with the loop variable, reaching one element past the end. Not reported: the one-past-the-end address &buf[sizeof(buf)] and byte pointers (char, unsigned char, uint8_t, void) plus sizeof, a pointer cast to a byte pointer before the addition ((uint8_t *)hdr + sizeof(*hdr)), pointer offsets by element counts (a + sizeof(a) / sizeof(a[0])), sizeof(x) - 1 bounds, a <= loop that indexes a different array, offsets computed from runtime lengths (no dataflow), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-823/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [823],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["oor-pointer-offset", "cwe-823", "c", "cpp", "memory-safety"],
}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, line)

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_strip(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$|/\*.*?\*/`, "")

# Types whose pointer arithmetic is byte arithmetic.
_byte_types := {"char", "uint8_t", "int8_t", "u8", "u_char", "uchar", "BYTE", "byte", "gchar", "guchar", "void", "std::byte", "char8_t", "Byte", "UInt8"}

_not_types := {"return", "sizeof", "case", "else", "goto", "typedef", "throw", "delete", "new", "do"}

# Every type the file declares `name` with, as a pointer or an array.
_decl_types(content, name) := {t |
	some re in [
		concat("", [`(?m)(?:^|[ \t(,;{])(?:(?:const|volatile|static|unsigned|signed|struct|enum|union|register)[ \t]+)*([A-Za-z_][\w:]*)[ \t]*(?:\*[ \t]*(?:const[ \t]*)?)+`, name, `[ \t]*[;,)=\[]`]),
		concat("", [`(?m)(?:^|[ \t(,;{])(?:(?:const|volatile|static|unsigned|signed|struct|enum|union|register)[ \t]+)*([A-Za-z_][\w:]*)[ \t]+`, name, `[ \t]*\[`]),
	]
	some m in regex.find_all_string_submatch_n(re, content, -1)
	t := m[1]
	not t in _not_types
}

_non_byte_decl(content, name) if {
	ts := _decl_types(content, name)
	count(ts) > 0
	count({t | some t in ts; t in _byte_types}) == 0
}

# Shape A: an array indexed at its own size.
_shape(_, lines, i, code) := "an array is indexed at its own size, one element past its end; the last element is at sizeof(buf) - 1" if {
	contains(code, "sizeof")
	some m in regex.find_all_string_submatch_n(`(&\s*)?\b([A-Za-z_]\w*)\s*\[\s*sizeof\s*\(?\s*([A-Za-z_]\w*)\s*\)?\s*\]`, code, -1)
	m[1] == ""
	m[2] == m[3]
}

# Shape B: a non-byte pointer offset by a sizeof value (scaled twice).
_shape(content, lines, i, code) := "a pointer to a non-byte type is offset by a sizeof value, which pointer arithmetic multiplies by the element size again; offset by an element count or cast to a byte pointer first" if {
	contains(code, "sizeof")
	some m in regex.find_all_string_submatch_n(`(\)\s*|\*\s*|\.\s*|->\s*|&\s*)?\b([A-Za-z_]\w*)\s*\+\s*sizeof\s*(?:\((?:[^()]|\([^()]*\))*\)|\s+[\w\[\]*.>-]+)\s*(\S?)`, code, -1)
	m[1] == ""
	m[3] != "/"
	_non_byte_decl(content, m[2])
}

# Shape C: an inclusive loop bound at the array's size, indexing that array.
_shape(_, lines, i, code) := "the loop runs while the index is <= the array's size and indexes the array with it, so the last iteration reads or writes one element past the end; use <" if {
	contains(code, "<=")
	m := regex.find_all_string_submatch_n(`\bfor\s*\([^;]*;\s*([A-Za-z_]\w*)\s*<=\s*(?:sizeof\s*\(?\s*([A-Za-z_]\w*)\s*\)?|(?:ARRAY_SIZE|N_ELEMENTS|_countof|countof|std::size|G_N_ELEMENTS)\s*\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*)\s*(?:\.|->)\s*(?:size|length)\s*\(\s*\))\s*;`, code, 1)
	count(m) > 0
	idx := m[0][1]
	arr := concat("", [m[0][2], m[0][3], m[0][4]])
	arr != ""
	body := helpers.code_window(lines, i, 0, 8)
	regex.match(concat("", [`\b`, arr, `\s*\[\s*`, idx, `\s*\]`]), body)
}

# Shape A': an array indexed at its own element count.
_count_macro := `(?:ARRAY_SIZE|N_ELEMENTS|_countof|countof|std::size|G_N_ELEMENTS|ARRAYSIZE|nitems)`

_shape(_, lines, i, code) := "an array is indexed at its own element count, one element past its end; the last element is at the count minus one" if {
	some m in regex.find_all_string_submatch_n(concat("", [`(&\s*)?\b([A-Za-z_]\w*)\s*\[\s*`, _count_macro, `\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\]`]), code, -1)
	m[1] == ""
	m[2] == m[3]
}

_shape(_, lines, i, code) := "an array is indexed at its own element count, one element past its end; the last element is at the count minus one" if {
	contains(code, "sizeof")
	some m in regex.find_all_string_submatch_n(`(&\s*)?\b([A-Za-z_]\w*)\s*\[\s*sizeof\s*\(?\s*([A-Za-z_]\w*)\s*\)?\s*/\s*sizeof\s*\(\s*\*?\s*([A-Za-z_]\w*)\s*(?:\[\s*0\s*\])?\s*\)\s*\]`, code, -1)
	m[1] == ""
	m[2] == m[3]
	m[3] == m[4]
}

findings contains finding if {
	some path, content in input.file_contents
	some x in _exts
	endswith(path, x)
	regex.match(`\[\s*(?:sizeof|ARRAY_SIZE|N_ELEMENTS|_countof|countof|std::size|G_N_ELEMENTS|ARRAYSIZE|nitems)\b|\+\s*sizeof|<=\s*(?:sizeof|ARRAY_SIZE|N_ELEMENTS|_countof|countof|std::size|G_N_ELEMENTS|[A-Za-z_]\w*\s*(?:\.|->)\s*(?:size|length)\s*\()`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\[\s*(?:sizeof|ARRAY_SIZE|N_ELEMENTS|_countof|countof|std::size|G_N_ELEMENTS|ARRAYSIZE|nitems)\b|\+\s*sizeof|<=`, line)
	not _is_comment(line)
	code := _strip(line)
	some msg in {s | s := _shape(content, lines, i, code)}
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
