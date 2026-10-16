# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_193

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-193",
	"name": "Off-by-one Error",
	"description": "A C or C++ size or index is one too large or one too small for the terminator or the last element. Reported: malloc/xmalloc/g_malloc (or C++ new char[]) of strlen(s) (or a sum of strlen calls) with no + 1 whose result is then filled by strcpy/strcat/sprintf or terminated; a write to buf[sizeof(buf)] or to name[N] where name is declared name[N]; a for loop whose condition is i <= N or i <= sizeof(arr) and whose body indexes arr[i] where arr is declared arr[N] (or is the sizeof operand); strncat(dst, src, sizeof(dst)) and strncat(dst, src, sizeof(dst) - strlen(dst)), whose bound leaves no room for the terminator; and strncpy(dst, src, strlen(src)), which copies exactly the source length and never terminates the destination. Not reported: + 1 allocations, sizeof(x) - 1 bounds and indices, a malloc(strlen(s)) used for a length-prefixed copy with memcpy and no terminator, loops over an array declared with a larger bound, strings and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-193/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [193],
	"capec": ["CAPEC-100"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["off-by-one", "arithmetic", "buffer", "cwe-193"],
}

_is_c(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_needles := {"strlen", "sizeof", "<=", "]"}

# String and character literals blanked, so a message is not code.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `'x'`)

_esc(s) := replace(replace(s, ".", `\.`), "*", `\*`)

_decl_re := `^\s*(?:(?:static|const|unsigned|signed|volatile|extern|struct\s+\w+|enum\s+\w+)\s+)*(?:char|int|short|long|float|double|u?int\d+_t|size_t|bool|unsigned|BYTE|wchar_t|uchar|u_char)\s+\*?\s*(\w+)\s*\[\s*([A-Za-z_]\w*|\d+)\s*\]`

# Every array declaration of the file, in one pass over the content.
_decls(content) := {[m[1], m[2]] |
	some m in regex.find_all_string_submatch_n(concat("", ["(?m)", _decl_re]), content, -1)
}

_line_needles := {"sizeof", "<=", "strncat", "strncpy", "malloc", "] =", "]=", "new char", "new wchar_t"}

_line_gate(line) if {
	some n in _line_needles
	contains(line, n)
}

_msg := "Off-by-one: this size or index leaves no room for the string terminator or reaches one element past the end of the array. Allocate strlen(s) + 1, bound strncat by sizeof(dst) - strlen(dst) - 1, index at most size - 1, and loop with i < N"

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	_has_any(content)
	lines := split(content, "\n")
	decls := _decls(content)
	some i, line in lines
	_line_gate(line)
	not helpers.is_comment_line(line)

	_off_by_one(lines, i, line, decls)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# buf[sizeof(buf)] = ...
_off_by_one(_, _, c, _) if {
	contains(c, "sizeof")
	m := regex.find_all_string_submatch_n(`(\w+)\s*\[\s*sizeof\s*(?:\(\s*(\w+)\s*\)|(\w+))\s*\]\s*=[^=]`, c, -1)
	some k
	m[k][1] == concat("", [m[k][2], m[k][3]])
}

# name[N] = ... where name is declared name[N]: a macro bound anywhere in the
# file, a numeric bound only in a declaration a few lines up in the same block.
_off_by_one(lines, i, c, decls) if {
	contains(c, "]")
	m := regex.find_all_string_submatch_n(`(\w+)\s*\[\s*([A-Za-z_]\w*|\d+)\s*\]\s*=[^=]`, c, -1)
	some k
	[m[k][1], m[k][2]] in decls
	not regex.match(_decl_re, c)
	_same_scope(lines, i, m[k][1], m[k][2])
}

# rec.name[N] = ... / p->name[N] = ... where a struct member is declared name[N]
# and every declaration of that name in the file has that bound.
_off_by_one(_, _, c, decls) if {
	contains(c, "]")
	m := regex.find_all_string_submatch_n(`(?:\.|->)\s*(\w+)\s*\[\s*(\d+)\s*\]\s*=[^=]`, c, -1)
	some k
	[m[k][1], m[k][2]] in decls
	_all_same_bound(decls, m[k][1], m[k][2])
}

_all_same_bound(decls, name, n) if {
	every d in decls {
		not _other_bound(d, name, n)
	}
}

_same_scope(_, _, _, n) if not regex.match(`^\d+$`, n)

_same_scope(lines, i, name, n) if {
	regex.match(`^\d+$`, n)
	some j in numbers.range(max([0, i - 40]), i - 1)
	ds := regex.find_all_string_submatch_n(_decl_re, lines[j], 1)
	count(ds) > 0
	ds[0][1] == name
	ds[0][2] == n
	not _block_ends(lines, j, i)
}

_block_ends(lines, j, i) if {
	some k in helpers.span(j + 1, i - 1)
	startswith(lines[k], "}")
}

# for (...; i <= N; ...) arr[i] with arr declared arr[N], or i <= sizeof(arr)
_off_by_one(lines, i, c, decls) if {
	contains(c, "<=")
	m := regex.find_all_string_submatch_n(`\bfor\s*\([^;]*;\s*(\w+)\s*<=\s*(?:sizeof\s*(?:\(\s*(\w+)\s*\)|(\w+))|([A-Za-z_]\w*|\d+))\s*;`, c, 1)
	count(m) > 0
	v := m[0][1]
	some arr in _loop_arrays(m[0], decls)
	body := concat("\n", array.slice(lines, i, min([count(lines), i + 4])))
	regex.match(concat("", [`\b`, arr, `\s*\[\s*`, v, `\s*\]`]), body)
}

_loop_arrays(g, _) := {s} if {
	s := concat("", [g[2], g[3]])
	s != ""
}

_loop_arrays(g, decls) := {d[0] | some d in decls; d[1] == g[4]} if concat("", [g[2], g[3]]) == ""

# strncat(dst, src, sizeof(dst)) and strncat(dst, src, sizeof(dst) - strlen(dst))
_off_by_one(_, _, line, _) if {
	contains(line, "strncat")
	c := _code(line)
	m := regex.find_all_string_submatch_n(`\bstrncat\s*\(\s*([\w.>-]+)\s*,[^,]+,\s*sizeof\s*(?:\(\s*([\w.>-]+)\s*\)|([\w.>-]+))\s*(?:-\s*strlen\s*\(\s*([\w.>-]+)\s*\)\s*)?\)`, c, -1)
	some k
	m[k][1] == concat("", [m[k][2], m[k][3]])
	m[k][4] in {"", m[k][1]}
}

# strncpy(dst, src, strlen(src))
_off_by_one(_, _, line, _) if {
	contains(line, "strncpy")
	c := _code(line)
	m := regex.find_all_string_submatch_n(`\bstrncpy\s*\([^,]+,\s*([^,]+?)\s*,\s*(?:std::)?strlen\s*\(\s*([^()]+?)\s*\)\s*\)`, c, -1)
	some k
	m[k][1] == m[k][2]
}

# p = malloc(strlen(s)) with no + 1, then used as a C string.
_off_by_one(lines, i, line, _) if {
	contains(line, "strlen")
	c := _code(line)
	m := regex.find_all_string_submatch_n(`(\w+(?:(?:->|\.)\w+)*)\s*=\s*(?:(?:\([^()]*\)\s*)?(?:std::)?(?:malloc|xmalloc|g_malloc|zmalloc|av_malloc)\s*\(\s*(?:(?:std::)?strlen\s*\([^()]*\)\s*\+?\s*)+\)|new\s+(?:char|wchar_t)\s*\[\s*(?:(?:std::)?strlen\s*\([^()]*\)\s*\+?\s*)+\])`, c, 1)
	count(m) > 0
	p := _esc(m[0][1])
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
	not helpers.is_comment_line(lines[j])
	regex.match(concat("", [`\b(?:strcpy|strcat|sprintf|stpcpy)\s*\(\s*`, p, `\s*,|(?:^|[^\w>.])`, p, `\s*\[[^\]]+\]\s*=\s*(?:'\\0'|0)\s*;`]), lines[j])
}

_has_any(content) if {
	some n in _needles
	contains(content, n)
}

_other_bound(d, name, n) if {
	d[0] == name
	d[1] != n
}
