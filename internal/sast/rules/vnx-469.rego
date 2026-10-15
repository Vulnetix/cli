# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_469

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-469",
	"name": "Use of Pointer Subtraction to Determine Size",
	"description": "C or C++ pointer subtraction between two pointers that provably point into different objects, used as a size or distance: two distinct arrays declared with a size in the file (`body - header`, `&outbox[0] - &inbox[0]`), two pointers each assigned from its own allocation (malloc, calloc, strdup, strndup, new T[n]) in the file (`second - first`, including a subtraction broken across two lines), and C++ iterators of two different containers (`std::distance(left.begin(), right.end())`, `right.end() - left.begin()`). The result of subtracting pointers into different objects is undefined, so a length computed this way is garbage. Not reported: subtraction of pointers that may share an object (a pointer derived from a search, `cursor - buf` where cursor = buf + n, struct members such as `s->end - s->start`), element or dereferenced values (`a[i] - b[i]`, `*a - *b`), sizeof expressions, the same container's begin and end, realloc results, pointers whose provenance is not in the file, linked-list node pointers (the CWE's own example, whose provenance a line-oriented rule cannot follow), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-469/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [469],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["pointer-subtraction", "cwe-469"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

# String literals blanked, trailing comments removed.
_code(line) := regex.replace(
	regex.replace(
		regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`),
		`/\*.*?\*/`, " ",
	),
	`//.*$`, "",
)

_operand := `(?:&\s*([A-Za-z_]\w*)\s*\[[^\]]*\]|([A-Za-z_]\w*))`

# a - b where neither side is a member, element or dereference.
_sub_re := concat("", [`(?:^|[^\w.>*&\]])`, _operand, `\s*-\s*`, _operand, `(\s*(?:\[|\.|->|\())?`])

_iter := `(?:c?r?(?:begin|end))\s*\(\s*\)`

_iter_sub_re := concat("", [`\b([A-Za-z_]\w*)\s*(?:\.|->)\s*`, _iter, `\s*-\s*([A-Za-z_]\w*)\s*(?:\.|->)\s*`, _iter])

_distance_re := concat("", [`\bdistance\s*\(\s*([A-Za-z_]\w*)\s*(?:\.|->)\s*`, _iter, `\s*,\s*([A-Za-z_]\w*)\s*(?:\.|->)\s*`, _iter])

_array_decl_re := `(?:^|[\s;{(,])(?:(?:static|const|unsigned|signed|volatile)\s+)*(?:char|int|long|short|float|double|bool|wchar_t|[A-Za-z_]\w*_t|struct\s+\w+)\s+([A-Za-z_]\w*)\s*\[\s*[^\]\s][^\]]*\]`

_alloc_re := `(?:^|[^\w.>])([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?(?:(?:x|g_)?(?:malloc|calloc|zalloc)\s*\(|strn?dup\s*\(|new\s+[\w:]+\s*\[)`

_objects(lines) := [[j, m[1]] |
	some j, l in lines
	_maybe_object(l)
	not helpers.is_comment_line(l)
	some re in [_array_decl_re, _alloc_re]
	some m in regex.find_all_string_submatch_n(re, _code(l), -1)
]

_maybe_object(l) if contains(l, "[")

_maybe_object(l) if contains(l, "alloc")

_maybe_object(l) if contains(l, "dup")

_maybe_object(l) if contains(l, "new ")

# The name's nearest definition above the subtraction is the object itself:
# a later parameter, declaration or assignment of the same name (another
# function reusing `buf`/`end`, `buf = start;`) means it may no longer be
# that object.
_known(lines, objs, name, i) if {
	js := [o[0] | some o in objs; o[1] == name; o[0] < i]
	count(js) > 0
	oj := max(js)
	not _redefined(lines, name, oj, i)
}

_redefined(lines, name, oj, i) if {
	oj + 1 <= i - 1
	some j in numbers.range(oj + 1, i - 1)
	contains(lines[j], name)
	_defines(_code(lines[j]), name)
}

# `char *name,` / `const char *name)` / `int name;` (a typed declarator) or `name = ...`.
_defines(code, name) if {
	some re in [
		concat("", [`\b([A-Za-z_]\w*)\s*[*&]*\s+[*&]*\s*`, name, `\s*(?:[,;)=\[]|$)`]),
		concat("", [`\b([A-Za-z_]\w*)\s*[*&]+\s*`, name, `\s*(?:[,;)=\[]|$)`]),
	]
	some m in regex.find_all_string_submatch_n(re, code, -1)
	not _non_type[m[1]]
}

# Words that precede a name without declaring it (`sizeof header`, `return buf;`).
_non_type := {"sizeof", "return", "case", "goto", "delete", "throw", "alignof", "typeof", "decltype"}

_defines(code, name) if regex.match(concat("", [`(?:^|[^\w.>*])`, name, `\s*=[^=]`]), code)

_name(m, a, b) := m[a] if m[a] != ""

_name(m, a, b) := m[b] if m[a] == ""

# A subtraction broken after the operator continues on the next line.
_joined(lines, i, code) := concat(" ", [code, trim_space(_code(lines[i + 1]))]) if {
	endswith(trim_space(code), "-")
	i + 1 < count(lines)
}

_joined(lines, i, code) := code if not endswith(trim_space(code), "-")

_pointer_sub(text, lines, objs, i) if {
	some m in regex.find_all_string_submatch_n(_sub_re, text, -1)
	trim_space(m[5]) == ""
	a := _name(m, 1, 2)
	b := _name(m, 3, 4)
	a != b
	_known(lines, objs, a, i)
	_known(lines, objs, b, i)
}

_iterator_sub(text) if {
	some re in [_iter_sub_re, _distance_re]
	some m in regex.find_all_string_submatch_n(re, text, -1)
	m[1] != m[2]
}

_cheap(l) if contains(l, "-")

_cheap(l) if contains(l, "distance")

_cand_re := `[\w\])]\s*-\s*(?:&\s*)?[A-Za-z_]|[\w\]]\s*-\s*$|distance\s*\(`

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	regex.match(`(?:alloc\s*\(|strn?dup\s*\(|new\s+[\w:]+\s*\[|begin\s*\(|\w\s+\w+\s*\[\s*\w)`, content)
	lines := split(content, "\n")
	cands := [i |
		some i, l in lines
		_cheap(l)
		regex.match(_cand_re, l)
		not helpers.is_comment_line(l)
	]
	count(cands) > 0
	objs := _objects(lines)
	some i in cands
	line := lines[i]
	text := _joined(lines, i, _code(line))
	_hit(text, lines, objs, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Pointer subtraction between pointers into different objects (separate arrays, separate allocations or different containers' iterators): the result is undefined and cannot be used as a size. Track the length explicitly",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_hit(text, lines, objs, i) if {
	count(objs) > 1
	_pointer_sub(text, lines, objs, i)
}

_hit(text, _, _, _) if {
	regex.match(`(?:begin|end)\s*\(`, text)
	_iterator_sub(text)
}
