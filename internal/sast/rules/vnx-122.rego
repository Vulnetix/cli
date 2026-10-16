# SPDX-License-Identifier: Apache-2.0
# CWE-122: Heap-based Buffer Overflow

package vulnetix.rules.vnx_122

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-122",
	"name": "Heap-based buffer overflow from an undersized string allocation",
	"description": "Reports two C/C++ shapes that overflow a heap buffer. (1) A string buffer allocated with malloc/xmalloc, calloc(n, 1) or new char[] (std:: forms included) sized by strlen() alone (or a sum of strlen() calls, or a variable assigned from strlen() just above) with no + 1 for the terminator, which a strcpy/strcat/sprintf/stpcpy into that buffer within the next lines then overruns by one byte; the allocation line is reported. (2) A heap buffer allocated with a fixed size (a number, an upper-case constant or a sizeof) that then receives an unbounded copy: strcpy/strcat from a non-literal source, gets(), or sprintf with an unbounded %s (also when the call breaks after the destination); the copy line is reported. Not reported: allocations with + 1, byte buffers filled with memcpy, strcpy/strcat of a string literal, copies preceded by a strlen()/strnlen() length check between the allocation and the copy, strncpy/snprintf/strdup, %.Ns precision, comments and string literals. Overflows of stack buffers, computed sizes and flows across functions are out of scope.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-122/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [122],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["heap-overflow", "memory", "c", "cwe-122"],
}

_exts := {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}

_is_c(path) if {
	some ext in _exts
	endswith(path, ext)
}

# `X = (cast) malloc(SIZE);` or `X = new char[SIZE];` -> [X, SIZE]
_alloc(line) := [m[1], m[2]] if {
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?(?:std::)?(?:malloc|xmalloc)\s*\((.+)\)\s*;`, line, 1)[0]
}

_alloc(line) := [m[1], m[2]] if {
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*new\s+(?:unsigned\s+)?char\s*\[(.+)\]\s*;`, line, 1)[0]
}

# `X = (cast) calloc(SIZE, 1);` (one-byte elements) -> [X, SIZE]
_alloc(line) := [m[1], m[2]] if {
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?(?:std::)?x?calloc\s*\(([^,]+),\s*(?:1|sizeof\s*\(\s*char\s*\))\s*\)\s*;`, line, 1)[0]
}

# Whole-file and per-line gates: an allocation of the shape each check needs.
_gate_strlen := `\b(?:x?[mc]alloc\s*\(|new\s+(?:unsigned\s+)?char\s*\[)\s*(?:(?:std::)?strlen\s*\(|[A-Za-z_]\w*\s*[\)\]]\s*;)`

_gate_fixed := `\b(?:x?[mc]alloc\s*\(|new\s+(?:unsigned\s+)?char\s*\[)\s*(?:\d|[A-Z_][A-Z0-9_]*\s*[\)\]*,]|sizeof)`

# Cheap literal pre-gate (zmalloc/je_malloc wrappers are not this shape).
_has_alloc(content) if contains(content, "= malloc")

_has_alloc(content) if contains(content, "=malloc")

_has_alloc(content) if contains(content, ") malloc")

_has_alloc(content) if contains(content, ")malloc")

_has_alloc(content) if contains(content, "xmalloc")

_has_alloc(content) if contains(content, "new char")

_has_alloc(content) if contains(content, "new unsigned char")

_has_alloc(content) if contains(content, "calloc(")

_has_alloc(content) if contains(content, "std::malloc")

_maybe_alloc(line) if contains(line, "alloc")

_maybe_alloc(line) if contains(line, "new ")

_strlen_only := `^\s*(?:std::)?strlen\s*\([^()]*\)(\s*\+\s*(?:std::)?strlen\s*\([^()]*\))*\s*$`

_strlen_size(_, _, size) if regex.match(_strlen_only, size)

# `len = strlen(s);` just above, then malloc(len)
_strlen_size(lines, i, size) if {
	regex.match(`^\s*[A-Za-z_]\w*\s*$`, size)
	v := trim_space(size)
	some j in numbers.range(max([0, i - 5]), i - 1)
	not helpers.is_comment_line(lines[j])
	regex.match(concat("", [`\b`, v, `\s*=\s*strlen\s*\([^()]*\)\s*;`]), lines[j])
}

_fixed_size(size) if regex.match(`^\s*(\d+|[A-Z_][A-Z0-9_]*|sizeof\s*\(?\s*[\w\s\*]+\)?)(\s*\*\s*sizeof\s*\(\s*char\s*\))?\s*$`, size)

_string_write(line, v) if regex.match(concat("", [`\b(strcpy|strcat|sprintf|stpcpy)\s*\(\s*`, v, `\s*,`]), line)

# unbounded copy into v from something that is not a literal
_unbounded_copy(line, v) if regex.match(concat("", [`\b(strcpy|strcat|stpcpy)\s*\(\s*`, v, `\s*,\s*[^"\s]`]), line)

_unbounded_copy(line, v) if regex.match(concat("", [`\bgets\s*\(\s*`, v, `\s*\)`]), line)

_unbounded_copy(line, v) if regex.match(concat("", [`\bsprintf\s*\(\s*`, v, `\s*,\s*"[^"]*%s`]), line)

# The copy call's text, joined with the next line when the call breaks after `dst,`.
_copy_text(lines, j) := concat(" ", [lines[j], lines[j + 1]]) if {
	j + 1 < count(lines)
	endswith(trim_space(lines[j]), ",")
} else := lines[j]

_checked_between(lines, a, b) if {
	a + 1 <= b - 1
	some k in helpers.span(a + 1, b - 1)
	regex.match(`\bstrn?len\s*\(`, lines[k])
	not helpers.is_comment_line(lines[k])
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

# (1) strlen-sized allocation receiving a string copy
findings contains f if {
	some path, content in input.file_contents
	_is_c(path)
	_has_alloc(content)
	contains(content, "strlen")
	regex.match(_gate_strlen, content)
	lines := split(content, "\n")
	some i, line in lines
	_maybe_alloc(line)
	regex.match(_gate_strlen, line)
	not helpers.is_comment_line(line)
	a := _alloc(line)
	_strlen_size(lines, i, a[1])
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
	_string_write(lines[j], a[0])
	not helpers.is_comment_line(lines[j])
	f := _finding(path, i, line, sprintf("%s is allocated with strlen() and no room for the terminating NUL, then written as a string: the copy overflows the heap buffer by one byte; allocate strlen() + 1", [a[0]]))
}

# (2) fixed-size heap buffer receiving an unbounded copy
findings contains f if {
	some path, content in input.file_contents
	_is_c(path)
	_has_alloc(content)
	regex.match(_gate_fixed, content)
	regex.match(`\b(strcpy|strcat|stpcpy|gets|sprintf)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	_maybe_alloc(line)
	regex.match(_gate_fixed, line)
	not helpers.is_comment_line(line)
	a := _alloc(line)
	_fixed_size(a[1])
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 15]))
	_unbounded_copy(_copy_text(lines, j), a[0])
	not helpers.is_comment_line(lines[j])
	not _checked_between(lines, i, j)
	f := _finding(path, j, lines[j], sprintf("Unbounded copy into the fixed-size heap buffer %s (allocated as %s): input longer than the allocation overflows the heap; use a bounded copy (snprintf, strlcpy) or size the buffer from the input", [a[0], trim_space(a[1])]))
}
