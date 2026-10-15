# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_125

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-125",
	"name": "Out-of-bounds Read",
	"description": "Reports two C/C++ out-of-bounds reads. (1) An off-by-one loop: for (...; i <= BOUND; ...) whose body reads ARR[i], where BOUND is the declared length of ARR (an array declared ARR[BOUND] in the same file) or sizeof(ARR), sizeof(ARR)/sizeof(ARR[0]), ARRAY_SIZE(ARR), countof/_countof/nitems(ARR); the last iteration reads one element past the end. The for line is reported. (2) A char array filled to its full size by read(), recv(), pread() or fread(..., 1, sizeof(buf), ...), so it holds no terminating NUL, and then passed to a string function (strlen, strdup, strcmp, strstr, strchr, atoi, strtol, puts, printf %s, std::string(...)) within the next lines without buf[n] = '\\0' in between; the string function reads past the buffer. Not reported: i < BOUND, i <= BOUND - 1, loops over a bound unrelated to the indexed array, writes, reads sized sizeof(buf) - 1, buffers terminated before use, binary buffers handled with memcpy, comments. The former rule reported every strcpy/memcpy call; those are not reads past a buffer by themselves and are no longer reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-125/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [125],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["oob-read", "memory", "cwe-125"],
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


# The array a loop bound names directly.
_bound_array(bound) := m[1] if {
	m := regex.find_all_string_submatch_n(`^sizeof\s*\(?\s*([A-Za-z_]\w*)\s*\)?(\s*/\s*sizeof\s*\(?\s*(\*\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*\[\s*0\s*\])\s*\)?)?$`, bound, 1)[0]
}

_bound_array(bound) := m[1] if {
	m := regex.find_all_string_submatch_n(`^(?:ARRAY_SIZE|ARRAYSIZE|countof|_countof|nitems|N_ELEMENTS|COUNT_OF)\s*\(\s*([A-Za-z_]\w*)\s*\)$`, bound, 1)[0]
}

# ARR[idx] read (not the target of a plain assignment) in the loop body.
_reads(line, arr, idx) if regex.match(concat("", [`\b`, arr, `\s*\[\s*`, idx, `\s*\]\s*([^=\s]|==|$)`]), line)

_body(lines, i) := [lines[k] | some k in numbers.range(i, min([count(lines) - 1, i + 5])); not helpers.is_comment_line(lines[k])]

# Every `for (...; i <= BOUND; ...)` in a C file, found with one scan of the
# file (the pattern starts with a literal, so the scan is fast) and located by
# offset, instead of testing every line: [path, line index, idx, bound].
_loop_ml := `for\s*\([^;\n]*;\s*([A-Za-z_]\w*)\s*<=\s*([^;\n]+?)\s*;`

_loops contains [path, ln, m[1], trim_space(m[2])] if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "<=")
	some m in regex.find_all_string_submatch_n(_loop_ml, content, -1)
	some off in indexof_n(content, m[0])
	ln := count(indexof_n(substring(content, 0, off), "\n"))
}

_loop_lines := {path: split(input.file_contents[path], "\n") | some l in _loops; path := l[0]}

# (1a) bound is sizeof/ARRAY_SIZE of the array that is indexed
findings contains f if {
	some l in _loops
	[path, i, idx, bound] := l
	arr := _bound_array(bound)
	lines := _loop_lines[path]
	line := lines[i]
	not helpers.is_comment_line(line)
	some b in _body(lines, i)
	_reads(b, arr, idx)
	f := _finding(path, i, line, sprintf("Loop runs %s up to and including the length of %s (%s): the last iteration reads %s[%s] past the end; use < instead of <=", [idx, arr, bound, arr, idx]))
}

# Cheap substring test before the declaration regex over the whole file.
_declared_lit(content, arr, bound) if contains(content, concat("", [arr, "[", bound, "]"]))

_declared_lit(content, arr, bound) if contains(content, concat("", [arr, " [", bound, "]"]))

_declared_lit(content, arr, bound) if contains(content, concat("", [arr, "[ ", bound, " ]"]))

# (1b) bound is the declared length of the indexed array
findings contains f if {
	some l in _loops
	[path, i, idx, bound] := l
	regex.match(`^([A-Za-z_]\w*|\d+)$`, bound)
	lines := _loop_lines[path]
	line := lines[i]
	not helpers.is_comment_line(line)
	some b in _body(lines, i)
	some r in regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\s*\[\s*`, idx, `\s*\]`]), b, -1)
	arr := r[1]
	_reads(b, arr, idx)
	_declared_lit(input.file_contents[path], arr, bound)
	regex.match(concat("", [`(?m)^[^=(\n]*\b[A-Za-z_]\w*\s+\*?`, arr, `\s*\[\s*`, bound, `\s*\]\s*(;|=)`]), input.file_contents[path])
	f := _finding(path, i, line, sprintf("Loop runs %s up to and including %s, the declared length of %s: the last iteration reads %s[%s] past the end; use < instead of <=", [idx, bound, arr, arr, idx]))
}

# (2) full-size read into a char array, then used as a C string
_has_read(content) if contains(content, "read(")

_has_read(content) if contains(content, "recv(")

_fill_re := `\b(?:read|recv|pread)\s*\(\s*[^,]+,\s*([A-Za-z_]\w*)\s*,\s*sizeof\s*\(?\s*([A-Za-z_]\w*)\s*\)?\s*[,)]`

_fill_re2 := `\bfread\s*\(\s*([A-Za-z_]\w*)\s*,\s*1\s*,\s*sizeof\s*\(?\s*([A-Za-z_]\w*)\s*\)?\s*,`

_filled(line) := m[1] if {
	m := regex.find_all_string_submatch_n(_fill_re, line, 1)[0]
	m[1] == m[2]
}

_filled(line) := m[1] if {
	m := regex.find_all_string_submatch_n(_fill_re2, line, 1)[0]
	m[1] == m[2]
}

_string_use(line, v) if regex.match(concat("", [`\b(strlen|strdup|strstr|strchr|strrchr|strcmp|strncmp|strcasecmp|atoi|atol|atof|strtol|strtoul|puts|string)\s*\(\s*`, v, `\s*[,)]`]), line)

_string_use(line, v) if regex.match(concat("", [`\b(strcpy|strcat|strcmp|strstr)\s*\([^;]*,\s*`, v, `\s*\)`]), line)

_string_use(line, v) if regex.match(concat("", [`printf\s*\(.*%s.*,\s*`, v, `\s*[,)]`]), line)

_terminated(lines, a, b, v) if {
	some k in numbers.range(a, b)
	regex.match(concat("", [`\b`, v, `\s*\[[^\]]+\]\s*=\s*('\\0'|0)\s*;`]), lines[k])
}

findings contains f if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "sizeof")
	_has_read(content)
	lines := split(content, "\n")
	some j, def in lines
	contains(def, "sizeof")
	not helpers.is_comment_line(def)
	v := _filled(def)
	some d in numbers.range(max([0, j - 30]), j - 1)
	regex.match(concat("", [`^\s*(?:static\s+)?char\s+`, v, `\s*\[`]), lines[d])
	some i in numbers.range(j + 1, min([count(lines) - 1, j + 12]))
	not helpers.is_comment_line(lines[i])
	_string_use(lines[i], v)
	not _terminated(lines, j + 1, i, v)
	f := _finding(path, i, lines[i], sprintf("%s was filled to its full size (sizeof(%s)) by a read with no room for a terminating NUL, then used as a C string: the string function reads past the end of the buffer; read sizeof(%s) - 1 bytes and terminate at the returned length", [v, v, v]))
}
