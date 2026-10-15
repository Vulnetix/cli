# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_128

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-128",
	"name": "Wrap-around Error",
	"description": "Reports a C/C++ allocation whose size is a multiplication involving a count read from outside the program, with no overflow check, so a large count wraps the size around to a small value and the buffer is then overrun: malloc/xmalloc/alloca(n * size), realloc(p, n * size) and new T[a * b], where n is the result of atoi/atol/strtol/strtoul (and the ll variants), ntohl/ntohs/be*toh/le*toh or getenv, a variable filled by scanf/fscanf/sscanf (&n), fread(&n, ...) or read(fd, &n, ...), within the 20 lines above, or such a call written directly in the product; also size_t bytes = n * size; malloc(bytes). Not reported: calloc and reallocarray (which check the multiplication), a count compared with <, <=, > or >= before the allocation, a SIZE_MAX/INT_MAX bound, __builtin_mul_overflow or ckd_mul, counts that do not come from such a source (internal sizes, constants), comments. Counts that reach the allocation through a function argument or a struct field are out of scope.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-128/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [128],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["wraparound", "integer", "cwe-128"],
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

_src_fn := `(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull|ntohl|ntohs|be16toh|be32toh|be64toh|le16toh|le32toh|le64toh|getenv)`

_src_gate := `\b(?:atoi|atol|atoll|strto[u]?ll?|ntoh[ls]|[bl]e(?:16|32|64)toh|getenv|scanf|fscanf|sscanf|fread|read|recv|pread)\s*\(`

# Names a line fills from outside the program.
_src_names(line) := {v |
	m := regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?(?:std::)?`, _src_fn, `\s*\(`]), line, -1)
	some x in m
	v := x[1]
} | {v |
	regex.match(`\b(?:scanf|fscanf|sscanf)\s*\(`, line)
	m := regex.find_all_string_submatch_n(`&\s*([A-Za-z_]\w*)`, line, -1)
	some x in m
	v := x[1]
} | {v |
	m := regex.find_all_string_submatch_n(`\bfread\s*\(\s*&\s*([A-Za-z_]\w*)`, line, -1)
	some x in m
	v := x[1]
} | {v |
	m := regex.find_all_string_submatch_n(`\b(?:read|recv|pread)\s*\(\s*[^,]+,\s*&\s*([A-Za-z_]\w*)`, line, -1)
	some x in m
	v := x[1]
}

# The size expression of an allocation on this line.
_size(line) := m[1] if {
	m := regex.find_all_string_submatch_n(`\b(?:x?malloc|alloca)\s*\((.*)\)`, line, 1)[0]
}

_size(line) := m[1] if {
	m := regex.find_all_string_submatch_n(`\bx?realloc\s*\([^,]+,(.*)\)`, line, 1)[0]
}

_size(line) := m[1] if {
	m := regex.find_all_string_submatch_n(`\bnew\s+[\w:<>]+\s*\[(.*)\]`, line, 1)[0]
}

_in_product(expr, v) if regex.match(concat("", [`\b`, v, `\b\s*\)?\s*\*|\*\s*\(?\s*(?:\(\s*[\w ]+\)\s*)?`, v, `\b`]), expr)

_bounded(lines, from, to, v) if {
	from <= to
	some k in numbers.range(from, to)
	not helpers.is_comment_line(lines[k])
	regex.match(concat("", [`\b`, v, `\s*(>|>=|<|<=)[^>=]|[^<>](>|>=|<|<=)\s*`, v, `\b|SIZE_MAX|INT_MAX|UINT\d*_MAX|_overflow\s*\(|ckd_mul`]), lines[k])
}

_alloc_line(line) if contains(line, "alloc")

_alloc_line(line) if contains(line, "new ")

_direct(s) if regex.match(concat("", [_src_fn, `\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*\*|\*\s*`, _src_fn, `\s*\(`]), s)

# (A) a source call written directly in the product
findings contains f if {
	some path, lines in _file_lines
	some i, line in lines
	_alloc_line(line)
	contains(line, "*")
	s := _size(line)
	not helpers.is_comment_line(line)
	_direct(s)
	f :=_finding(path, i, line, "Allocation size multiplies a value parsed from input with no overflow check: a large value wraps the size around and the buffer is overrun; use calloc()/reallocarray() or check the count against SIZE_MAX / size first")
}

# (B) a source variable in the product
findings contains f if {
	some path, lines in _file_lines
	some i, line in lines
	_alloc_line(line)
	contains(line, "*")
	s := _size(line)
	not helpers.is_comment_line(line)
	some j in numbers.range(max([0, i - 20]), i - 1)
	regex.match(_src_gate, lines[j])
	not helpers.is_comment_line(lines[j])
	some v in _src_names(lines[j])
	_in_product(s, v)
	not _direct(s)
	not _bounded(lines, j + 1, i - 1, v)
	f := _finding(path, i, line, sprintf("Allocation size multiplies %s, which line %d reads from input, with no overflow check: a large %s wraps the size around and the buffer is overrun; use calloc()/reallocarray() or check %s against SIZE_MAX / size first", [v, j + 1, v, v]))
}

# (C) bytes = n * size; malloc(bytes)
findings contains f if {
	some path, lines in _file_lines
	some i, line in lines
	_alloc_line(line)
	s := trim_space(_size(line))
	regex.match(`^[A-Za-z_]\w*$`, s)
	not helpers.is_comment_line(line)
	some k in numbers.range(max([0, i - 6]), i - 1)
	regex.match(concat("", [`\b`, s, `\s*=[^=;]*\*`]), lines[k])
	not helpers.is_comment_line(lines[k])
	some j in numbers.range(max([0, k - 20]), k - 1)
	regex.match(_src_gate, lines[j])
	not helpers.is_comment_line(lines[j])
	some v in _src_names(lines[j])
	_in_product(lines[k], v)
	not _bounded(lines, j + 1, i - 1, v)
	f := _finding(path, i, line, sprintf("Allocation size %s is %s multiplied with no overflow check, and %s is read from input on line %d: a large value wraps the size around and the buffer is overrun; use calloc()/reallocarray() or check against SIZE_MAX / size first", [s, v, v, j + 1]))
}

# Files worth splitting, computed once for the three checks: an allocation and
# an input source, tested with cheap literal searches.
_file_lines := {path: split(content, "\n") |
	some path, content in input.file_contents
	_is_c(path)
	_has_alloc(content)
	_has_source(content)
}

_has_alloc(content) if {
	some p in {" ", "=", "(", ")", "\t", "x"}
	some a in {"malloc(", "realloc(", "alloca("}
	contains(content, concat("", [p, a]))
}

_has_alloc(content) if regex.match(`new [\w:<>]+ ?\[`, content)

_has_source(content) if {
	some lit in {"atoi(", "atol(", "strtol", "strtoul", "ntohl(", "ntohs(", "toh(", "getenv(", "scanf(", "fread(", "read(", "recv("}
	contains(content, lit)
}
