# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_680

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-680",
	"name": "Integer Overflow to Buffer Overflow",
	"description": "A C or C++ heap or stack allocation whose size is a multiplication involving a count read from outside the program, with no overflow or range check in between, so a large count wraps the product and the buffer is allocated far smaller than the code then writes. Reported: malloc, realloc, alloca, xmalloc, g_malloc, kmalloc, vmalloc, HeapAlloc, LocalAlloc and GlobalAlloc, and C++ new T[...], whose size multiplies a value parsed or received on the same line (atoi, strtol and friends, ntohl/ntohs/beNNtoh, getenv) or a variable that one of the 20 lines above assigned from such a call or filled through scanf/fscanf/sscanf, fread, read, recv/recvfrom, ReadFile or std::cin >>; also an allocation sized by a variable that one of the 10 lines above computed as such a product (size_t bytes = n * sizeof *e; malloc(bytes)). A comparison only against 0 or 1 (n <= 0, n > 0) bounds nothing and does not count as a check. Not reported: calloc and reallocarray (which check the product), a product of constants or of internal counts, a count compared against any other bound (<, >, <=, >= or == on the variable) or guarded by SIZE_MAX, INT_MAX, __builtin_mul_overflow or ckd_mul between the read and the allocation, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-680/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [680],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["integer-overflow-to-buffer", "cwe-680"],
}

_is_c(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_alloc_re := `(?:^|[^\w.>])(?:std::)?(?:malloc|realloc|alloca|_alloca|xmalloc|xrealloc|g_malloc|g_malloc0|g_realloc|kmalloc|kzalloc|vmalloc|HeapAlloc|LocalAlloc|GlobalAlloc)\s*\(|\bnew\s+[\w:<>]+\s*\[`

_parse_re := `\b(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull|strtoumax|ntohl|ntohs|be16toh|be32toh|be64toh|le16toh|le32toh|le64toh|getenv)\s*\(`

_fill_re := `(?:^|[^\w])(?:scanf|fscanf|sscanf|fread|read|recv|recvfrom|ReadFile)\s*\(`

_blank(s) := regex.replace(regex.replace(s, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# The allocation's size text: from the call to the end of the statement (the
# next line too when the call is broken), with sizeof terms collapsed so a
# pointer type inside sizeof is not read as a multiplication.
_size_text(lines, i) := t if {
	line := _blank(lines[i])
	m := regex.find_all_string_submatch_n(concat("", [`(?:`, _alloc_re, `)(.*)$`]), line, 1)
	count(m) > 0
	rest := m[0][1]
	full := _with_next(lines, i, rest)
	t := regex.replace(regex.replace(full, `sizeof\s*\([^()]*\)`, "SZ"), `sizeof\s+\*?\s*[\w.>-]+`, "SZ")
}

_with_next(_, _, rest) := rest if contains(rest, ";")

_with_next(lines, i, rest) := concat(" ", [rest, _blank(lines[i + 1])]) if {
	not contains(rest, ";")
	i + 1 < count(lines)
}

_with_next(lines, i, rest) := rest if {
	not contains(rest, ";")
	i + 1 >= count(lines)
}

_has_product(t) if regex.match(`[\w\)\]]\s*\*\s*[\w(]`, t)

# Variables assigned from a parse/byte-order call, or filled through a read.
_sourced(lines, i) := {[v, j] |
	some j in numbers.range(max([0, i - 20]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_parse_re, l)
	v := helpers.assigned_first(l)
} | {[v, j] |
	some j in numbers.range(max([0, i - 20]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_fill_re, l)
	some g in regex.find_all_string_submatch_n(`&\s*(\w+)\b`, l, -1)
	v := g[1]
} | {[v, j] |
	some j in numbers.range(max([0, i - 20]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	contains(l, "cin")
	some g in regex.find_all_string_submatch_n(`>>\s*(\w+)`, l, -1)
	v := g[1]
}

_guard_re := `SIZE_MAX|INT_MAX|UINT_MAX|UINT32_MAX|SSIZE_MAX|__builtin_mul_overflow|ckd_mul|_overflow\s*\(`

_guarded(lines, j, i, v) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(concat("", [`\b`, v, `\s*(?:[<>]=?|==)\s*[\w(-]|[\w)]\s*[<>]=?\s*`, v, `\b`]), l)
	_upper_cmp(l, v)
}

# A comparison only against 0 or 1 (n <= 0, n > 0, n == 0) rejects a missing
# or negative count but bounds nothing, so it is not a guard.
_low := {"0", "1", "-1", "0U", "0u", "0L"}

_upper_cmp(l, v) if {
	some g in regex.find_all_string_submatch_n(concat("", [`\b`, v, `\s*(?:[<>]=?|==)\s*(-?[\w(]+)`]), l, -1)
	not g[1] in _low
}

_upper_cmp(l, v) if {
	some g in regex.find_all_string_submatch_n(concat("", [`(-?[\w)]+)\s*[<>]=?\s*`, v, `\b`]), l, -1)
	not g[1] in _low
}

_guarded(lines, j, i, _) if {
	some k in numbers.range(j, i)
	regex.match(_guard_re, lines[k])
}

_bad(_, _, t) if regex.match(_parse_re, t)

# The size is a variable that one of the 10 lines above computed as a product
# (size_t bytes = n * sizeof *e; p = malloc(bytes);).
_bad_via_var(lines, i, t) if {
	not _has_product(t)
	some g in regex.find_all_string_submatch_n(`^\s*(\w+)\s*[),]`, t, 1)
	v := g[1]
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	contains(l, v)
	contains(l, "*")
	not helpers.is_comment_line(l)
	some a in regex.find_all_string_submatch_n(concat("", [`(?:^|[\s(])`, v, `\s*=\s*([^=;][^;]*)`]), _blank(l), 1)
	rhs := regex.replace(regex.replace(a[1], `sizeof\s*\([^()]*\)`, "SZ"), `sizeof\s+\*?\s*[\w.>-]+`, "SZ")
	_has_product(rhs)
	_bad(lines, i, rhs)
}

_flag(lines, i, t) if {
	_has_product(t)
	_bad(lines, i, t)
}

_flag(lines, i, t) if _bad_via_var(lines, i, t)

_bad(lines, i, t) if {
	some pair in _sourced(lines, i)
	v := pair[0]
	regex.match(concat("", [`\b`, v, `\b`]), t)
	not _guarded(lines, pair[1], i, v)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(`alloc|new\s`, content)
	regex.match(`\b(?:ato|strto|ntoh|be\d\dtoh|le\d\dtoh|getenv|scanf|fread|read|recv|ReadFile|cin)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`alloc|new\s`, line)
	not helpers.is_comment_line(line)
	t := _size_text(lines, i)
	_flag(lines, i, t)
	finding := {
		"rule_id": metadata.id,
		"message": "Allocation size multiplies an externally supplied count with no overflow check; a large count wraps the product and the buffer is too small. Use calloc/reallocarray or check count > SIZE_MAX / size first",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
