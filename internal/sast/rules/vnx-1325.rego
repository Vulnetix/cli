# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1325

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1325",
	"name": "Improperly Controlled Sequential Memory Allocation",
	"description": "An allocation (Go make([]T, n)/map/chan, Java new byte[n]/char[n]/int[n]/long[n] and ByteBuffer.allocate/allocateDirect, C/C++ malloc/calloc/realloc and new T[n]) is sized by a value that arrived from outside the program (a parsed request parameter or header, Content-Length, a binary length prefix, ntohl/be32toh/atoi/strtol/strtoull, a command-line argument, or a variable filled through &n by binary.Read/fread/recv/scanf) with no upper bound checked first, or a loop whose iteration count is such a value allocates on every pass. An attacker who controls the size or the count can exhaust memory and cause denial of service. Not reported: sizes taken from len()/sizeof/length of data already in memory, constants, values the program computed itself, a size compared against a maximum in an if/assert above the allocation (a check of zero or a lower bound only does not count), a size clamped with min()/Math.min, test files and comments. Taint is followed one assignment within 25 lines; flows through helper functions are not.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1325/",
	"languages": ["c", "cpp", "go", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1325],
	"capec": ["CAPEC-130"],
	"attack_technique": ["T1499"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["memory", "allocation", "dos", "loop", "cwe-1325"],
}

# ── Languages ────────────────────────────────────────────────────────────

_c_exts := {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "c" if {
	some ext in _c_exts
	endswith(path, ext)
}

# ── Sources of attacker-controlled sizes ─────────────────────────────────

# Go: a number parsed from text, a length header or prefix, a request value.
_source := {
	"go": `(strconv\.(Atoi|ParseInt|ParseUint)\(|ContentLength|Content-Length|\.FormValue\(|\.PostFormValue\(|URL\.Query\(\)|binary\.(BigEndian|LittleEndian)\.Uint|binary\.Read\(|ReadUvarint|ReadVarint|os\.Args|\bflag\.(Int|Uint)|\.Header\.Get\()`,
	"java": `(getContentLength|getIntHeader\(|getParameter\(|getHeader\(|readInt\(|readLong\(|parseInt\(|parseLong\(|Integer\.valueOf\()`,
	"c": `(atoi\(|atol\(|atoll\(|strtou?ll?\(|strtoimax\(|strtoumax\(|ntohl\(|ntohs\(|be(?:16|32|64)toh\(|le(?:16|32|64)toh\(|argv\[|fread\(|recv\(|scanf\()`,
}

# ── Allocation sites and their size expressions ──────────────────────────

_alloc := {
	"go": `\bmake\(\s*(?:\[\]|map\[|chan\s)`,
	"java": `\bnew\s+(?:byte|char|int|long|short)\s*\[|\bByteBuffer\.allocate(?:Direct)?\s*\(`,
	"c": `\b(?:malloc|calloc|realloc)\s*\(|\bnew\s+[\w:]+\s*\[`,
}

_size_res := {
	"go": [`\bmake\(\s*(?:\[\][^,()]*|map\[[^\]]*\][^,()]*|chan\s+[^,()]*)\s*,\s*(.*)$`],
	"java": [`\bnew\s+(?:byte|char|int|long|short)\s*\[\s*([^\]]+)\]`, `\bByteBuffer\.allocate(?:Direct)?\s*\(([^;]*)\)`],
	"c": [`\b(?:malloc|calloc|realloc)\s*\(([^;]*)\)`, `\bnew\s+[\w:]+\s*\[\s*([^\]]+)\]`],
}

# A size that is only the length of something already held is not amplification.
_strip_len(s) := regex.replace(s, `\b(len|cap|sizeof|length|size)\s*\([^()]*\)`, "")

_sizes(lang, line) := {s |
	some re in _size_res[lang]
	some m in regex.find_all_string_submatch_n(re, line, -1)
	s := _strip_len(m[1])
	regex.match(`[A-Za-z_]`, s)
}

# ── Taint ────────────────────────────────────────────────────────────────

# The names a source line fills: the assigned name (including C declarations
# with several type words such as `unsigned long long n = strtoull(...)`), and
# an out-parameter written by binary.Read/fread/recv/scanf (`&n`).
_src_names(l) := {v | v := helpers.assigned_first(l)} | {v |
	some m in regex.find_all_string_submatch_n(`^\s*(?:(?:const|unsigned|signed|long|short|static|volatile|struct)\s+)+[A-Za-z_]\w*(?:\s+|\s*\*+\s*)([A-Za-z_]\w*)\s*=[^=]`, l, 1)
	v := m[1]
} | {v |
	some m in regex.find_all_string_submatch_n(`\b(?:binary\.Read|fread|recv|scanf|sscanf|fscanf)\s*\([^&;]*&\s*([A-Za-z_]\w*)`, l, 1)
	v := m[1]
}

_word(v) := concat("", [`\b`, v, `\b`])

_clamped(s) if regex.match(`(?i)\bmin\s*\(`, s)

# The source lines near an allocation and the variables they assign are
# computed once per allocation line: src_idx holds line indices, srcs holds
# [line index, assigned name]. The window reaches 40 lines up so that a loop
# header up to 15 lines above can be linked to an assignment 25 lines above it.

# The size expression itself reads the source…
_tainted(lang, _, _, _, size) if {
	regex.match(_source[lang], size)
	not _clamped(size)
}

# …or names a variable that a nearby line assigned from one, unchecked.
_tainted(_, lines, srcs, i, size) if {
	some [j, v] in srcs
	j < i
	j >= i - 25
	contains(size, v)
	regex.match(_word(v), size)
	not _bounded(lines, i, v)
}

# An if/assert above compares v against an upper limit, or v was clamped.
_bounded(lines, i, v) if {
	some k in numbers.range(max([0, i - 25]), i - 1)
	l := lines[k]
	contains(l, v)
	regex.match(`^\s*(?:\}\s*)?(?:else\s+)?(?:if\b|assert|require|check|Preconditions\.)`, l)
	not helpers.is_comment_line(l)
	_upper_cmp(l, v)
}

_bounded(lines, i, v) if {
	some k in numbers.range(max([0, i - 25]), i - 1)
	l := lines[k]
	contains(l, v)
	_clamped(l)
	helpers.assigned_first(l) == v
}

_upper_cmp(l, v) if regex.match(concat("", [_word(v), `\s*>=?\s*[1-9A-Za-z_(]`]), l)

_upper_cmp(l, v) if regex.match(concat("", [`(?:[A-Za-z_)]|[1-9]\d*)\s*<=?\s*`, _word(v)]), l)

# ── Allocation inside a loop whose bound comes from outside ──────────────
# The size can be a constant: `for i < n { buf = malloc(4096) }` allocates
# n*4096 bytes, and n is the attacker's. The `for` header must sit above the
# allocation at a shallower indent, so a loop that has already ended does not
# count.

_indent(l) := count(l) - count(trim_left(l, " \t"))

_for_bound_tainted(src_idx, _, lines, j) if {
	j in src_idx
	not _clamped(lines[j])
}

_for_bound_tainted(_, srcs, lines, j) if {
	some [k, v] in srcs
	k < j
	k >= j - 25
	contains(lines[j], v)
	regex.match(_word(v), lines[j])
	not _bounded(lines, j, v)
}

_in_tainted_loop(src_idx, srcs, lines, i) if {
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	startswith(trim_left(lines[j], " \t"), "for")
	regex.match(`^\s*for\b`, lines[j])
	_indent(lines[j]) < _indent(lines[i])
	_for_bound_tainted(src_idx, srcs, lines, j)
	not _capped_in_loop(lines, j, i)
}

# The loop body checks a running total or the count against a limit before
# allocating.
_capped_in_loop(lines, j, i) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	regex.match(`^\s*(?:\}\s*)?(?:else\s+)?if\b.*(?:>=?|<=?)\s*[A-Za-z_(]`, lines[k])
	not helpers.is_comment_line(lines[k])
}

# ── Findings ─────────────────────────────────────────────────────────────

_reported(lang, _, srcs, lines, i, line) if {
	some size in _sizes(lang, line)
	_tainted(lang, lines, srcs, i, size)
}

_reported(_, src_idx, srcs, lines, i, _) if _in_tainted_loop(src_idx, srcs, lines, i)

_msg := {
	"go": "Allocation sized by a value read from outside the program; cap it with a maximum before allocating to prevent memory exhaustion",
	"java": "Array or buffer sized by a value read from outside the program; validate it against a maximum limit before allocation to prevent OutOfMemoryError or DoS",
	"c": "Allocation sized by a value read from outside the program; check it against a maximum (and for multiplication overflow) before allocating",
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	_cheap(lang, content)
	_src_kw(lang, content)
	regex.match(_alloc[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	_cheap(lang, line)
	regex.match(_alloc[lang], line)
	not helpers.is_comment_line(line)
	src_idx := {j | some j in numbers.range(max([0, i - 40]), i); l := lines[j]; _src_kw(lang, l); regex.match(_source[lang], l); not helpers.is_comment_line(l)}
	srcs := {[j, v] | some j in src_idx; some v in _src_names(lines[j])}
	_reported(lang, src_idx, srcs, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": _msg[lang],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A substring every allocation site of the language contains, tested before
# the regular expression.
_cheap("go", line) if contains(line, "make(")

_cheap("java", line) if contains(line, "new ")

_cheap("java", line) if contains(line, "allocate")

_cheap("c", line) if contains(line, "alloc")

_cheap("c", line) if contains(line, "new ")

# Literal fragments of every source, tested before the regular expression.
_src_kws := {
	"go": ["strconv.", "ContentLength", "Content-Length", "FormValue(", "URL.Query()", "binary.", "ReadUvarint", "ReadVarint", "os.Args", "flag.", "Header.Get("],
	"java": ["getContentLength", "getIntHeader(", "getParameter(", "getHeader(", "readInt(", "readLong(", "parseInt(", "parseLong(", "Integer.valueOf("],
	"c": ["atoi(", "atol(", "strto", "ntoh", "toh(", "argv[", "fread(", "recv(", "scanf("],
}

_src_kw(lang, s) if {
	some kw in _src_kws[lang]
	contains(s, kw)
}
