package vulnetix.rules.vnx_c_005

import rego.v1

metadata := {
	"id": "VNX-C-005",
	"name": "Integer overflow in malloc/calloc size arithmetic",
	"description": "Reports a C or C++ allocation whose size is a multiplication or addition involving a count read from outside the program, with no overflow check: malloc, xmalloc, g_malloc, kmalloc, kzalloc, valloc, realloc, xrealloc, g_realloc, calloc, aligned_alloc and memalign (std:: forms included) whose size argument, or the variable it was computed into a few lines above, combines with * or + a value parsed or received in the 30 lines above (atoi/atol/strtol/strtoul family, std::stoi/stoul, ntohl/ntohs/be32toh family, getenv, or an &out argument of scanf/fscanf/sscanf/fread/read/recv/recvfrom), or such a call written directly in the size. A wrapped product or sum makes the buffer smaller than the code that fills it assumes. Not reported: a count compared with < or > (or checked against SIZE_MAX, INT_MAX, __builtin_mul_overflow, ckd_mul) or reassigned between the read and the allocation, calloc(n, size) with plain arguments (calloc checks that product itself), reallocarray, sizes from constants, sizeof or internal lengths such as strlen(s) + 1 or a doubled capacity, and string literals and comments. Deliberately out of scope: counts that arrive through struct fields, function parameters or other files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-c-005/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [190, 131, 787],
	"capec": ["CAPEC-92"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["integer-overflow", "c", "malloc", "memory-safety"],
}

# ── C source files ───────────────────────────────────────────────────────

_c_exts := [".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".mm"]

_c_file(path, _) if {
	some ext in _c_exts
	endswith(path, ext)
}

_c_file(path, content) if {
	endswith(path, ".m")
	regex.match(`(?m)^\s*#\s*(?:import|include)\b|@(?:implementation|interface)\b`, content)
}

# ── Literals and comments ────────────────────────────────────────────────

_mask_chars(s) := regex.replace(s, `'(?:[^'\\]|\\.)'`, "'_'")

_mask_strings(s) := regex.replace(_mask_chars(s), `"(?:[^"\\]|\\.)*"`, `""`)

_mask(s) := regex.replace(regex.replace(_mask_strings(s), `/\*.*?\*/`, " "), `(?://|/\*).*$`, "")

_comment_line(l) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, l)

_in_block_comment(lines, i) if {
	start := max([0, i - 40])
	i > start
	marks := [j | some j in numbers.range(start, i - 1); _comment_mark(lines[j])]
	count(marks) > 0
	_opens_block(_mask_strings(lines[max(marks)]))
}

_comment_mark(l) if contains(l, "/*")

_comment_mark(l) if contains(l, "*/")

_opens_block(s) if {
	o := indexof_n(s, "/*")
	count(o) > 0
	not contains(s, "*/")
}

_opens_block(s) if {
	o := indexof_n(s, "/*")
	c := indexof_n(s, "*/")
	count(o) > 0
	count(c) > 0
	max(o) > max(c)
}

# ── Allocators and their size argument ───────────────────────────────────

# Size is the whole argument list.
_one_arg := {"malloc", "xmalloc", "g_malloc", "g_malloc0", "kmalloc", "kzalloc", "valloc", "pvalloc", "calloc"}

# Size is the second argument.
_second_arg := {"realloc", "xrealloc", "g_realloc", "aligned_alloc", "memalign"}

_alloc_re := `(?:^|[^\w.>:]|std::)(malloc|xmalloc|g_malloc0?|kmalloc|kzalloc|valloc|pvalloc|calloc|realloc|xrealloc|g_realloc|aligned_alloc|memalign)\s*\((.*)$`

# Masked call text: the rest of the line after `(`, continued over up to
# three more lines until the statement's `;`.
_call_text(lines, i, rest) := t if {
	more := [_mask(lines[k]) | some k in numbers.range(i + 1, min([count(lines) - 1, i + 3]))]
	joined := concat(" ", array.concat([rest], more))
	t := _to_semicolon(joined)
}

_to_semicolon(s) := substring(s, 0, indexof(s, ";")) if indexof(s, ";") >= 0

_to_semicolon(s) := s if indexof(s, ";") < 0

_flat(s) := regex.replace(regex.replace(regex.replace(s, `\([^()]*\)`, "0"), `\([^()]*\)`, "0"), `\([^()]*\)`, "0")

# The call's own argument text (top level, nested calls flattened to 0).
_top(t) := substring(f, 0, indexof(f, ")")) if {
	f := _flat(t)
	indexof(f, ")") >= 0
}

_top(t) := _flat(t) if indexof(_flat(t), ")") < 0

# The size part of the argument text, raw (for names) and flattened (for
# the arithmetic). For a second-argument allocator, the text after the
# first top-level comma.
_size(fn, t) := [t, _top(t)] if _one_arg[fn]

_size(fn, t) := [raw, top] if {
	_second_arg[fn]
	f := _top(t)
	ci := indexof(f, ",")
	ci >= 0
	top := substring(f, ci + 1, -1)
	rc := indexof(t, ",")
	raw := substring(t, rc + 1, -1)
}

# A binary * or + at the call's top level, or anywhere in a computed size.
_arith(s) if regex.match(`[\w)\]]\s*[*+]\s*[\w(]`, s)

# calloc(n, size) checks its own product; only arithmetic inside an
# argument counts.
_size_arith("calloc", top) if {
	some a in split(top, ",")
	_arith(a)
}

_size_arith(fn, top) if {
	fn != "calloc"
	_arith(top)
}

# ── Sources of an external count ─────────────────────────────────────────

_parse_re := `\b(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull|strtoimax|strtoumax|stoi|stol|stoll|stoul|stoull|ntohl|ntohs|be16toh|be32toh|be64toh|le16toh|le32toh|le64toh|getenv)\s*\(`

_outparam_re := `\b(?:scanf|fscanf|sscanf|fread|read|recv|recvfrom)\s*\(`

# Names assigned from a parse call, or filled through &name by an input call.
_tainted_at(line) := _assigned_from_parse(line) | _filled_by_input(line)

_assigned_from_parse(line) := {v |
	regex.match(_parse_re, line)
	m := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*=[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_filled_by_input(line) := {v |
	regex.match(_outparam_re, line)
	some m in regex.find_all_string_submatch_n(`&\s*([A-Za-z_]\w*)`, line, -1)
	v := m[1]
}

_taint(lines, i) := {[v, j] |
	some j in numbers.range(max([0, i - 30]), i - 1)
	l := lines[j]
	contains(l, "(")
	not _comment_line(l)
	some v in _tainted_at(_mask(l))
}

_word(v, s) if regex.match(concat("", [`(?:^|[^\w.>])`, v, `\b`]), s)

# ── Guards between the read and the allocation ───────────────────────────

_guarded(lines, j, i, v) if {
	some k in numbers.range(j, i - 1)
	l := _mask(lines[k])
	regex.match(`\b(?:SIZE_MAX|SSIZE_MAX|INT_MAX|UINT_MAX|UINT16_MAX|UINT32_MAX|INT32_MAX|LONG_MAX|ULONG_MAX|PTRDIFF_MAX)\b|__builtin_\w*_overflow|\bckd_(?:mul|add)\b|_overflow\s*\(|\bmul_overflows?\b`, l)
}

_guarded(lines, j, i, v) if {
	some k in numbers.range(j, i - 1)
	l := _mask(lines[k])
	regex.match(`\b(?:if|while|assert|for)\b|\?`, l)
	regex.match(concat("", [`(?:^|[^\w.>])`, v, `\s*[<>]|[<>]=?\s*`, v, `\b`]), l)
}

# Reassigned (clamped, recomputed) after the read.
_guarded(lines, j, i, v) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	l := _mask(lines[k])
	regex.match(concat("", [`(?:^|[^\w.>*])`, v, `\s*=[^=]`]), l)
	not regex.match(_parse_re, l)
}

# ── The size expression a single-name argument was computed from ─────────

_computed(lines, i, top) := rhs if {
	regex.match(`^\s*[A-Za-z_]\w*\s*$`, top)
	name := trim_space(top)
	cands := [[j, m[1]] |
		some j in numbers.range(max([0, i - 10]), i - 1)
		l := _mask(lines[j])
		contains(l, name)
		m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.>*])`, name, `\s*=([^=].*)$`]), l, 1)[0]
	]
	count(cands) > 0
	rhs := cands[count(cands) - 1][1]
}

# The size text (raw) and its arithmetic, directly or through a variable.
_size_expr(lines, i, fn, t) := [raw, top] if {
	s := _size(fn, t)
	_size_arith(fn, s[1])
	raw := s[0]
	top := s[1]
}

_size_expr(lines, i, fn, t) := [rhs, rhs] if {
	s := _size(fn, t)
	not _size_arith(fn, s[1])
	rhs := _computed(lines, i, s[1])
	_arith(_flat(rhs))
}

# ── Findings ─────────────────────────────────────────────────────────────

_alloc_words := ["alloc", "memalign"]

_hit_lines(content) := {n |
	some w in _alloc_words
	contains(content, w)
	parts := split(content, w)
	nls := [strings.count(p, "\n") | some p in parts]
	some k in numbers.range(1, count(parts) - 1)
	startswith(trim_left(parts[k], " \t0"), "(")
	n := sum(array.slice(nls, 0, k))
}

_reported(lines, i, raw) if {
	regex.match(_parse_re, raw)
}

_reported(lines, i, raw) if {
	some tv in _taint(lines, i)
	v := tv[0]
	_word(v, raw)
	not _guarded(lines, tv[1], i, v)
	not _narrow(lines, tv[1], i, v)
}

# An 8- or 16-bit count (ntohs, uint16_t len) is promoted before the
# arithmetic: len + 1 or len * sizeof(T) cannot wrap a size_t.
_narrow(lines, j, _, _) if regex.match(`\b(?:ntohs|be16toh|le16toh)\s*\(`, lines[j])

_narrow(lines, j, i, v) if {
	some k in numbers.range(max([0, j - 30]), i)
	contains(lines[k], v)
	regex.match(concat("", [`\b(?:u?int(?:8|16)_t|u_?int(?:8|16)|unsigned\s+(?:short|char)|u_short|u_char|short|uint16|uint8|guint16|guint8|WORD|BYTE)\s+(?:[A-Za-z_]\w*\s*,\s*)*`, v, `\s*[;,=]`]), lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path, content)
	regex.match(`(?:alloc|memalign)\s*\(`, content)
	regex.match(`(?:atoi|atol|strto|stoi|stol|stoul|ntoh|toh|getenv|scanf|fread|read|recv)\w*\s*\(`, content)
	hits := _hit_lines(content)
	count(hits) > 0
	lines := split(content, "\n")
	some i in hits
	line := lines[i]
	not _comment_line(line)
	m := regex.find_all_string_submatch_n(_alloc_re, _mask(line), 1)
	count(m) > 0
	fn := m[0][1]
	t := _call_text(lines, i, m[0][2])
	se := _size_expr(lines, i, fn, t)
	_reported(lines, i, se[0])
	not _in_block_comment(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s() size is computed from an externally supplied count with no overflow check; reject counts above SIZE_MAX / element size (or use calloc / reallocarray) before allocating", [fn]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
