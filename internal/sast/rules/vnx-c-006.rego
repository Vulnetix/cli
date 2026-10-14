package vulnetix.rules.vnx_c_006

import rego.v1

metadata := {
	"id": "VNX-C-006",
	"name": "Use of alloca() for dynamic stack allocation",
	"description": "Reports C, C++ and Objective-C stack allocations whose size is decided at run time without a bound: alloca(), _alloca() and __builtin_alloca() whose size argument names a variable, member or call (alloca(len), alloca(strlen(a) + strlen(b) + 2), alloca(n * sizeof(T))), strdupa() of a non-literal string, and a variable-length array declared with a size taken from strlen() or from a count parsed or received in the 30 lines above (atoi/strtol family, ntohl/ntohs, getenv, &out of scanf/fread/read/recv). An oversized request moves the stack pointer past the guard page into other memory. Not reported: sizes made only of literals, upper-case macros and sizeof, a size variable compared with < or > in the 15 lines above or in a ternary on the same line (n < 256 ? alloca(n) : malloc(n)), a MIN()/min() clamp, _malloca (which falls back to the heap), strndupa, other functions whose names contain alloca, declarations, #define macros, VLAs sized by a plain parameter, string literals and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-c-006/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [676, 1325],
	"capec": ["CAPEC-100"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["alloca", "stack-overflow", "c", "dangerous-function", "memory-safety"],
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

_macro_line(lines, i) if regex.match(`^\s*#`, lines[i])

_macro_line(lines, i) if {
	i > 0
	endswith(trim_right(lines[i - 1], " \t\r"), "\\")
}

# C files, decided once for both rules.
_files[path] := content if {
	some path, content in input.file_contents
	_c_file(path, content)
}

_hit_lines(content, word) := {n |
	contains(content, word)
	parts := split(content, word)
	nls := [strings.count(p, "\n") | some p in parts]
	some k in numbers.range(1, count(parts) - 1)
	n := sum(array.slice(nls, 0, k))
}

# ── The call ─────────────────────────────────────────────────────────────

_call_re := `(?:^|[^\w.>:])(alloca|_alloca|__builtin_alloca|strdupa)\s*\((.*)$`

# The masked argument text: the rest of the line, continued over up to two
# more lines, cut at the call's closing parenthesis.
_arg_text(lines, i, rest) := arg if {
	more := [_mask(lines[k]) | some k in numbers.range(i + 1, min([count(lines) - 1, i + 2]))]
	joined := concat(" ", array.concat([rest], more))
	arg := _balanced(joined)
}

# Up to the parenthesis that closes the call (three nesting levels): nested
# pairs are rewritten to braces, so the first `)` left closes the call.
_braced(s) := regex.replace(regex.replace(regex.replace(s, `\(([^()]*)\)`, "{${1}}"), `\(([^()]*)\)`, "{${1}}"), `\(([^()]*)\)`, "{${1}}")

_balanced(s) := _unbrace(substring(f, 0, indexof(f, ")"))) if {
	f := _braced(s)
	indexof(f, ")") >= 0
}

_balanced(s) := _unbrace(f) if {
	f := _braced(s)
	indexof(f, ")") < 0
}

_unbrace(s) := replace(replace(s, "{", "("), "}", ")")

# Names in a size that are not sizeof operands, macros or literals.
_runtime_names(arg) := {m |
	no_sizeof := regex.replace(arg, `\bsizeof\s*(?:\((?:[^()]|\([^()]*\))*\)|\*?\s*\w+(?:->\w+|\.\w+)*)`, " 0 ")
	some m in regex.find_n(`[A-Za-z_]\w*`, no_sizeof, -1)
	regex.match(`[a-z]`, m)
	not _type_word[m]
}

_type_word := {"struct", "union", "enum", "const", "unsigned", "signed", "char", "int", "long", "short", "size_t", "void"}

_clamped(arg) if regex.match(`\b(?:MIN|min|std::min|MIN2)\s*\(`, arg)

# A bound on one of the size's names: compared in an if/while/assert/ternary
# in the 15 lines above or on the call's own line.
_guarded(lines, i, names) if {
	some k in numbers.range(max([0, i - 15]), i)
	l := _mask(lines[k])
	regex.match(`\b(?:if|while|assert)\b|\?`, l)
	some v in names
	regex.match(concat("", [`(?:^|[^\w])`, v, `\s*[<>]|[<>]=?\s*`, v, `\b`]), l)
}

findings contains finding if {
	some path, content in _files
	regex.match(`(?:alloca|strdupa)\s*\(`, content)
	hits := _hit_lines(content, "alloca") | _hit_lines(content, "strdupa")
	count(hits) > 0
	lines := split(content, "\n")
	some i in hits
	line := lines[i]
	contains(line, "a")
	not _comment_line(line)
	m := regex.find_all_string_submatch_n(_call_re, _mask(line), 1)
	count(m) > 0
	fn := m[0][1]
	not _declaration(m[0][2])
	not _macro_line(lines, i)
	arg := _arg_text(lines, i, m[0][2])
	_dynamic(fn, arg)
	not _clamped(arg)
	not _guarded(lines, i, _runtime_names(arg))
	not _in_block_comment(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s() allocates a run-time size on the stack with no bound; use malloc()/calloc() or reject sizes above a small fixed limit first", [fn]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# `void *alloca(size_t size);`, `char *alloca ();`
_declaration(rest) if regex.match(`^\s*(?:(?:const\s+)?(?:size_t|unsigned|int|void)\b[^)]*)?\)\s*;`, rest)

_dynamic("strdupa", arg) if not regex.match(`^\s*""\s*$`, arg)

_dynamic(fn, arg) if {
	fn != "strdupa"
	count(_runtime_names(arg)) > 0
}

# ── Variable-length arrays sized by input ────────────────────────────────

_vla_re := `^\s*(?:(?:static|const|volatile|unsigned|signed|register)\s+)*(?:char|wchar_t|int|long|short|float|double|bool|u?int(?:8|16|32|64)_t|size_t|uint|u_char|uchar|BYTE)\s+([A-Za-z_]\w*)\s*\[([^\]]+)\]\s*;`

_parse_re := `\b(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull|strtoimax|strtoumax|ntohl|ntohs|be16toh|be32toh|be64toh|le16toh|le32toh|le64toh|getenv)\s*\(`

_outparam_re := `\b(?:scanf|fscanf|sscanf|fread|read|recv|recvfrom)\s*\(`

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

_input_sized(_, _, size) if regex.match(`\b(?:strlen|wcslen)\s*\(`, size)

_input_sized(lines, i, size) if regex.match(_parse_re, size)

_input_sized(lines, i, size) if {
	names := _runtime_names(size)
	some j in numbers.range(max([0, i - 30]), i - 1)
	l := lines[j]
	contains(l, "(")
	not _comment_line(l)
	some v in _tainted_at(_mask(l))
	names[v]
	not _guarded(lines, i, {v})
}

findings contains finding if {
	some path, content in _files
	contains(content, "];")
	regex.match(`\b(?:strlen|wcslen|atoi|atol|strto[a-z]+|ntoh[ls]|[bl]e(?:16|32|64)toh|getenv|[fs]?scanf|fread|read|recv(?:from)?)\s*\(`, content)
	hits := _hit_lines(content, "];")
	count(hits) > 0
	lines := split(content, "\n")
	some i in hits
	line := lines[i]
	not _comment_line(line)
	m := regex.find_all_string_submatch_n(_vla_re, _mask(line), 1)
	count(m) > 0
	size := m[0][2]
	count(_runtime_names(size)) > 0
	_input_sized(lines, i, size)
	not _clamped(size)
	not _in_block_comment(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Variable-length array '%s' is sized by input with no bound; allocate it on the heap or reject sizes above a fixed limit first", [m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
