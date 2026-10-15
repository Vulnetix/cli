# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_908

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-908",
	"name": "Use of Uninitialized Resource",
	"description": "A C or C++ local is read before anything gives it a value. Reported: (1) a function-local scalar, pointer or C struct declared without an initializer (int total;, const char *name;, struct node *n;, and each name of int rc, n; or char *a, *b;, one finding per declaration line) whose first use in the function, within 30 lines, reads it (total += v[i], n->value = v, printf(\"%s\", name), return x); (2) such a local assigned only inside an if with no else (or on a single-line if) and then read at the declaration's own level (if (path) fd = open(...); return fd;); (3) a stack char array declared without an initializer, or a buffer from malloc/realloc/new char[], whose first use after any NULL check reads it as a string (strcat/strncat into it, strlen, strcmp, strchr, puts, printf %s, copied from with strcpy/memcpy). Not reported: a variable whose first use assigns it (including for (i = 0; ...)), takes its address (&x out-parameters, stat(path, &st)), reads it with >> or sizeof, or passes it to a C++ function (which may take it by reference) or a macro (ALL-CAPS, or a function-like #define in the project), including an assignment inside parentheses ((ch = getchar()) != EOF), a chained assignment (a = b = v), an assignment in an earlier statement on the same line (ip = strchr(s, c); if (!ip) ...), a statement-level ALL-CAPS macro call between the declaration and the read (which may assign it) and a guarded self-reference (x = first ? v : x & y); branches with else/default/switch, early returns or gotos between the assignment and the read; calloc and = {0}/memset/snprintf/fgets/strcpy into a buffer; statics, globals and struct/class fields (zero-initialized or not locals); comments and strings. Flow through loops, other functions and pointers is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-908/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [908],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["use-uninitialized-resource", "cwe-908", "uninitialized-variable"],
}

_lang(path) := "c" if endswith(path, ".c")

_lang(path) := "cpp" if {
	some ext in {".cc", ".cpp", ".cxx", ".c++"}
	endswith(path, ext)
}

_rng(a, b) := numbers.range(a, b) if a <= b

_rng(a, b) := [] if a > b

_indent(line) := count(line) - count(trim_left(line, " \t"))

_code(line) := regex.replace(line, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, `""`)

_type := `(?:(?:const|unsigned|signed|volatile|register)\s+)*(?:long\s+long|unsigned\s+(?:long|int|char|short)|int|long|short|char|float|double|bool|_Bool|size_t|ssize_t|off_t|unsigned|signed|u?int(?:8|16|32|64)_t|uintptr_t|intptr_t|ptrdiff_t|pid_t|uid_t|gid_t|time_t|mode_t|socklen_t|struct\s+\w+|enum\s+\w+)`

# `<type> name;` or `<type> *name;` with no initializer, indented.
# First words a declaration can start with (a cheap gate ahead of _decl_re).
_type_words := {"const", "unsigned", "signed", "volatile", "register", "long", "int", "short", "char", "float", "double", "bool", "_Bool", "size_t", "ssize_t", "off_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t", "uintptr_t", "intptr_t", "ptrdiff_t", "pid_t", "uid_t", "gid_t", "time_t", "mode_t", "socklen_t", "struct", "enum"}

_decl_re := concat("", [`^\s+`, _type, `(\s*\*+\s*(?:const\s+)?|\s+)([A-Za-z_]\w*)\s*;\s*(?://.*|/\*.*)?$`])

# `char name[N];` with no initializer.
_array_re := `^\s+(?:unsigned\s+|signed\s+)?char\s+([A-Za-z_]\w*)\s*\[[^\]]+\]\s*;\s*(?://.*|/\*.*)?$`

# A heap buffer whose contents start undefined.
_alloc_re := `^\s+(?:(?:unsigned\s+)?char\s*\*\s*)?([A-Za-z_]\w*)\s*=\s*(?:\(\s*(?:unsigned\s+)?char\s*\*\s*\)\s*)?(?:malloc|realloc)\s*\(|^\s+(?:char\s*\*\s*|auto\s*\*?\s*)?([A-Za-z_]\w*)\s*=\s*new\s+char\s*\[[^\]]+\]\s*;`

# Unindented lines that can start a function or a type: not blank, not a
# preprocessor line, comment or closing brace.
_tops(lines) := [t |
	some t, l in lines
	l != ""
	not startswith(l, " ")
	not startswith(l, "\t")
	not startswith(l, "#")
	not startswith(l, "/")
	not startswith(l, "*")
	not startswith(l, "}")
]

# The declaration sits in a function body: the nearest unindented line above
# is a function header or its brace, not a struct, class, union or enum.
_in_function(lines, tops, i) if {
	above := [t | some t in tops; t < i]
	count(above) > 0
	h := lines[above[count(above) - 1]]
	not regex.match(`^(?:typedef\s+)?(?:struct|class|union|enum|namespace|extern)\b`, h)
	regex.match(`\(|^\{`, h)
}

# A field of a struct, union or class declared inside the function.
_in_aggregate(lines, i) if {
	li := _indent(lines[i])
	ps := [k |
		some k in _rng(max([0, i - 30]), i - 1)
		trim_space(lines[k]) != ""
		_indent(lines[k]) < li
	]
	count(ps) > 0
	p := ps[count(ps) - 1]
	_opens_aggregate(lines, p)
}

_opens_aggregate(lines, p) if regex.match(`\b(?:struct|union|class|enum)\b[^;()]*\{\s*$`, lines[p])

_opens_aggregate(lines, p) if {
	regex.match(`^\s*\{\s*$`, lines[p])
	p > 0
	regex.match(`\b(?:struct|union|class|enum)\b[^;()]*$`, lines[p - 1])
}

# A column-0 closing brace between the declaration and line r: r is in
# another function.
_function_ends(lines, i, r) if {
	some k in _rng(i + 1, r - 1)
	startswith(lines[k], "}")
}

_file_tops[path] := _tops(split(content, "\n")) if {
	some path, content in input.file_contents
	_lang(path)
}

# Every pattern below is a constant: names are compared after extraction, so
# no expression is compiled per variable.

_tokens(s) := regex.split(`[^A-Za-z0-9_]+`, s)

_has_token(s, name) if {
	some t in _tokens(s)
	t == name
}

_token_count(s, name) := count([t | some t in _tokens(s); t == name])

# Lines that use name after line i in the function, ignoring sizeof(name).
# Only the first few lines naming it are examined closely.
_refs(lines, i, e, name) := [k |
	some k in array.slice(_mentions(lines, i, e, name), 0, 6)
	not _comment(lines[k])
	_has_token(_bare(lines[k]), name)
]

_mentions(lines, i, e, name) := [k |
	some k in _rng(i + 1, e)
	contains(lines[k], name)
	regex.match(concat("", [`\b`, name, `\b`]), lines[k])
]

# A comment line. Unlike helpers.is_comment_line, `*res = v;` is code: only a
# star followed by a space, a slash or nothing continues a block comment.
_comment(l) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$)|#)`, l)

_comment(l) if {
	endswith(trim_space(l), "*/")
	not contains(l, "/*")
}

# The line without strings, trailing comments, member names (list->len is
# not the local len) and sizeof operands (sizeof(*p) does not read p).
_bare(line) := s if {
	a := regex.replace(regex.replace(_code(line), `/\*.*?\*/|//.*$`, ""), `(\.|->)\s*[A-Za-z_]\w*`, "${1}_m_")
	s := regex.replace(a, `\bsizeof\s*(?:\([^()]*\)|\*?\s*\w+)`, "SIZEOF")
}

_captured(c, re) := {m[1] | some m in regex.find_all_string_submatch_n(re, c, -1)}

# Innermost calls and their arguments: [callee, [arg, ...]].
_calls(c) := array.concat(_calls1(c), _calls1(regex.replace(c, _call_re, " CALL ")))

_call_re := `([A-Za-z_]\w*)\s*\(([^()]*)\)`

_calls1(c) := [[m[1], [trim_space(a) | some a in split(m[2], ",")]] |
	some m in regex.find_all_string_submatch_n(_call_re, c, -1)
]

_callees(c, name) := {f |
	some [f, args] in _calls(c)
	some a in args
	a == name
}

# The line gives name a value, or may (address taken, read into, passed to a
# C++ function or a macro).
_inits(c, name, _, _) if _captured(c, `(?:^|[^&])&\s*([A-Za-z_]\w*)`)[name]

_inits(c, name, _, _) if _captured(c, `>>\s*([A-Za-z_]\w*)`)[name]

# name = <expression not using name>
_inits(c, name, _, _) if {
	some seg in split(c, ";")
	_captured(seg, `(?:^|[^\w.>\]])([A-Za-z_]\w*)\s*=[^=]`)[name]
	_token_count(seg, name) == 1
}

# a = b = expr: every name in the chain is assigned.
_inits(c, name, _, _) if {
	some seg in split(c, ";")
	_captured(seg, `=\s*([A-Za-z_]\w*)\s*=[^=]`)[name]
	_token_count(seg, name) == 1
}

# for (i = 0; i < n; i++), (ch = getchar()) != EOF: assigned, then used.
_inits(c, name, _, _) if _captured(c, `\(\s*([A-Za-z_]\w*)\s*=[^=]`)[name]

# x = first ? init : (x & y): the self-reference is guarded.
_inits(c, name, _, _) if {
	contains(c, "?")
	_captured(c, `(?:^|[^\w.>\]])([A-Za-z_]\w*)\s*=[^=][^;]*\?`)[name]
}

# Inline assembly outputs.
_inits(c, _, _, _) if regex.match(`\b_*asm_*\b`, c)

# A re-declaration that shadows the variable.
_inits(c, name, _, _) if {
	some m in regex.find_all_string_submatch_n(`^\s*(?:const\s+|struct\s+|unsigned\s+)*(\w+)[\s*]+(\w+)\s*[\[=;,]`, c, 1)
	not _keyword[m[1]]
	m[2] == name
}

_keyword := {"return", "goto", "case", "else", "delete", "throw", "sizeof", "typeof", "co_return"}

# st.field = v, st.a.b = v: a C struct filled member by member.
_inits(c, name, _, "struct") if _captured(c, `\b([A-Za-z_]\w*)(?:\s*(?:\.|->)\s*\w+|\s*\[[^\]]*\])+\s*=[^=]`)[name]

# C++ may take the argument by reference; in C only a macro can assign an
# argument, an ALL-CAPS one or one the project defines.
_inits(c, name, "cpp", _) if {
	some m in _callees(c, name)
	not _reader[m]
}

_inits(c, name, "c", _) if {
	some m in _callees(c, name)
	regex.match(`^[A-Z][A-Z0-9_]+$`, m)
}

_inits(c, name, "c", _) if {
	some m in _callees(c, name)
	_macros[m]
}

_macros contains m[1] if {
	some path, content in input.file_contents
	_c_source(path)
	contains(content, "define")
	some m in regex.find_all_string_submatch_n(`(?m)^\s*#\s*define\s+([a-z_]\w*)\(`, content, -1)
}

# Calls known to read their argument (and keywords that look like calls).
_reader := {"printf", "fprintf", "sprintf", "snprintf", "puts", "fputs", "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strncat", "memcpy", "memmove", "free", "write", "send", "close", "abs", "return", "if", "while", "switch", "for", "assert"}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_msg_read := "A local variable is read before anything assigns it: its value is whatever was on the stack (or in the register), so the result, a pointer dereference or a length derived from it is undefined. Initialize it at its declaration or assign it on every path before the first read"

_msg_branch := "A local variable is assigned only inside an if with no else and read afterwards: on the path where the condition is false it is read uninitialized. Initialize it at its declaration or assign it in every branch"

_msg_buf := "A buffer is used as a string before anything writes it: a stack array and memory from malloc/new[] start with indeterminate contents, so strcat/strlen/printf read past it looking for a terminator. Initialize it first (buf[0] = '\\0', calloc, snprintf, strcpy)"

# One pass over the lines of a C or C++ file serves both checks.
findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ";")
	_type_words[split(trim_left(line, " \t"), " ")[0]]
	f := _check(path, lines, i, line, lang)
}

# Heap buffers: `out = malloc(n);` starts with the variable, not a type.
findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, "alloc(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "alloc(")
	not _type_words[split(trim_left(line, " \t"), " ")[0]]
	f := _check(path, lines, i, line, lang)
}

findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, "new char")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "new char")
	not _type_words[split(trim_left(line, " \t"), " ")[0]]
	f := _check(path, lines, i, line, lang)
}

# ── (1)/(2) scalars, pointers and C structs ──────────────────────────────

_check(path, lines, i, line, lang) := f if {
	not contains(line, "=")
	not contains(line, "(")
	_type_words[split(trim_left(line, " \t"), " ")[0]]
	m := regex.find_all_string_submatch_n(_decl_re, line, 1)
	count(m) > 0
	name := m[0][2]
	kind := _decl_kind(m[0][0], m[0][1])
	f := _scalar_finding(path, lines, i, name, lang, kind)
}

# The tokens of each of the 30 lines below a declaration, computed once for
# all of its declarators.
_token_window(lines, i) := [[k, toks] |
	some k in _rng(i + 1, min([count(lines) - 1, i + 30]))
	toks := {t | some t in _tokens(lines[k])}
]

_scalar_finding(path, lines, i, name, lang, kind) := _scalar_finding_refs(path, lines, i, name, lang, kind, _refs(lines, i, min([count(lines) - 1, i + 30]), name))

_scalar_finding_refs(path, lines, i, name, lang, kind, refs) := f if {
	count(refs) > 0
	k := _report_line(lines, i, refs, name, lang, kind)
	not _function_ends(lines, i, k[0])
	not _macro_between(lines, i, k[0])
	not _in_aggregate(lines, i)
	_in_function(lines, _file_tops[path], i)
	f := _finding(path, k[0], lines[k[0]], k[1])
}

# `int rc, n;` / `char *p, *q;`: several declarators, none initialized.
_multi_re := concat("", [`^\s+`, _type, `\s*((?:\*+\s*)?[A-Za-z_]\w*(?:\s*,\s*\*?\s*[A-Za-z_]\w*)+)\s*;\s*(?://.*|/\*.*)?$`])

# One finding per multi-declarator line (the first, in sorted order), so the
# shared per-line pass stays a single function call.
_check(path, lines, i, line, lang) := f if {
	contains(line, ",")
	not contains(line, "(")
	not contains(line, "=")
	not contains(line, "[")
	_type_words[split(trim_left(line, " \t"), " ")[0]]
	m := regex.find_all_string_submatch_n(_multi_re, line, 1)
	count(m) > 0
	fs := _multi_checks(path, lines, i, line, lang, m[0][1])
	count(fs) > 0
	f := [g | some g in fs][0]
}

_multi_checks(path, lines, i, line, lang, names) := {f |
	win := _token_window(lines, i)
	struct_value := regex.match(`\bstruct\s+\w+\s`, line)
	some part in split(names, ",")
	name := trim_left(trim_space(part), "* ")
	kind := _multi_kind(struct_value, part)
	ments := [k | some [k, toks] in win; toks[name]]
	refs := [k | some k in array.slice(ments, 0, 6); not _comment(lines[k]); _has_token(_bare(lines[k]), name)]
	f := _scalar_finding_refs(path, lines, i, name, lang, kind, refs)
}

_multi_kind(sv, part) := "struct" if {
	sv
	not contains(part, "*")
}

_multi_kind(sv, _) := "scalar" if not sv

_multi_kind(_, part) := "scalar" if contains(part, "*")

_decl_kind(decl, sep) := "struct" if _is_struct_value(decl, sep)

_decl_kind(decl, sep) := "scalar" if not _is_struct_value(decl, sep)

_is_struct_value(decl, sep) if {
	regex.match(`\bstruct\s+\w+\s+\w+\s*;`, decl)
	not contains(sep, "*")
}

# (1) the first use reads it
_report_line(lines, _, refs, name, lang, kind) := [refs[0], _msg_read] if {
	not _inits(_bare(lines[refs[0]]), name, lang, kind)
}

# (2) the first use assigns it under an if with no else; a later use at the
# declaration's level reads it
_report_line(lines, i, refs, name, lang, kind) := [r, _msg_branch] if {
	first := refs[0]
	c := _bare(lines[first])
	_plain_assign(c, name)
	not _captured(c, `&\s*([A-Za-z_]\w*)`)[name]
	d := _indent(lines[i])
	_conditional_assign(lines, i, first, d, c, name)
	later := [k | some k in refs; k > first; _indent(lines[k]) == d]
	count(later) > 0
	r := later[0]
	not _inits(_bare(lines[r]), name, lang, kind)
	not _other_path(lines, first, r, d)
}

_plain_assign(c, name) if _captured(c, `^\s*([A-Za-z_]\w*)\s*=[^=]`)[name]

_plain_assign(c, name) if _captured(c, `^\s*if\s*\(.*\)\s*([A-Za-z_]\w*)\s*=[^=]`)[name]

_conditional_assign(lines, i, first, d, _, _) if {
	_indent(lines[first]) > d
	openers := [k |
		some k in _rng(i + 1, first - 1)
		trim_space(lines[k]) != ""
		_indent(lines[k]) == d
	]
	count(openers) > 0
	regex.match(`^\s*if\s*\(`, lines[openers[count(openers) - 1]])
}

_conditional_assign(lines, _, first, d, c, name) if {
	_indent(lines[first]) == d
	_captured(c, `^\s*if\s*\(.*\)\s*([A-Za-z_]\w*)\s*=[^=]`)[name]
}

_other_path(lines, first, r, d) if {
	some k in _rng(first + 1, r - 1)
	_indent(lines[k]) == d
	regex.match(`\b(?:else|default|return|goto|exit|abort|break|continue)\b|^\s*case\b`, lines[k])
}

# ── (3) buffers read as strings before they are written ──────────────────

_buffer_name(line) := m[0][1] if {
	contains(line, "char")
	contains(line, "[")
	not contains(line, "=")
	m := regex.find_all_string_submatch_n(_array_re, line, 1)
	count(m) > 0
}

_buffer_name(line) := name if {
	_alloc_hint(line)
	m := regex.find_all_string_submatch_n(_alloc_re, line, 1)
	count(m) > 0
	name := concat("", [x | some x in array.slice(m[0], 1, count(m[0])); x != ""])
	name != ""
}

_alloc_hint(line) if contains(line, "alloc(")

_alloc_hint(line) if contains(line, "new char")

_null_check(line, name) if {
	some m in regex.find_all_string_submatch_n(`^\s*(?:if\s*\(\s*(?:!\s*(\w+)|(\w+)\s*==\s*(?:NULL|nullptr|0)|(?:NULL|nullptr)\s*==\s*(\w+))\s*\)|assert\s*\(\s*(\w+)(?:\s*!=\s*(?:NULL|nullptr))?\s*\))`, line, 1)
	some x in array.slice(m, 1, count(m))
	x == name
}

# Reads its first argument as a string.
_reads_first := {"strcat", "strncat", "strlen", "strnlen", "strcmp", "strncmp", "strcasecmp", "strchr", "strrchr", "strstr", "strdup", "puts", "fputs", "atoi", "atol", "strtol", "strtoul"}

# Reads a later argument (the source, or a %s operand).
_reads_later := {"strcat", "strncat", "strcpy", "strncpy", "strcmp", "strncmp", "strcasecmp", "strstr", "memcpy", "memmove", "printf", "fprintf", "sprintf", "snprintf", "syslog"}

_reads_string(c, name) if {
	some [f, args] in _calls(c)
	_reads_first[f]
	args[0] == name
}

_reads_string(c, name) if {
	some [f, args] in _calls(c)
	_reads_later[f]
	some j, a in args
	j > 0
	a == name
}

_reads_string(c, name) if _captured(c, `<<\s*([A-Za-z_]\w*)\s*(?:<<|;)`)[name]

_writer := {"fgets", "read", "recv", "recvfrom", "snprintf", "sprintf", "vsnprintf", "strcpy", "strncpy", "strlcpy", "memset", "memcpy", "memmove", "getcwd", "gethostname", "readlink", "fread", "strftime", "sscanf", "fscanf", "realpath", "bzero", "explicit_bzero", "pread", "getline"}

# The same line also fills the buffer (fgets(buf, ...) == NULL || strncmp(buf, ...)).
_writes_string(c, name) if {
	some [f, args] in _calls(c)
	_writer[f]
	some a in args
	a == name
}

_check(path, lines, i, line, lang) := f if {
	name := _buffer_name(line)
	refs := [k | some k in _refs(lines, i, min([count(lines) - 1, i + 30]), name); not _null_check(lines[k], name)]
	count(refs) > 0
	c := _bare(lines[refs[0]])
	_reads_string(c, name)
	not _writes_string(c, name)
	not _function_ends(lines, i, refs[0])
	_in_function(lines, _file_tops[path], i)
	f := _finding(path, refs[0], lines[refs[0]], _msg_buf)
}

_c_source(path) if _lang(path)

_c_source(path) if {
	some ext in {".h", ".hh", ".hpp", ".hxx"}
	endswith(path, ext)
}

# A statement-level function-like macro (CRC64_SPLIT(3);) between the
# declaration and the read may assign the variable from its body.
_macro_between(lines, i, r) if {
	some k in _rng(i + 1, r - 1)
	regex.match(`^\s*[A-Z][A-Z0-9_]{2,}\s*\([^;]*\)\s*;`, lines[k])
}

