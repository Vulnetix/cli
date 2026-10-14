package vulnetix.rules.vnx_c_002

import rego.v1

metadata := {
	"id": "VNX-C-002",
	"name": "Format string injection via non-literal format argument",
	"description": "Reports a C or C++ printf-family call whose format argument is not a string literal in two shapes. (1) The non-literal is the only thing after the format position, so a string is being printed as a format (printf(buf), fprintf(fp, msg), syslog(LOG_ERR, msg), snprintf(buf, n, s), dprintf, wprintf, swprintf, wsprintf, printk, and BSD warn/warnx/err/errx in files that include <err.h>); this is the shape -Wformat-security warns about. (2) The format, with further arguments, is argv[...] or getenv(...) directly, or a variable assigned from getenv/secure_getenv/argv or filled by fgets/gets/read/recv/recvfrom/fread/getline/scanf in the 25 lines above (also asprintf, vprintf, vfprintf, vsprintf, vsnprintf, vsyslog and the other v-forms, which always pass a va_list). Not reported: literal formats including adjacent literals, macro prefixes (COLOR \"...\", KERN_INFO \"...\"), literal ternaries and gettext _(\"...\"); upper-case macro formats; a variable initialised from a literal or a literal table in this file; a format that is a parameter of the enclosing function when further arguments are passed (variadic wrappers are the correct pattern, and the caller is the place to look); macro definitions; prototypes; method calls named printf; string literals and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-c-002/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [134],
	"capec": ["CAPEC-135"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["format-string", "c", "injection", "memory-safety"],
}

# ── C source files ───────────────────────────────────────────────────────
# .m is Objective-C only when it looks like it; MATLAB also uses .m.

_c_exts := [".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".mm"]

_c_file(path, _) if {
	some ext in _c_exts
	endswith(path, ext)
}

_c_file(path, content) if {
	endswith(path, ".m")
	regex.match(`(?m)^\s*#\s*(?:import|include)\b|@(?:implementation|interface)\b`, content)
}

# ── Lines, comments and literals ─────────────────────────────────────────

# Indices of the lines that call one of `names`: the name as a whole word,
# then optional space and `(`. The file is split on each name it contains
# (native string search), so no line of a file is visited one by one.
_hit_lines(content, names) := {n |
	some name in names
	contains(content, name)
	some n in _call_lines(content, name)
}

_call_lines(content, name) := {n |
	parts := split(content, name)
	nls := [strings.count(p, "\n") | some p in parts]
	some k in numbers.range(1, count(parts) - 1)
	trim_right(parts[k - 1], _wordchars) == parts[k - 1]
	startswith(trim_left(parts[k], " \t\r\n"), "(")
	n := sum(array.slice(nls, 0, k))
}

_wordchars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

_mask_chars(s) := regex.replace(s, `'(?:[^'\\]|\\.)'`, "'_'")

_mask_strings(s) := regex.replace(_mask_chars(s), `"(?:[^"\\]|\\.)*"`, `""`)

# Code text of a line: literals emptied, comments removed.
_mask(s) := regex.replace(regex.replace(_mask_strings(s), `/\*.*?\*/`, " "), `(?://|/\*).*$`, "")

_comment_line(l) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, l)

# Inside a /* ... */ block opened on an earlier line.
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

# Part of a #define, directly or through backslash continuation lines.
_in_macro(lines, i) if regex.match(`^\s*#\s*define\b`, lines[i])

_in_macro(lines, i) if {
	i > 0
	_continued(lines[i - 1])
	some j in numbers.range(max([0, i - 30]), i - 1)
	regex.match(`^\s*#\s*define\b`, lines[j])
	every k in numbers.range(j, i - 1) {
		_continued(lines[k])
	}
}

_continued(l) if endswith(trim_right(l, " \t\r"), "\\")

# What precedes the function name on a call: not a type (a prototype), not
# `.`/`->` (a method of the same name), not `#define name(`.
_call_prefix_ok(pre) if {
	t := trim_right(pre, " \t")
	not regex.match(`(?:\.|->|[\w*&])$`, t)
}

_call_prefix_ok(pre) if regex.match(`(?:^|[^\w])(?:return|else|do|case)\s*$`, pre)

# The masked text after the opening parenthesis, continued over the next
# three lines for a call that wraps.
_call_text(lines, i, rest) := concat(" ", array.concat([rest], [_mask(lines[k]) |
	some k in numbers.range(i + 1, i + 3)
	k < count(lines)
]))

# Nested groups collapse to one token; a group holding only a literal
# (gettext's _("...")) keeps the literal marker.
_flat1(s) := regex.replace(regex.replace(s, `\(\s*(?:L|u8|u|U)?""\s*\)`, `""`), `\([^()]*\)`, "0")

_flat(s) := _flat1(_flat1(_flat1(s)))

# Top-level arguments of the call whose text starts after its `(`.
_args(call) := [trim_space(a) | some a in split(_inner(_flat(call)), ",")]

_inner(f) := substring(f, 0, indexof(f, ")")) if indexof(f, ")") >= 0

_inner(f) := f if indexof(f, ")") < 0

# ── Format functions and the position of their format argument ──────────

_fmt_pos := {
	"printf": 0, "wprintf": 0, "vprintf": 0, "vwprintf": 0, "printk": 0,
	"fprintf": 1, "fwprintf": 1, "vfprintf": 1, "vfwprintf": 1, "sprintf": 1, "vsprintf": 1,
	"asprintf": 1, "vasprintf": 1, "dprintf": 1, "vdprintf": 1, "wsprintf": 1, "wsprintfA": 1,
	"wsprintfW": 1, "syslog": 1, "vsyslog": 1,
	"snprintf": 2, "vsnprintf": 2, "swprintf": 2, "vswprintf": 2,
}

# BSD <err.h>: warn(fmt, ...), err(eval, fmt, ...). Only with the header, since
# warn and err are common names for a project's own one-argument helpers.
_bsd_pos := {"warn": 0, "warnx": 0, "vwarn": 0, "vwarnx": 0, "err": 1, "errx": 1, "verr": 1, "verrx": 1}

_positions(content) := object.union(_fmt_pos, _bsd_pos) if contains(content, "<err.h>")

_positions(content) := _fmt_pos if not contains(content, "<err.h>")

_names_re(pos) := concat("|", [k | some k, _ in pos])

# ── Format argument analysis ─────────────────────────────────────────────

_literal_fmt(f) if {
	contains(f, `""`)
	not _direct_source(f)
}

_literal_fmt(f) if regex.match(`^[A-Z_][A-Z0-9_]*$`, f)

# First identifier of the format expression: `name` in name.c_str().
_root(f) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)`, f, 1)
	count(m) > 0
}

# The variable is initialised from a literal, a literal ternary or a table of
# literals somewhere in this file.
_literal_var(content, x) if {
	regex.match(concat("", [`\b`, x, `\s*(?:\[[^\]]*\])?\s*=\s*(?:\([^()]*\)\s*)?(?:\{\s*)?(?:L|u8|u|U)?"`]), content)
}

_literal_var(content, x) if {
	regex.match(concat("", [`\b`, x, `\s*=[^;?]*\?\s*(?:L)?"[^;]*:\s*(?:L)?"`]), content)
}

_direct_source(f) if regex.match(`^\s*(?:argv\s*\[|(?:secure_)?getenv(?:0|""))`, f)

_assign_source := `\b(?:(?:secure_)?getenv\s*\(|argv\s*\[|readline\s*\()`

# Out-parameter sources: the buffer an input function writes into.
_outparam_res := [
	`\bf?gets\s*\(\s*(\w+)`,
	`\b(?:read|recv|recvfrom|ReadFile)\s*\(\s*[^,]+,\s*(?:\([^()]*\)\s*)?&?\s*(\w+)`,
	`\bfread\s*\(\s*(?:\([^()]*\)\s*)?&?\s*(\w+)`,
	`\bgetline\s*\(\s*&\s*(\w+)`,
	`\b[fs]?scanf\s*\([^;]*?"\s*,\s*&?\s*(\w+)`,
]

_taints(l, x) if {
	regex.match(_assign_source, l)
	_assigned_c(l) == x
}

_taints(l, x) if {
	some re in _outparam_res
	some m in regex.find_all_string_submatch_n(re, l, -1)
	m[1] == x
}

_tainted(lines, i, x) if {
	some j in numbers.range(max([0, i - 25]), i - 1)
	j < i
	l := lines[j]
	not _comment_line(l)
	contains(l, x)
	_taints(l, x)
}

# ── Verdicts ─────────────────────────────────────────────────────────────

# (1) the string is the format and nothing follows it.
_issue(args, k, content, _, _) := "a non-literal string is used as the format with no arguments; a '%' in it reads or writes the stack. Print it with a literal format (printf(\"%s\", s)) or fputs" if {
	count(args) == k + 1
	f := args[k]
	f != ""
	not _literal_fmt(f)
	not _literal_var(content, _root(f))
}

# (2) the format comes from input.
_issue(args, k, _, lines, i) := "the format argument is read from the environment, the command line or input; an attacker who controls it can read or write memory with %x/%n. Use a literal format and pass the value as an argument" if {
	count(args) > k + 1
	f := args[k]
	not _literal_fmt(f)
	_from_input(f, lines, i)
}

_from_input(f, _, _) if _direct_source(f)

_from_input(f, lines, i) if _tainted(lines, i, _root(f))

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path, content)
	pos := _positions(content)
	hits := _hit_lines(content, object.keys(pos))
	count(hits) > 0
	lines := split(content, "\n")
	call_re := concat("", [`^(.*?)\b(`, _names_re(pos), `)\s*\((.*)$`])
	some i in hits
	line := lines[i]
	not _comment_line(line)
	m := regex.find_all_string_submatch_n(call_re, _mask(line), 1)
	count(m) > 0
	_call_prefix_ok(m[0][1])
	k := pos[m[0][2]]
	args := _args(_call_text(lines, i, m[0][3]))
	msg := _issue(args, k, content, lines, i)
	not _in_block_comment(lines, i)
	not _in_macro(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s(): %s", [m[0][2], msg]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The identifier assigned on a line: `fmt` in `const char *fmt = getenv(...)`.
_assigned_c(l) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*=[^=]`, l, 1)
	count(m) > 0
}
