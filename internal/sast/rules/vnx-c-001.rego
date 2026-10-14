package vulnetix.rules.vnx_c_001

import rego.v1

metadata := {
	"id": "VNX-C-001",
	"name": "Unbounded copy into a buffer (strcpy, strcat, gets, sprintf %s, scanf %s)",
	"description": "Reports C and C++ calls that copy data of unknown length into a buffer without a size: gets() and _getws() (always); strcpy, stpcpy, strcat, wcscpy, wcpcpy, wcscat, _mbscpy, _mbscat, _tcscpy, _tcscat and lstrcpy/lstrcat (A/W) when the source is not a string literal or an upper-case macro constant; sprintf and wsprintf whose literal format has a %s conversion with no precision, and vsprintf; scanf, fscanf, sscanf and their wide/v forms whose literal format has a %s, %ls or %[ conversion with no field width. Not reported: the bounded APIs (strlcpy, strncpy, snprintf, fgets, gets_s, the _s functions), %.Ns, %Ns, %ms and %*s conversions, a copy whose source length was measured (strlen/wcslen/strnlen of it) or whose destination size was compared in an if/while/assert in the 15 lines above (which covers the malloc(strlen(s) + 1) idiom), a copy between two fields of the same name (dst->errstr from src->errstr), declarations and prototypes, #define redefinitions, method calls named like these functions, string literals and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-c-001/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [120, 676, 787],
	"capec": ["CAPEC-100"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["buffer-overflow", "c", "dangerous-function", "memory-safety"],
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

_raw_window(lines, i) := concat(" ", [_mask_chars(lines[k]) |
	some k in numbers.range(i, i + 2)
	k < count(lines)
])

_flat(s) := regex.replace(regex.replace(regex.replace(s, `\([^()]*\)`, "0"), `\([^()]*\)`, "0"), `\([^()]*\)`, "0")

# Top-level arguments of the call whose text starts after its `(`.
_args(call) := [trim_space(a) | some a in split(_inner(_flat(call)), ",")]

_inner(f) := substring(f, 0, indexof(f, ")")) if indexof(f, ")") >= 0

_inner(f) := f if indexof(f, ")") < 0

_nospace(s) := regex.replace(s, `\s+`, "")

# ── Sinks ────────────────────────────────────────────────────────────────

_names := `strcpy|stpcpy|wcscpy|wcpcpy|_mbscpy|_tcscpy|lstrcpy[AW]?|strcat|wcscat|_mbscat|_tcscat|lstrcat[AW]?|gets|_getws|sprintf|vsprintf|wsprintf[AW]?|scanf|wscanf|vscanf|fscanf|fwscanf|vfscanf|sscanf|swscanf|vsscanf`

_scanf_fns := _scanf_first | _scanf_second

_all_fns := ((((_gets_fns | _copy_fns) | _sprintf_fns) | {"vsprintf"}) | _scanf_fns)

_call_re := concat("", [`^(.*?)\b(`, _names, `)\s*\((.*)$`])

_gets_fns := {"gets", "_getws"}

_copy_fns := {
	"strcpy", "stpcpy", "wcscpy", "wcpcpy", "_mbscpy", "_tcscpy", "lstrcpy", "lstrcpyA", "lstrcpyW",
	"strcat", "wcscat", "_mbscat", "_tcscat", "lstrcat", "lstrcatA", "lstrcatW",
}

_sprintf_fns := {"sprintf", "wsprintf", "wsprintfA", "wsprintfW"}

_scanf_first := {"scanf", "wscanf", "vscanf"}

_scanf_second := {"fscanf", "fwscanf", "vfscanf", "sscanf", "swscanf", "vsscanf"}

# A source that is a literal, adjacent literals, an upper-case macro, or a
# choice between literals.
_constant(src) if regex.match(`^\s*(?:(?:L|u8|u|U)?""|[A-Z][A-Z0-9_]*|\s)+$`, src)

_constant(src) if regex.match(`^[^?]*\?\s*(?:L|u8|u|U)?""\s*:\s*(?:L|u8|u|U)?""\s*$`, src)

# The 15 code lines above measured the source or compared the destination's size.
_guarded(lines, i, dst, src) if {
	s := _nospace(src)
	some j in numbers.range(max([0, i - 15]), i - 1)
	j < i
	l := _nospace(_mask(lines[j]))
	_measures(l, s)
}

_guarded(lines, i, dst, _) if {
	d := _nospace(dst)
	some j in numbers.range(max([0, i - 15]), i - 1)
	j < i
	m := _mask(lines[j])
	regex.match(`\b(?:if|while|assert)\b|\?`, m)
	l := _nospace(m)
	_sizes(l, d)
}

_measures(l, s) if contains(l, concat("", ["len(", s, ")"]))

_measures(l, s) if contains(l, concat("", ["len(", s, ","]))

_measures(l, s) if contains(l, concat("", ["strcspn(", s, ","]))

_sizes(l, d) if contains(l, concat("", ["sizeof(", d, ")"]))

_sizes(l, d) if contains(l, concat("", ["sizeof", d]))

# dst->errstr from src->errstr: two fields of the same declaration.
_same_field(dst, src) if {
	a := regex.find_all_string_submatch_n(`(?:->|\.)\s*(\w+)\s*$`, dst, 1)
	b := regex.find_all_string_submatch_n(`(?:->|\.)\s*(\w+)\s*$`, src, 1)
	count(a) > 0
	count(b) > 0
	a[0][1] == b[0][1]
}

# printf-family %s with no precision; %% is a literal percent.
_unbounded_print(fmt) if regex.match(`%[-+ #0'\d$*]*(?:hh|h|ll|l|L|w|I64|I32)?[sS]`, replace(fmt, "%%", ""))

# scanf-family %s, %ls, %S or %[ with no width, not suppressed, not %m.
_unbounded_scan(fmt) if regex.match(`%(?:l|h|w|L)?[sS\[]`, replace(fmt, "%%", ""))

_sprintf_fmt(win) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`\b(?:sprintf|wsprintf[AW]?)\s*\(\s*[^,;"]+,\s*(?:L|u8|u|U)?"((?:[^"\\]|\\.)*)"`, win, 1)
	count(m) > 0
}

_scan_fmt(fn, win) := m[0][1] if {
	fn in _scanf_first
	m := regex.find_all_string_submatch_n(`\b(?:scanf|wscanf|vscanf)\s*\(\s*L?"((?:[^"\\]|\\.)*)"`, win, 1)
	count(m) > 0
}

_scan_fmt(fn, win) := m[0][1] if {
	fn in _scanf_second
	m := regex.find_all_string_submatch_n(`\b(?:fscanf|fwscanf|vfscanf|sscanf|swscanf|vsscanf)\s*\(\s*[^,;"]+,\s*L?"((?:[^"\\]|\\.)*)"`, win, 1)
	count(m) > 0
}

_any_measured(lines, i, args) if {
	count(args) > 2
	some a in array.slice(args, 2, count(args))
	_guarded(lines, i, "\u0000", a)
}

# ── Verdicts ─────────────────────────────────────────────────────────────

_issue(fn, _, _, _) := "gets() reads a line of unlimited length into a fixed buffer and cannot be used safely; use fgets(buf, sizeof buf, stdin)" if fn in _gets_fns

_issue(fn, call, lines, i) := msg if {
	fn in _copy_fns
	args := _args(call)
	count(args) >= 2
	not _constant(args[1])
	not _guarded(lines, i, args[0], args[1])
	not _same_field(args[0], args[1])
	msg := sprintf("%s() copies a source of unknown length with no destination size; check the length first or use strlcpy/strlcat (or snprintf) with sizeof the destination", [fn])
}

_issue(fn, call, lines, i) := msg if {
	fn in _sprintf_fns
	fmt := _sprintf_fmt(_raw_window(lines, i))
	_unbounded_print(fmt)
	args := _args(call)
	not _guarded(lines, i, args[0], "\u0000")
	not _any_measured(lines, i, args)
	msg := sprintf("%s() expands %%s with no precision into a fixed buffer; use snprintf(buf, sizeof buf, ...) or a %%.Ns precision", [fn])
}

_issue("vsprintf", call, _, _) := "vsprintf() writes a caller-supplied format of unknown expansion with no destination size; use vsnprintf(buf, sizeof buf, fmt, ap)" if {
	args := _args(call)
	count(args) >= 2
	not contains(args[1], `""`)
}

_issue(fn, _, lines, i) := msg if {
	fmt := _scan_fmt(fn, _raw_window(lines, i))
	_unbounded_scan(fmt)
	msg := sprintf("%s() reads a %%s/%%[ conversion with no field width into a fixed buffer; give a width one less than the buffer size, e.g. %%63s", [fn])
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path, content)
	hits := _hit_lines(content, _all_fns)
	count(hits) > 0
	lines := split(content, "\n")
	some i in hits
	line := lines[i]
	not _comment_line(line)
	m := regex.find_all_string_submatch_n(_call_re, _mask(line), 1)
	count(m) > 0
	_call_prefix_ok(m[0][1])
	msg := _issue(m[0][2], _call_text(lines, i, m[0][3]), lines, i)
	not _in_block_comment(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
