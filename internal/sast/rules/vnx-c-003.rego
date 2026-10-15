package vulnetix.rules.vnx_c_003

import rego.v1

metadata := {
	"id": "VNX-C-003",
	"name": "OS command injection: a shell command built from or read from untrusted data",
	"description": "Reports C and C++ calls that hand a string to a shell (system, popen, _popen, _wpopen, _wsystem, p2open, C++ std::system, and execl/execlp/execle of sh/bash/zsh/dash with \"-c\") when the command is argv[...] or getenv(...) directly; a variable assigned from getenv/secure_getenv/argv/readline or filled by fgets/gets/read/recv/recvfrom/fread/getline/scanf in the 25 lines above; or a variable composed in those lines from non-constant data: sprintf/snprintf/_snprintf/asprintf/swprintf/wsprintf/g_snprintf/g_strdup_printf with a %s argument that is not a literal or macro, strcat/strncat/strlcat/strcpy/strncpy/strlcpy/stpcpy of a non-constant, or C++ std::string +, +=, append() and ostream << of a non-literal (also inline: popen((\"ls \" + dir).c_str(), ...)). Also reports wordexp() of a non-literal without WRDE_NOCMD, which runs $(...) command substitution. Not reported: literal or macro commands, system(NULL), commands composed only from literals, macros and numeric conversions (%d), a command that is a parameter of the enclosing function (a wrapper: the caller is where it is built), a command whose composition is preceded within those lines by a validation, allow-list or quoting call (is_valid_*, isValid*, sanitize, escape, quote, g_shell_quote, strspn/strpbrk/strcspn; unescape, invalidate and the buf[strcspn(buf, \"\\n\")] = 0 newline trim do not count), exec* without a shell, posix_spawn, prototypes, function-pointer fields and methods named system, string literals and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-c-003/",
	"languages": ["c", "cpp"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [78, 88, 676],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["command-injection", "c", "os-command", "shell"],
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
# `.`/`->` (a method or function-pointer field of the same name).
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

_flat(s) := regex.replace(regex.replace(regex.replace(s, `\([^()]*\)`, "0"), `\([^()]*\)`, "0"), `\([^()]*\)`, "0")

# Top-level arguments of the call whose text starts after its `(`.
_args(call) := [trim_space(a) | some a in split(_inner(_flat(call)), ",")]

_inner(f) := substring(f, 0, indexof(f, ")")) if indexof(f, ")") >= 0

_inner(f) := f if indexof(f, ")") < 0

# A literal, adjacent literals, an upper-case macro, or NULL.
_constant(a) if regex.match(`^\s*(?:(?:L|u8|u|U)?""|[A-Z][A-Z0-9_]*|\s)+$`, a)

_constant(a) if regex.match(`^\s*(?:0|nullptr)\s*$`, a)

# First identifier of an expression: `cmd` in cmd.c_str(), &cmd, oss.str().
_root(a) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)`, a, 1)
	count(m) > 0
}

# The identifier assigned on a line: `cmd` in `char *cmd = getenv(...)`.
_assigned_c(l) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*=[^=]`, l, 1)
	count(m) > 0
}

# ── Untrusted sources ────────────────────────────────────────────────────

_direct_source(a) if regex.match(`^\s*(?:argv\s*\[|(?:secure_)?getenv0)`, a)

_assign_source := `\b(?:(?:secure_)?getenv\s*\(|argv\s*\[|readline\s*\()`

_outparam_res := [
	`\bf?gets\s*\(\s*(\w+)`,
	`\b(?:read|recv|recvfrom|ReadFile)\s*\(\s*[^,]+,\s*(?:\([^()]*\)\s*)?&?\s*(\w+)`,
	`\bfread\s*\(\s*(?:\([^()]*\)\s*)?&?\s*(\w+)`,
	`\bgetline\s*\(\s*&\s*(\w+)`,
	`\b[fs]?scanf\s*\([^;]*?"\s*,\s*&?\s*(\w+)`,
]

# ── How a command variable was produced, line by line ───────────────────

_builder_fmt_pos := {
	"sprintf": 1, "snprintf": 2, "_snprintf": 2, "asprintf": 1, "swprintf": 2,
	"wsprintf": 1, "wsprintfA": 1, "wsprintfW": 1, "g_snprintf": 2,
}

_conv_re := `%[-+ #0'\d.*$]*(?:hh|h|ll|l|L|z|j|t|q|w|I64|I32)?([diouxXeEfFgGaAcCsSpn])`

# A %s conversion whose argument is not a literal or macro.
_s_arg_nonconst(fmt, args, k) if {
	convs := [m[1] | some m in regex.find_all_string_submatch_n(_conv_re, replace(fmt, "%%", ""), -1)]
	some idx, c in convs
	c in {"s", "S"}
	k + 1 + idx < count(args)
	not _constant(args[(k + 1) + idx])
}

_raw_fmt(fn, k, raw) := m[0][1] if {
	re := concat("", [`\b`, fn, `\s*\(\s*(?:[^,;"]+,\s*){`, format_int(k, 10), `}(?:L|u8|u|U)?"((?:[^"\\]|\\.)*)"`])
	m := regex.find_all_string_submatch_n(re, raw, 1)
	count(m) > 0
}

# printf-style composition into x.
_builds(raw, code, x) if {
	m := regex.find_all_string_submatch_n(`\b(sprintf|snprintf|_snprintf|asprintf|swprintf|wsprintf[AW]?|g_snprintf)\s*\((.*)$`, code, 1)
	count(m) > 0
	args := _args(m[0][2])
	_root(args[0]) == x
	k := _builder_fmt_pos[m[0][1]]
	_s_arg_nonconst(_raw_fmt(m[0][1], k, _mask_chars(raw)), args, k)
}

_builds(raw, code, x) if {
	_assigned_c(code) == x
	m := regex.find_all_string_submatch_n(`\bg_strdup_printf\s*\((.*)$`, code, 1)
	count(m) > 0
	args := _args(m[0][1])
	_s_arg_nonconst(_raw_fmt("g_strdup_printf", 0, _mask_chars(raw)), args, 0)
}

# strcat/strcpy-style copy of a non-constant into x.
_builds(_, code, x) if {
	m := regex.find_all_string_submatch_n(`\b(?:strn?cat|strlcat|wcsn?cat|strn?cpy|strlcpy|stpcpy|wcsn?cpy)\s*\((.*)$`, code, 1)
	count(m) > 0
	args := _args(m[0][1])
	count(args) >= 2
	_root(args[0]) == x
	not _constant(args[1])
}

# C++: x = a + b, x += y, x.append(y), x << y with a non-literal operand.
_builds(_, code, x) if {
	regex.match(concat("", [`\b`, x, `\s*(?:\(|=[^=])[^;]*(?:[\w\])]\s*\+|\+\s*[A-Za-z_(])`]), code)
}

_builds(_, code, x) if regex.match(concat("", [`\b`, x, `\s*\+=\s*[^;]*[A-Za-z_]`]), code)

_builds(_, code, x) if regex.match(concat("", [`\b`, x, `\b[^;]*\.\s*append\s*\(\s*[A-Za-z_]`]), code)

_builds(_, code, x) if regex.match(concat("", [`\b`, x, `\s*<<(?:[^;]*<<)?\s*[A-Za-z_]`]), code)

# x read from the environment, the command line or input.
_builds(_, code, x) if {
	regex.match(_assign_source, code)
	_assigned_c(code) == x
}

_builds(_, code, x) if {
	some re in _outparam_res
	some m in regex.find_all_string_submatch_n(re, code, -1)
	m[1] == x
}

_composed(lines, i, x) if {
	some j in numbers.range(max([0, i - 25]), i - 1)
	j < i
	raw := lines[j]
	contains(raw, x)
	not _comment_line(raw)
	_builds(raw, _mask(raw), x)
}

# A printf-style builder whose call wraps over the next lines:
# snprintf(cmd, sizeof cmd,\n "tar -tzf %s",\n name);
_composed(lines, i, x) if {
	some j in numbers.range(max([0, i - 25]), i - 2)
	j < i - 1
	raw0 := lines[j]
	contains(raw0, x)
	not _comment_line(raw0)
	code0 := _mask(raw0)
	not contains(code0, ";")
	regex.match(`\b(?:sprintf|snprintf|_snprintf|asprintf|swprintf|wsprintf[AW]?|g_snprintf|g_strdup_printf)\s*\(`, code0)
	ks := [k | some k in numbers.range(j, min([j + 3, i - 1]))]
	raw := concat(" ", [lines[k] | some k in ks])
	code := concat(" ", [_mask(lines[k]) | some k in ks])
	_builds(raw, code, x)
}

# A validation, allow-list or quoting call in the lines above the sink.
_validated(lines, i) if {
	some j in numbers.range(max([0, i - 25]), i - 1)
	j < i
	l := lines[j]
	not _comment_line(l)
	regex.match(`(?:(?:^|[^A-Za-z])(?:[Vv]alid|[Ss]aniti[sz]|[Ee]scape|[Qq]uote|[Aa]llow|[Ww]hitelist|is_?[Ss]afe|IsSafe|strspn|strpbrk|strcspn)|[a-z](?:Valid|Saniti[sz]|Escape|Quote|Allow|Whitelist|Safe))\w*\s*\(`, l)
	not _newline_strip(l)
}

# buf[strcspn(buf, "\n")] = 0 trims fgets' newline; it checks nothing.
_newline_strip(l) if regex.match(`\[\s*str[c]?spn\s*\([^;]*\]\s*=`, l)

# ── Sinks ────────────────────────────────────────────────────────────────

_shell_fns := {"system", "popen", "_popen", "_wpopen", "_wsystem", "p2open"}

_exec_fns := {"execl", "execlp", "execle"}

_all_fns := (_shell_fns | _exec_fns) | {"wordexp"}

_call_re := `^(.*?)\b(system|popen|_popen|_wpopen|_wsystem|p2open|execl|execlp|execle|wordexp)\s*\((.*)$`

_unsafe_cmd(a, _, _, _) if _direct_source(a)

_unsafe_cmd(a, _, lines, i) if {
	not _constant(a)
	_composed(lines, i, _root(a))
}

# popen(("ls " + dir).c_str(), "r"): composed inside the call itself.
_unsafe_cmd(a, call, _, _) if {
	contains(a, "c_str")
	regex.match(`^[^;]*?(?:[\w\])]\s*\+\s*[A-Za-z_(]|""\s*\+\s*[A-Za-z_(])`, call)
}

_issue(fn, call, lines, i) := "the command passed to the shell is built from or read from data this function does not control; run the program with execv/posix_spawn and an argument array, or validate it against an allow-list" if {
	fn in _shell_fns
	args := _args(call)
	_unsafe_cmd(args[0], call, lines, i)
	not _validated(lines, i)
}

# execl("/bin/sh", "sh", "-c", cmd, NULL)
_issue(fn, _, lines, i) := "the command handed to 'sh -c' is built from or read from data this function does not control; exec the program directly with an argument array, or validate it against an allow-list" if {
	fn in _exec_fns
	raw := concat(" ", [_mask_chars(lines[k]) | some k in numbers.range(i, i + 2); k < count(lines)])
	m := regex.find_all_string_submatch_n(`\bexecl[pe]?\s*\(\s*"(?:/usr)?(?:/bin/)?(?:ba|z|da|k|tc|c)?sh"\s*,[^;]*?"-c"\s*,\s*([^,;]+?)\s*[,)]`, raw, 1)
	count(m) > 0
	a := trim_space(_flat(_mask(m[0][1])))
	_unsafe_cmd(a, a, lines, i)
	not _validated(lines, i)
}

_issue("wordexp", call, _, _) := "wordexp() without WRDE_NOCMD performs $(...) and backtick command substitution on its input; pass WRDE_NOCMD, or use glob() for path patterns" if {
	args := _args(call)
	count(args) >= 3
	not _constant(args[0])
	not contains(args[2], "WRDE_NOCMD")
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
		"message": sprintf("%s(): %s", [m[0][2], msg]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
