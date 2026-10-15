package vulnetix.rules.vnx_bash_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-BASH-004",
	"name": "Unquoted variable used in command or test",
	"description": "Reports an unquoted expansion of a value the script's caller controls, used where the shell word-splits and globs it: a script-level positional parameter ($1, ${2}, ${1:-x}, $@, $*, outside any function) or a variable assigned from one, from read, from OPTARG or by a for loop over \"$@\" within the 80 lines above, appearing as an argument of a command (rm -rf $dir, cp $2 /backup, ssh $host, a continued command line) or as an operand of [ ] or test ([ -n $name ] is always true when the value is empty). A value with a space or glob character then becomes several arguments or a list of files, which is argument injection. Not reported: double-quoted expansions (including multi-line strings and awk/sed programs in quotes), [[ ]] tests, arithmetic $(( )), assignments, case words, $#, $?, $$, $!, ${#var}, a function's own positional parameters (its caller is the script), variables the script sets itself (constant flag strings, command output), a value the script checks is all digits ([[ $1 =~ ^[0-9]+$ ]] or a case arm *[!0-9]*), echo/printf/exit/return/shift/log lines, comments, here-document bodies, test paths and .bats files, and zsh scripts (zsh does not split unquoted parameters). Shell files are .sh, .bash, .ksh and extensionless files with a sh/bash/dash/ksh shebang.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-004/",
	"languages": ["bash", "shell"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [78, 88],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["bash", "word-splitting", "unquoted-variable", "argument-injection"],
}

_shell_exts := [".sh", ".bash", ".ksh"]

_is_shell(path, content) if {
	some ext in _shell_exts
	endswith(path, ext)
	not _zsh_shebang(content)
}

# An extensionless script with a non-zsh shell shebang. The Gradle and Maven
# wrappers are generated.
_is_shell(path, content) if {
	startswith(content, "#!")
	regex.match(`(^|/)[^/.]+$`, path)
	not regex.match(`(^|/)(gradlew|mvnw)$`, path)
	regex.match(`^#![ \t]*(\S*/)?(env[ \t]+(-\S+[ \t]+)*)?(ba|da|k|mk)?sh(\s|$)`, content)
}

_zsh_shebang(content) if regex.match(`^#![ \t]*(\S*/)?(env[ \t]+(-\S+[ \t]+)*)?zsh(\s|$)`, content)

_comment(line) if startswith(trim_space(line), "#")

# Double-quoted strings (with ${...} and up to two levels of $( ) nesting
# carrying their own quotes) and single-quoted strings.
_dq := `"(?:[^"\\$]|\\.|\$\{(?:[^{}]|\{[^{}]*\})*\}|\$\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|\$)*"`

_sq := `'[^']*'`

_strings(line) := regex.replace(regex.replace(line, `\\.`, ""), concat("|", [_dq, _sq]), "_q_")

# What the shell splits on this line: strings, [[ ]], arithmetic, assignment
# words and case words removed.
_bare(stripped) := t if {
	t2 := regex.replace(stripped, `\$\(\((?:[^()]|\([^()]*\))*\)\)|\(\((?:[^()]|\([^()]*\))*\)\)`, "0")
	t3 := regex.replace(t2, `\[\[.*?\]\]`, "true")
	t4 := regex.replace(t3, `(^|[\s;&|(])((local|export|readonly|declare|typeset)(\s+-\w+)*\s+)?[A-Za-z_]\w*(\[[^\]]*\])?\+?=\S*`, "$1")
	t := regex.replace(t4, `\bcase\s+\S+\s+in\b`, "case")
}

# A quote left open on the line: it opens or closes a multi-line string.
_open_quote(line) if regex.match(`["']`, _strings(line))

# Line i lies inside a string opened on an earlier line (an odd number of
# lines with an unbalanced quote in the 40 lines above).
_in_multiline_string(lines, i) if {
	opens := [j |
		some j in numbers.range(max([0, i - 40]), i - 1)
		regex.match(`["']`, lines[j])
		not _comment(lines[j])
		_open_quote(lines[j])
	]
	count(opens) % 2 == 1
}

# Lines whose only command prints or exits: splitting there is cosmetic.
_harmless(bare) if regex.match(`^\s*(echo|printf|:|exit|return|shift|log\w*|info|warn\w*|error|die|debug)\b[^;&|]*$`, bare)

_exp_re := `\$(?:\{([A-Za-z_]\w*|[0-9])(?:[:/%^,][^}]*)?\}|([A-Za-z_]\w*|[0-9@*]))`

_names(bare) := {n |
	some m in regex.find_all_string_submatch_n(_exp_re, bare, -1)
	n := concat("", [m[1], m[2]])
}

_positional(n) if regex.match(`^[0-9@*]$`, n)

# ── Function scope ──────────────────────────────────────────────────────

# Function headers and column-0 closing braces of a file, found once.
# Indexes of the lines matching re, found with one whole-content search.
_lines_matching(content, lines, re) := js if {
	set := {m[0] | some m in regex.find_all_string_submatch_n(concat("", [`(?m)^.*(?:`, re, `).*$`]), content, -1)}
	js := [j | count(set) > 0; some j, l in lines; set[l]]
}

_fn_head_re := `^\s*(?:function\s+[\w:.-]+|[\w:.-]+\s*\(\s*\))\s*(?:\{|\(|$)`

# Every line any per-file index needs, found in one pass.
_interesting_re := `\(\s*\)|\bfunction\s|^\}|=["']?\$\{?[1-9@*]|\bfor\s+\w+\s+in\s+"?\$[@*{]|OPTARG|\bread\b`

_fn_info(lines, hits) := {
	"h": [j | some j in hits; regex.match(_fn_head_re, lines[j])],
	"c": [j | some j in hits; startswith(lines[j], "}")],
}

# Line i is inside a function body: the nearest header above it has no
# column-0 closing brace between it and i.
_in_function(fn, i) if {
	hs := [h | some h in fn.h; h < i]
	count(hs) > 0
	s := max(hs)
	not _closed_between(fn, s, i)
}

_closed_between(fn, s, i) if {
	some c in fn.c
	s < c
	c < i
}

# ── Caller-controlled names ─────────────────────────────────────────────

_assign_pos_re(n) := concat("", [`(?:^|[\s;(])(?:(?:local|export|readonly|declare|typeset)(?:\s+-\w+)*\s+)?`, n, `=["']?\$\{?[1-9@*]\b`])

_input_re(n) := concat("", [
	`(?:^|[\s;(])(?:(?:local|export|readonly|declare|typeset)(?:\s+-\w+)*\s+)?`, n, `=["']?\$\{?OPTARG\b`,
	`|\bread\b[^;|&]*\s`, n, `(?:\s|;|$)`,
])

_tainted(_, _, _, n) if {
	_positional(n)
	n != "0"
}

# A name assigned from the caller within the 80 lines above.
_tainted(_, idx, i, n) if {
	not _positional(n)
	some j in idx[n]
	j <= i
	i - j <= 80
}

# [line, name] for every assignment from the caller: from a script-level
# positional parameter or for loop over "$@" (outside any function), and from
# read or OPTARG anywhere.
_sources(lines, hits, fn) := array.concat(_pos_sources(lines, hits, fn), _input_sources(lines, hits))

# Source lines by name.
_index(srcs) := {n: js | some s in srcs; n := s[1]; js := [t[0] | some t in srcs; t[1] == n]}

_pos_sources(lines, hits, fn) := [[j, m[1]] |
	some j in hits
	l := lines[j]
	regex.match(`=["']?\$\{?[1-9@*]|\bfor\s+\w+\s+in\s+"?\$[@*{]`, l)
	not _comment(l)
	some m in regex.find_all_string_submatch_n(`(?:^|[\s;(])(?:for\s+)?([A-Za-z_]\w*)(?:=["']?\$\{?[1-9@*]|\s+in\s+"?\$(?:[@*]|\{[@*1-9]\}))`, l, -1)
	not regex.match(`\b(local|declare|typeset)\s`, l)
	not _in_function(fn, j)
]

_input_sources(lines, hits) := array.concat(
	[[j, m[1]] |
		some j in hits
		l := lines[j]
		contains(l, "OPTARG")
		some m in regex.find_all_string_submatch_n(`(?:^|[\s;(])([A-Za-z_]\w*)=["']?\$\{?OPTARG\b`, l, -1)
	],
	[[j, w] |
		some j in hits
		l := lines[j]
		contains(l, "read")
		not _comment(l)
		some m in regex.find_all_string_submatch_n(`\bread\b([^;|&<>]*)`, l, -1)
		some w in split(m[1], " ")
		regex.match(`^[A-Za-z_]\w*$`, w)
	],
)

_line_re(ns) := r if {
	count(ns) > 0
	r := concat("", [`\$\{?(?:[1-9@*]|(?:`, concat("|", [n | some n in ns]), `)\b)`])
}

_line_re(ns) := `\$\{?[1-9@*]` if count(ns) == 0

# ── Here-documents ──────────────────────────────────────────────────────

_heredocs(lines) := [[s, e] |
	some s, l in lines
	contains(l, "<<")
	not _comment(l)
	m := regex.find_all_string_submatch_n(`(?:^|[^<])<<-?\s*(?:'([A-Za-z_][\w-]*)'|"([A-Za-z_][\w-]*)"|\\?([A-Za-z_][\w-]*))`, l, 1)
	count(m) > 0
	delim := concat("", [m[0][1], m[0][2], m[0][3]])
	ends := [j |
		some j in numbers.range(s + 1, min([s + 400, count(lines) - 1]))
		trim_space(lines[j]) == delim
	]
	count(ends) > 0
	e := ends[0]
]

_in_heredoc(docs, i) if {
	some d in docs
	d[0] < i
	i < d[1]
}

_docs(content, lines) := _heredocs(lines) if contains(content, "<<")

_docs(content, _) := [] if not contains(content, "<<")

findings contains finding if {
	some path, content in input.file_contents
	_is_shell(path, content)
	not helpers.is_test_path(path)
	regex.match(`\$\{?[1-9@*]|OPTARG|\bread\b`, content)
	lines := split(content, "\n")
	hits := _lines_matching(content, lines, _interesting_re)
	fn := _fn_info(lines, hits)
	idx := _index(_sources(lines, hits, fn))
	ext := {n | some n, _ in idx}
	line_re := _line_re(ext)
	docs := _docs(content, lines)
	some i, line in lines
	contains(line, "$")
	regex.match(line_re, line)
	not _comment(line)
	cands := {n |
		some n in _names(line)
		_known(ext, n)
		_tainted(lines, idx, i, n)
	}
	count(cands) > 0
	stripped := _strings(line)
	not regex.match(`["']`, stripped)
	bare := _bare(stripped)
	some n in _names(bare)
	n in cands
	not _harmless(bare)
	not _in_heredoc(docs, i)
	not _in_multiline_string(lines, i)
	not _fn_positional(fn, i, n)
	not _validated_numeric(content, n)
	finding := {
		"rule_id": metadata.id,
		"message": "An unquoted value from the caller (a positional parameter, read or OPTARG) is word-split and globbed here; quote it (\"$var\") or use [[ ]] for tests",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A positional parameter inside a function is the function's own argument.
_fn_positional(fn, i, n) if {
	_positional(n)
	_in_function(fn, i)
}

# The script checks the value is all digits ([[ $1 =~ ^[0-9]+$ ]] or a case
# arm *[!0-9]*), so it cannot split or glob.
_validated_numeric(content, n) if {
	regex.match(`^\w+$`, n)
	contains(content, "0-9")
	regex.match(concat("", [`\$\{?`, n, `\}?"?\s*=~\s*["']?\^\[(0-9|\[:digit:\])\][+*]?\$`]), content)
}

_validated_numeric(content, n) if {
	regex.match(`^\w+$`, n)
	contains(content, "0-9")
	regex.match(concat("", [`(?s)\bcase\s+"?\$\{?`, n, `\}?"?\s+in\b.{0,200}\*\[!\^?0-9\]\*`]), content)
}

_validated_numeric(content, n) if {
	regex.match(`^\w+$`, n)
	contains(content, "digit")
	regex.match(concat("", [`\$\{?`, n, `\}?"?\s*=~\s*["']?\^\[\[:digit:\]\]\+\$`]), content)
}

_known(_, n) if _positional(n)

_known(ext, n) if ext[n]
