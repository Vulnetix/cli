package vulnetix.rules.vnx_bash_001

import rego.v1

metadata := {
	"id": "VNX-BASH-001",
	"name": "eval or sh -c of a dynamically built string",
	"description": "Reports a shell eval statement, and a bash/sh/zsh/ksh/dash -c (including /bin/sh -c, env bash -c) or su/runuser -c command string, whose text contains an expansion the shell will re-parse as code: a variable or positional parameter ($cmd, ${x}, $1, $@), a command substitution whose own command line is dynamic, or the output of a download or decoder ($(curl ...), $(wget ...), $(... | base64 -d)). Variables assigned only constant strings in the same file count as constant. Also reported: the indirect-reference idiom eval \"x=\\$$name\" when the name comes from a positional parameter or read, and find -exec sh -c / xargs -I{} sh -c scripts that paste {} into the code text. Not reported: static or single-quoted strings, escaped \\$, arithmetic and $?, eval \"$(tool init/env/hook)\" of a local tool's own output, getopt's eval set -- \"$opts\", indirect references through a name from a fixed list, sh -c 'script' _ \"$arg\" (the value is passed as an argument, not code), eval inside a string, comment or usage here-document, eval_gettext and other lookalikes, generated gradlew/mvnw wrappers and Makefiles. Shell files are .sh, .bash, .bats, .ksh, .zsh and extensionless files with a sh/bash/dash/ksh/zsh shebang.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-001/",
	"languages": ["bash", "shell", "generic"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["eval", "bash", "command-injection", "shell"],
}

# ── Which files are shell scripts ───────────────────────────────────────

_shell_exts := [".sh", ".bash", ".bats", ".ksh", ".zsh"]

_is_shell(path, _) if {
	some ext in _shell_exts
	endswith(path, ext)
}

# An extensionless script (bin/deploy, docker-entrypoint) with a shell
# shebang. The Gradle and Maven wrappers are generated and escape their own
# arguments before the eval they contain.
_is_shell(path, content) if {
	regex.match(`(^|/)[^/.]+$`, path)
	not regex.match(`(^|/)(gradlew|mvnw)$`, path)
	regex.match(`^#![ \t]*(\S*/)?(env[ \t]+(-\S+[ \t]+)*)?(ba|da|k|z|mk)?sh(\s|$)`, content)
}

_comment(line) if startswith(trim_space(line), "#")

_bt := "`"

# Double-quoted strings holding no command substitution, and single-quoted
# strings: removed before asking whether `eval` is a command on the line, so
# `echo "never eval $x"` is text.
_strip_re := `"(?:[^"\\$]|\\.|\$[^("])*\$?"|'[^']*'`

_eval_re := concat("", [`(?:^|[;&|(){!`, _bt, `]|\b(?:then|do|else|if|elif|while|until|command|builtin|time)\s)\s*eval\s+(.*)$`])

_dash_c_re := `(?:^|[\s;&|(!])(?:\S*/)?(?:ba|da|k|z)?sh\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*c\s+(.*)$`

# Shell words: a double-quoted string, a single-quoted string, an operator, or
# a bare word.
_tok_re := `"(?:[^"\\]|\\.)*"|'[^']*'|[;&|]+|[^\s;&|"']+`

# ── The evaluated text ──────────────────────────────────────────────────

# The words of `arg` up to the first command separator.
_words(arg) := ws if {
	toks := [t | some m in regex.find_all_string_submatch_n(_tok_re, arg, -1); t := m[0]]
	seps := [k |
		some k, t in toks
		regex.match(`^[;&|]+$`, t)
		_depth(array.slice(toks, 0, k)) <= 0
	]
	end := min(array.concat(seps, [count(toks)]))
	ws := array.slice(toks, 0, end)
}

# Open command substitutions in a run of words: a separator inside one is
# part of the substituted command, not the end of the evaluated words.
_depth(ts) := n if {
	txt := concat(" ", ts)
	n := count(split(txt, "$(")) - count(split(txt, ")"))
}

# Text the shell expands: single-quoted words dropped, escapes and the
# indirect-name form (\$$name) removed, arithmetic removed.
_expanded(words) := t if {
	kept := concat(" ", [w | some w in words; not startswith(w, "'")])
	t1 := regex.replace(kept, `\\\$\$\{?([A-Za-z_]\w*|[0-9@*])\}?`, "")
	t2 := regex.replace(t1, `\\.`, "")
	t := regex.replace(t2, `\$\(\([^()]*\)\)`, "0")
}

_var_re := `\$\{?([A-Za-z_]\w*|[0-9@*])`

_vars(t) := {v | some m in regex.find_all_string_submatch_n(_var_re, t, -1); v := m[1]}

# Command substitutions whose body is a fixed command line.
_subs(t) := array.concat(
	[m[1] | some m in regex.find_all_string_submatch_n(`\$\(([^()]*)\)`, t, -1)],
	[m[1] | some m in regex.find_all_string_submatch_n(concat("", [_bt, `([^`, _bt, `]*)`, _bt]), t, -1)],
)

_open_subs(t) := count(split(t, "$(")) - 1 + ((count(split(t, _bt)) - 1) / 2)

# Fetchers and decoders: their output is remote or hidden data, not a local
# tool's own shell setup.
_untrusted_cmd(body) if {
	first := regex.replace(trim_space(body), `^(sudo\s+|command\s+|exec\s+)*(\S*/)?`, "")
	regex.match(`^(curl|wget|nc|ncat|socat|fetch|http|https|aria2c|lynx|base64|xxd|openssl|gunzip|zcat|ssh)(\s|$)`, first)
}

_untrusted_cmd(body) if regex.match(`\|\s*(base64|xxd|openssl|gunzip|zcat)(\s|$)`, body)

# A variable every assignment of which in the file is a constant string.
_constant_var(lines, v) if {
	regex.match(`^[A-Za-z_]\w*$`, v)
	re := concat("", [`(?:^|[\s;(])(?:local\s+|export\s+|readonly\s+|(?:declare|typeset)\s+(?:-\w+\s+)*)?`, v, `\+?=(.*)$`])
	vals := [m[0][1] |
		some l in lines
		contains(l, v)
		not _comment(l)
		m := regex.find_all_string_submatch_n(re, l, 1)
		count(m) > 0
	]
	count(vals) > 0
	every val in vals {
		not regex.match(concat("", [`[$`, _bt, `]`]), val)
	}
	not _assigned_dynamically(lines, v)
}

_assigned_dynamically(lines, v) if {
	some l in lines
	contains(l, v)
	regex.match(concat("", [`\b(read\b[^;|&]*|for\s+|getopts\s+\S+\s+)`, v, `\b`]), l)
}

# The getopt idiom: getopt's output is quoted for exactly this eval.
_getopt_idiom(lines, words, vars) if {
	count(words) > 1
	words[0] == "set"
	words[1] == "--"
	_from_getopt(lines, words, vars)
}

_from_getopt(_, words, _) if {
	some w in words
	contains(w, "$(getopt")
}

_from_getopt(lines, _, vars) if {
	count(vars) > 0
	every v in vars {
		some l in lines
		contains(l, v)
		regex.match(concat("", [`\b`, v, `=["']?\$\(\s*(\S*/)?getopt\b`]), l)
	}
}

# Names that a nearby line takes from the caller: a positional parameter,
# read, OPTARG, or a loop over "$@".
_tainted_name(_, _, v) if regex.match(`^[0-9@*]$`, v)

_tainted_name(lines, i, v) if {
	some j in numbers.range(max([0, i - 40]), i - 1)
	l := lines[j]
	contains(l, v)
	not _comment(l)
	regex.match(concat("", [`(\b`, v, `=["']?\$\{?([0-9@*]|OPTARG)|\bread\b[^;|&]*\b`, v, `\b|\bfor\s+`, v, `\s+in\s+"?\$[@*{])`]), l)
}

# The evaluated words carry code the script did not write.
_dynamic(lines, i, words) if {
	t := _expanded(words)
	vars := _vars(t)
	not _getopt_idiom(lines, words, vars)
	_dynamic_text(lines, t, vars)
}

_dynamic(lines, i, words) if {
	kept := concat(" ", [w | some w in words; not startswith(w, "'")])
	some m in regex.find_all_string_submatch_n(`\\\$\$\{?([A-Za-z_]\w*|[0-9@*])`, kept, -1)
	_tainted_name(lines, i, m[1])
}

_dynamic_text(lines, _, vars) if {
	some v in vars
	not _constant_var(lines, v)
}

_dynamic_text(_, t, _) if {
	some body in _subs(t)
	_untrusted_cmd(body)
}

# A substitution this rule cannot take apart (nested) is not assumed safe.
_dynamic_text(_, t, _) if _open_subs(t) > count(_subs(t))

# ── Here-documents shown as text ────────────────────────────────────────

_heredocs(lines) := [[s, e] |
	some s, l in lines
	contains(l, "<<")
	not _comment(l)
	m := regex.find_all_string_submatch_n(`(?:^|[^<])<<-?\s*(?:'([A-Za-z_][\w-]*)'|"([A-Za-z_][\w-]*)"|\\?([A-Za-z_][\w-]*))`, l, 1)
	count(m) > 0
	not regex.match(`\b(bash|sh|zsh|ksh|dash|ssh|su|sudo|exec|eval|source)\b`, regex.replace(l, _strip_re, ""))
	delim := concat("", [m[0][1], m[0][2], m[0][3]])
	ends := [j |
		some j in numbers.range(s + 1, min([s + 2000, count(lines) - 1]))
		trim_space(lines[j]) == delim
	]
	count(ends) > 0
	e := ends[0]
]

_in_text_heredoc(docs, i) if {
	some d in docs
	d[0] < i
	i < d[1]
}

_docs(content, lines) := _heredocs(lines) if contains(content, "<<")

_docs(content, _) := [] if not contains(content, "<<")

# ── Findings ────────────────────────────────────────────────────────────

_arg(line, stripped, re) := m[0][1] if {
	regex.match(re, stripped)
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
}

_eval_words(line, stripped) := _words(_arg(line, stripped, _eval_re))

# sh -c: only the command string (the first word after -c) is code; the
# words after it are $0, $1 ... and are passed as values.
_dash_c_words(line, stripped) := [ws[0]] if {
	ws := _words(_arg(line, stripped, _dash_c_re))
	count(ws) > 0
}

# su/runuser -c: the command string is run by the target user's shell.
_su_c_re := `(?:^|[\s;&|(!])(?:\S*/)?(?:su|runuser)\s+(?:[^\s;&|]+\s+)*?(?:-c|--command)(?:\s+|=)(.*)$`

_su_c_words(line, stripped) := [ws[0]] if {
	regex.match(`\b(su|runuser)\s`, line)
	ws := _words(_arg(line, stripped, _su_c_re))
	count(ws) > 0
}

_message := "eval or sh -c re-parses a string built from variables or command output, so any shell syntax in that data runs as code; pass values as arguments (\"$@\", an array, sh -c 'cmd \"$1\"' _ \"$value\") or dispatch with a case statement instead"

findings contains finding if {
	some path, content in input.file_contents
	_is_shell(path, content)
	regex.match(`(?m)(eval|sh\s+(-[A-Za-z]+\s+)*-[A-Za-z]*c|\b(su|runuser)\s.*(-c|--command))\s`, content)
	lines := split(content, "\n")
	docs := _docs(content, lines)
	some i, line in lines
	regex.match(`(eval|sh|su|runuser)\s`, line)
	not _comment(line)
	not _in_text_heredoc(docs, i)
	stripped := regex.replace(line, _strip_re, "\"\"")
	_flagged(lines, i, line, stripped)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_flagged(lines, i, line, stripped) if _dynamic(lines, i, _eval_words(line, stripped))

_flagged(lines, i, line, stripped) if _dynamic(lines, i, _dash_c_words(line, stripped))

_flagged(lines, i, line, stripped) if _dynamic(lines, i, _su_c_words(line, stripped))

# find -exec sh -c '... {} ...' and xargs -I{} sh -c '... {} ...': the file
# name or input line is pasted into the script text, quoted or not.
_flagged(_, _, line, stripped) if {
	contains(line, "{}")
	regex.match(`\s-exec(dir)?\s|\bxargs\s`, line)
	some w in _dash_c_words(line, stripped)
	contains(w, "{}")
}
