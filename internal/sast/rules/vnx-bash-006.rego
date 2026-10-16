package vulnetix.rules.vnx_bash_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-BASH-006",
	"name": "Global IFS reassignment in shell script",
	"description": "Reports an IFS change that escapes the code that needed it: IFS assigned as a statement (IFS=, or IFS=':'; read ...) inside a function that never declares local IFS and never restores it before the function ends, so the caller's word splitting silently changes; IFS assigned at script level and never restored in the next 300 lines (no IFS=$saved, IFS=$' \\t\\n' or unset IFS); export IFS, which passes the separator to every child process; and IFS taken from a positional parameter or OPTARG, which hands word splitting to the caller. Not reported: a command-prefix assignment (while IFS= read -r line, IFS=, read -r a b), IFS set inside a subshell or command substitution ($(IFS=,; echo \"${a[*]}\")), local IFS, an assignment restored from a saved variable or by unset IFS, the restore line itself, the strict-mode IFS=$'\\n\\t', variables merely named like IFS, comments, strings, test paths and .bats files. Shell files are .sh, .bash and extensionless files with a sh/bash/dash/ksh shebang.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-006/",
	"languages": ["bash", "generic"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [20],
	"capec": ["CAPEC-15"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["ifs", "bash", "input-validation", "shell"],
}

_is_shell(path, _) if endswith(path, ".sh")

_is_shell(path, _) if endswith(path, ".bash")

_is_shell(path, content) if {
	startswith(content, "#!")
	regex.match(`(^|/)[^/.]+$`, path)
	regex.match(`^#![ \t]*(\S*/)?(env[ \t]+(-\S+[ \t]+)*)?(ba|da|k|mk)?sh(\s|$)`, content)
}

_comment(line) if startswith(trim_space(line), "#")

# IFS assigned as a statement of its own (not a command prefix).
_stmt_re := `(?:^|[;&|{)]|\bthen|\bdo|\belse)\s*(?:export\s+)?IFS=(\$'[^']*'|"[^"]*"|'[^']*'|[^\s;&|]*)\s*(?:;|&&|\|\||#|$)`

_value(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(_stmt_re, line, 1)
	count(m) > 0
}

# In a subshell or command substitution the change dies with it.
_subshell(line) if regex.match(`\(\s*(?:export\s+)?IFS=`, line)

_restore_value(v) if regex.match(`^"?\$\{?[A-Za-z_]\w*\}?"?$`, v)

_restore_value(v) if v == `$' \t\n'`

_restore_value(v) if v == `$'\n\t'`

_restore_value(v) if v == `$'\t\n'`

_tainted_value(v) if regex.match(`^["']?\$\{?(?:[1-9@*]|OPTARG)\b`, v)

_restore_re := `\bunset\s+(?:-v\s+)?IFS\b|\bIFS=(?:"\$\{?[A-Za-z_]\w*\}?"|\$\{?[A-Za-z_]\w*\}?|\$' \\t\\n')`

# ── Function scope ──────────────────────────────────────────────────────

_fn_starts(lines) := [j |
	some j, l in lines
	_maybe_fn(l)
	regex.match(`^\s*(function\s+[\w:.-]+|[\w:.-]+\s*\(\s*\))\s*(\{|\(|$)`, l)
]

_maybe_fn(l) if contains(l, "()")

_maybe_fn(l) if contains(l, "function")

_fn_ranges(lines) := [[s, e] |
	ends := [j | some j, l in lines; startswith(l, "}")]
	some s in _fn_starts(lines)
	e := min(array.concat([s + 1500, count(lines) - 1], [c | some c in ends; c > s]))
]

_scope(fr, i, _) := [r[0], r[1]] if {
	some r in fr
	r[0] < i
	i < r[1]
}

_scope(fr, i, n) := [-1, min([n - 1, i + 300])] if {
	not _in_any(fr, i)
}

_in_any(fr, i) if {
	some r in fr
	r[0] < i
	i < r[1]
}

_restored(lines, i, e) if {
	i + 1 <= e
	some j in numbers.range(i + 1, e)
	contains(lines[j], "IFS")
	not _comment(lines[j])
	regex.match(_restore_re, lines[j])
}

_local_ifs(lines, s, i) if {
	s >= 0
	some j in numbers.range(s, i - 1)
	regex.match(`\b(local|declare|typeset)\s+(-\w+\s+)*IFS\b`, lines[j])
}

_leaks(lines, fr, i, v) if {
	not _restore_value(v)
	not _tainted_value(v)
	sc := _scope(fr, i, count(lines))
	not _local_ifs(lines, sc[0], i)
	not _restored(lines, i, sc[1])
}

_reason(_, _, _, line, _) := "export" if regex.match(`\bexport\s+IFS\b`, line)

_reason(_, _, _, line, v) := "tainted" if {
	not regex.match(`\bexport\s+IFS\b`, line)
	_tainted_value(v)
}

_reason(lines, fr, i, line, v) := "leak" if {
	not regex.match(`\bexport\s+IFS\b`, line)
	_leaks(lines, fr, i, v)
}

_messages := {
	"export": "export IFS passes a changed field separator to every child process; set IFS only where it is needed and never export it",
	"tainted": "IFS is taken from the caller, which then controls how every later unquoted expansion is split; validate the separator or use read -d / parameter expansion instead",
	"leak": "IFS is changed and never restored in this scope, so every later unquoted expansion splits differently; use 'local IFS=...', a command prefix (IFS=, read ...) or a subshell",
}

_val_or_empty(line) := v if v := _value(line)

_val_or_empty(line) := "" if not _value(line)

findings contains finding if {
	some path, content in input.file_contents
	_is_shell(path, content)
	contains(content, "IFS")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	fr := _fn_ranges(lines)
	some i, line in lines
	contains(line, "IFS")
	not _comment(line)
	regex.match(`\bexport\s+IFS\b|(?:^|[;&|{)]|\bthen|\bdo|\belse)\s*(?:export\s+)?IFS=`, line)
	not _subshell(line)
	v := _val_or_empty(line)
	_stmt_or_export(line)
	reason := _reason(lines, fr, i, line, v)
	finding := {
		"rule_id": metadata.id,
		"message": _messages[reason],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_stmt_or_export(line) if regex.match(`\bexport\s+IFS\b`, line)

_stmt_or_export(line) if _value(line)
