package vulnetix.rules.vnx_bash_007

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-BASH-007",
	"name": "Unquoted command substitution in shell script",
	"description": "Reports a command substitution, $(...) or `...`, used outside double quotes as an argument of a command, where the shell word-splits and globs its output: cd $(dirname \"$f\"), chmod 600 $(find ...), tar czf out.tgz $(cat list), export $(grep -v '^#' .env | xargs), a continued command line, and a for loop over a file or text listing (for f in $(ls ...), $(find ...), $(cat ...), $(grep ...), $(git ls-files/diff --name-only ...)). A file name or line with a space or glob character then becomes several arguments or expands to other files, which is argument injection when the output is attacker-influenced. Not reported: substitutions inside double quotes (including nested ones and multi-line strings), assignments and ${VAR:-$(...)} defaults, [[ ]] tests, (( )) and $(( )) arithmetic, case words, here-strings, here-document bodies, a substitution in command position (if ! $(grep -q ...)), commands whose output is a number or a single token (seq, nproc, jobs -p, id, date, wc, uname, whoami, hostname, git rev-parse, tput, getconf, pgrep), for loops over other tool output, comments, echo/printf text, test paths and .bats files. Shell files are .sh, .bash and extensionless files with a sh/bash/dash/ksh shebang.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-007/",
	"languages": ["bash"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [88],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["word-splitting", "bash", "command-substitution", "shell"],
}

_is_bash(path, _) if endswith(path, ".sh")

_is_bash(path, _) if endswith(path, ".bash")

_is_bash(path, content) if {
	startswith(content, "#!")
	regex.match(`(^|/)[^/.]+$`, path)
	not regex.match(`(^|/)(gradlew|mvnw)$`, path)
	regex.match(`^#![ \t]*(\S*/)?(env[ \t]+(-\S+[ \t]+)*)?(ba|da|k|mk)?sh(\s|$)`, content)
}

_comment(line) if startswith(trim_space(line), "#")

# Number of unescaped occurrences of a quote character in s.
_count_quote(s, q) := n if {
	n := count(split(s, q)) - 1 - count(split(s, concat("", ["\\", q]))) + 1
}

# `$(` at part index k (k >= 1 of split(line, "$(")): the text before it.
_prefix(parts, k) := concat("$(", array.slice(parts, 0, k))

# The substitution at index k sits outside every quote, so the shell splits it.
_unquoted_at(parts, k) if {
	pre := _prefix(parts, k)
	_count_quote(pre, "\"") % 2 == 0
	_count_quote(pre, "'") % 2 == 0
	not regex.match(`(=|\$)\s*$`, pre) # assignment, or $$( )
	not regex.match(`\[\[[^\]]*$`, pre) # inside [[ ... ]]
	not regex.match(`<<<\s*$`, pre) # here-string
	not regex.match(`\(\([^)]*$`, pre) # inside (( ... ))
	not regex.match(`\bcase\s*$`, pre) # case word
}

# A substitution nested inside another that is itself in double quotes is
# quoted by the outer one: "$(cd "$(dirname "$0")" && pwd)". The outer is still
# open at boundary k when fewer `)` have appeared since it than substitutions
# opened after it.
_inside_open_quoted(parts, k) if {
	k >= 2
	some j in numbers.range(1, k - 1)
	_count_quote(_prefix(parts, j), "\"") % 2 == 1
	between := concat("$(", array.slice(parts, j, k))
	count(split(between, ")")) - 1 < k - j
}

# A default in an assignment: FIX=${VAR:-$(cd "$d" && pwd)} does not split.
_in_assignment_default(parts, k) if {
	regex.match(`^\s*(export\s+|local\s+|declare\s+|readonly\s+)?[A-Za-z_]\w*=\S*\$\{[^}]*$`, _prefix(parts, k))
}

# The substitution is the command word itself (its output is run, not split
# into another command's arguments).
_command_position(pre) if regex.match(`(^|[;&|({]|\bthen|\bdo|\belse|\bif|\bwhile|\buntil|!)\s*$`, pre)

# The inner command's first word, past sudo/command and env assignments.
_inner_cmd(inner) := c if {
	t := regex.replace(trim_space(inner), `^((sudo|command|builtin)\s+|[A-Za-z_]\w*=\S*\s+)*(\S*/)?`, "")
	c := regex.replace(t, `[\s);|&<>].*$`, "")
}

# Output that is a number, a token or a fixed list of tokens.
_safe_cmds := {
	"seq", "nproc", "jobs", "id", "date", "wc", "uname", "whoami", "hostname", "tput",
	"getconf", "pgrep", "pidof", "expr", "arch", "logname", "sysctl", "stat",
}

_safe_output(inner) if _inner_cmd(inner) in _safe_cmds

_safe_output(inner) if regex.match(`^\s*git\s+(rev-parse|rev-list\s+--count|describe)\b`, inner)

_safe_output(inner) if regex.match(`\|\s*wc\s+-[lcw]\s*$`, inner)

# for x in $(...): word splitting is what the loop asks for, and it goes wrong
# for listings of files and lines of text.
_for_loop(pre) if regex.match(`\bfor\s+\w+\s+in\s*$`, pre)

_listing(inner) if regex.match(`^\s*(sudo\s+)?(\S*/)?(ls|find|cat|grep|egrep|fgrep|locate|xargs|tail|head|sort|awk|sed|cut)\b`, inner)

_listing(inner) if regex.match(`^\s*git\s+(ls-files|diff\s+[^)]*--name-only|status\s+--porcelain|ls-tree)\b`, inner)

# A line whose only command prints.
_printing(line) if regex.match(`^\s*(echo|printf|log\w*|info|warn\w*|die|debug)\b`, line)

_reported(parts, k, cont) if {
	not startswith(parts[k], "(")
	_unquoted_at(parts, k)
	not _inside_open_quoted(parts, k)
	not _in_assignment_default(parts, k)
	pre := _prefix(parts, k)
	_arg_position(pre, cont)
	inner := parts[k]
	not _safe_output(inner)
	_loop_ok(pre, inner)
}

_loop_ok(pre, _) if not _for_loop(pre)

_loop_ok(pre, inner) if {
	_for_loop(pre)
	_listing(inner)
}

# ── Backticks ───────────────────────────────────────────────────────────

_bt := "`"

_strip_re := `"(?:[^"\\]|\\.)*"|'[^']*'`

_backtick_reported(line, cont) if {
	contains(line, _bt)
	stripped := regex.replace(line, _strip_re, "_q_")
	some m in regex.find_all_string_submatch_n(concat("", [`(^|.*?[^=\w])`, _bt, `([^`, _bt, `]+)`, _bt]), stripped, -1)
	pre := m[1]
	not regex.match(`=\S*$`, pre)
	_arg_position(pre, cont)
	not _safe_output(m[2])
	_loop_ok(pre, m[2])
}

# ── Multi-line strings and here-documents ───────────────────────────────

_dq := `"(?:[^"\\$]|\\.|\$\{(?:[^{}]|\{[^{}]*\})*\}|\$\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|\$)*"`

_open_quote(line) if regex.match(`["']`, regex.replace(regex.replace(line, `\\.`, ""), concat("|", [_dq, `'[^']*'`]), "_q_"))

_in_multiline_string(lines, i) if {
	opens := [j |
		some j in numbers.range(max([0, i - 40]), i - 1)
		regex.match(`["']`, lines[j])
		not _comment(lines[j])
		_open_quote(lines[j])
	]
	count(opens) % 2 == 1
}

_heredocs(lines) := [[s, e] |
	some s, l in lines
	contains(l, "<<")
	not _comment(l)
	m := regex.find_all_string_submatch_n(`(?:^|[^<])<<-?\s*(?:'([A-Za-z_][\w-]*)'|"([A-Za-z_][\w-]*)"|\\?([A-Za-z_][\w-]*))`, l, 1)
	count(m) > 0
	delim := concat("", [m[0][1], m[0][2], m[0][3]])
	ends := [j |
		some j in numbers.range(s + 1, min([s + 2000, count(lines) - 1]))
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

_has_sub(line) if contains(line, "$(")

_has_sub(line) if contains(line, _bt)

_line_reported(line, cont) if {
	contains(line, "$(")
	parts := split(line, "$(")
	some k in numbers.range(1, count(parts) - 1)
	_reported(parts, k, cont)
}

_line_reported(line, cont) if _backtick_reported(line, cont)

findings contains finding if {
	some path, content in input.file_contents
	_is_bash(path, content)
	not helpers.is_test_path(path)
	_has_sub(content)
	lines := split(content, "\n")
	docs := _docs(content, lines)
	some i, line in lines
	_has_sub(line)
	not _comment(line)
	not _printing(line)
	_line_reported(line, _continued(lines, i))
	not _in_heredoc(docs, i)
	not _in_multiline_string(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Unquoted command substitution is word-split and globbed into separate arguments; wrap it in double quotes (\"$(...)\"), or read a listing with mapfile -t / while read -r",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_arg_position(pre, _) if not _command_position(pre)

# The first word of a continuation line is an argument of the line above.
_arg_position(pre, true) if regex.match(`^\s*$`, pre)

_continued(lines, i) := true if _continued_true(lines, i)

_continued(lines, i) := false if not _continued_true(lines, i)

_continued_true(lines, i) if {
	i > 0
	endswith(trim_right(lines[i - 1], " \t\r"), "\\")
}
