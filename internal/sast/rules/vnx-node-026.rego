package vulnetix.rules.vnx_node_026

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-026",
	"name": "Child process spawn with shell:true enables command injection",
	"description": "Reports a child_process spawn(), spawnSync(), execFile() or execFileSync() call (bare, destructured, through any namespace or alias such as child_process./cp./import * as X, or require('child_process').spawn), a cross-spawn spawn() and an execa()/execaSync() call whose options set shell: true or a shell path string (inline, across lines, or in an options object assigned in the 30 lines above) while the command or an argument is not a constant: a variable, a property, or a template literal with an interpolation. Through a shell, metacharacters in that value run as extra commands. Not reported: shell: false or the default, a shell enabled only on Windows (shell: process.platform === 'win32'), a call whose command and arguments are all string literals or constants assigned a literal in the file (or __dirname / path.join of them), exec()/execSync() (always a shell; covered by VNX-NODE-003), lookalike functions (spawnEnemy, respawn), comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-026/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["command-injection", "spawn", "shell", "child-process", "node"],
}

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".jsx")
_is_js(path) if endswith(path, ".tsx")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

_call_re := `(?:^|[^\w$.]|(?:\b[A-Za-z_$][\w$]*|\))\.)(spawn|spawnSync|execFile|execFileSync|execa|execaSync)\s*\(`

_shell_re := `\bshell\s*:\s*(?:true\b|['"])`

# string literal contents removed; an interpolating template literal keeps its
# expressions as a marker
_strip(s) := regex.replace(
	regex.replace(s, concat("", ["`[^`$]*`"]), `''`),
	`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`,
	`''`,
)

_depth(lines, s, j) := sum([d |
	some k in numbers.range(s, j)
	c := _strip(lines[k])
	d := strings.count(c, "(") - strings.count(c, ")")
])

# The call's text from line i to its closing parenthesis (bounded).
_call_text(lines, i) := t if {
	hi := min([count(lines) - 1, i + 12])
	ends := [j | some j in numbers.range(i, hi); _depth(lines, i, j) <= 0]
	e := min(array.concat(ends, [hi]))
	t := concat("\n", [l | some k in numbers.range(i, e); l := lines[k]; not helpers.is_comment_line(l)])
}

# The text after the call's opening parenthesis.
_args(text) := a if {
	m := regex.find_all_string_submatch_n(concat("", ["(?s)", _call_re, `(.*)$`]), text, 1)
	count(m) > 0
	a := m[0][2]
}

# shell enabled inline
_shell_on(_, _, args) := "" if regex.match(_shell_re, _strip_keep_shell(args))

# shell enabled in an options object assigned above the call
_shell_on(lines, i, args) := id if {
	not regex.match(_shell_re, _strip_keep_shell(args))
	some id in _idents(args)
	some j in numbers.range(max([0, i - 30]), i - 1)
	contains(lines[j], id)
	regex.match(concat("", [`^\s*(?:export\s+)?(?:const|let|var)\s+`, id, `\b[^=]*=\s*\{`]), lines[j])
	some k in numbers.range(j, min([i - 1, j + 20]))
	not helpers.is_comment_line(lines[k])
	regex.match(_shell_re, lines[k])
}

# shell: '/bin/bash' is a string; keep it while stripping other literals
_strip_keep_shell(s) := regex.replace(s, `(shell\s*:\s*)'[^']*'|(shell\s*:\s*)"[^"]*"`, `${1}${2}'sh'`)

_idents(args) := {m[0] | some m in regex.find_all_string_submatch_n(`[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*`, _code_args(args), -1)}

# The positional arguments: the text before the inline options object, with
# string literals removed and `${` interpolation markers preserved.
_code_args(args) := c if {
	s := _strip(replace(args, "${", "$<"))
	parts := split(s, "{")
	c := parts[0]
}

_constant_ident(_, id) if id in {"__dirname", "__filename", "process.execPath", "process.cwd", "path.join", "path.resolve", "require.resolve", "true", "false", "null", "undefined", "async", "await"}

_constant_ident(content, id) if {
	regex.match(concat("", [`(?m)^\s*(?:export\s+)?const\s+`, id, `\s*=\s*(?:'[^'\n]*'|"[^"\n]*")\s*;?\s*$`]), content)
}

_dynamic(content, args, opts_id) if {
	contains(_code_args(args), "$<")
}

_dynamic(content, args, opts_id) if {
	some id in _idents(args)
	id != opts_id
	not _constant_ident(content, id)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	regex.match(`\bshell\s*:`, content)
	regex.match(`(child_process|execa|cross-spawn)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(spawn|execFile|execa)`, line)
	not helpers.is_comment_line(line)
	regex.match(_call_re, _strip(line))
	text := _call_text(lines, i)
	args := _args(text)
	opts_id := _shell_on(lines, i, args)
	_dynamic(content, args, opts_id)
	finding := {
		"rule_id": metadata.id,
		"message": "Child process started with shell enabled and a non-constant command or argument; shell metacharacters in that value execute as commands. Drop the shell option and pass arguments as an array",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
