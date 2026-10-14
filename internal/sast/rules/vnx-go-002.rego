package vulnetix.rules.vnx_go_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-002",
	"name": "Command injection via exec.Command",
	"description": "os/exec runs a command line that a formatted or request-supplied value can rewrite: exec.Command/CommandContext invokes a shell (sh, bash, zsh, dash, ksh, ash, cmd, powershell, pwsh, by name or path) with -c (or -lc, /C, -Command) and a script that is built with fmt.Sprintf or + concatenation, read from an HTTP request (net/http, gin, echo, fiber, gorilla/mux, chi), or held in a variable assigned from one of those in the 30 lines above; or the program to run is itself formatted, concatenated or taken from the request. Calls split over several lines are read as one. Not reported: a constant script, a value passed as a positional parameter after the script (sh -c '... \"$1\"' sh value), a value quoted with shellescape.Quote or shellquote.Join, a formatted or request value given as its own argument to a fixed program (no shell, so no injection), lookalike packages (sshexec.Command), the call inside a string literal or comment, and _test.go/testdata code, which builds its shell lines from its own constants.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-002/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["command-injection", "dangerous-function"],
}

# A value the requester chooses.
_request := `\b(?:r|req|request)\.(?:FormValue|PostFormValue)\(|\b(?:r|req|request)\.URL\.Query\(\)\.Get\(|\b(?:r|req|request)\.(?:Form|PostForm|Header)\.Get\(|\bmux\.Vars\(|\.PathValue\(|\bchi\.URLParam\(|\b(?:c|ctx|g|e)\.(?:Query|DefaultQuery|GetQuery|Param|Params|PostForm|DefaultPostForm|FormValue|QueryParam)\(`

# A command line assembled from pieces.
_built := `fmt\.Sprintf\(|"[^"]*"\s*\+\s*[\w(]|[\w)\]]\s*\+\s*"`

_shell := `"(?:(?:/usr)?(?:/local)?/bin/)?(?:sh|bash|zsh|dash|ksh|ash|cmd|cmd\.exe|powershell|powershell\.exe|pwsh)"`

_flag := `"(?:-[a-z]*c|/[cCkK]|-[Cc]ommand)"`

_quoted(text) if regex.match(`shellescape\.Quote\(|shellquote\.Join\(`, text)

# The call text: the line, plus its argument lines when the call is broken
# after '(' or ',' (up to the closing paren line).
_stmt(lines, i, line) := line if not regex.match(`[(,]\s*$`, line)

_stmt(lines, i, line) := s if {
	regex.match(`[(,]\s*$`, line)
	n := count(lines) - 1
	last := min([n, i + 6])
	closers := [k | some k in numbers.range(i + 1, last); startswith(trim_space(lines[k]), ")")]
	end := min(array.concat([last], closers))
	s := concat(" ", [lines[k] | some k in numbers.range(i, end)])
}

# The arguments of exec.Command / CommandContext (minus the context).
_args(stmt) := a if {
	parts := regex.split(`(?:^|[^\w.])exec\.Command\(`, stmt)
	count(parts) > 1
	a := parts[1]
}

_args(stmt) := a if {
	parts := regex.split(`(?:^|[^\w.])exec\.CommandContext\(`, stmt)
	count(parts) > 1
	a := regex.replace(parts[1], `^\s*[^,]+,\s*`, "")
}

# The call starts outside a string literal: an even number of double quotes
# and no raw-string backtick before it on the line.
_outside_string(line) if {
	idx := indexof(line, "exec.Command")
	idx >= 0
	prefix := regex.replace(substring(line, 0, idx), `\\.`, "")
	not contains(prefix, "`")
	count(regex.find_all_string_submatch_n(`"`, prefix, -1)) % 2 == 0
}

_word(v) := concat("", [`\b`, v, `\b`])

# Variables assigned, a few lines up, from a built string or a request value.
_tainted(lines, i) := helpers.tainted_names(lines, i, 30, concat("|", [_built, _request]))

# ── shell -c <script> ────────────────────────────────────────────────────
_script(args) := s if {
	m := regex.find_all_string_submatch_n(concat("", [`^\s*`, _shell, `\s*,\s*`, _flag, `\s*,\s*(.*)$`]), args, 1)
	count(m) > 0
	s := m[0][1]
}

_script(args) := s if {
	m := regex.find_all_string_submatch_n(concat("", [`^\s*"(?:/usr)?/bin/env"\s*,\s*`, _shell, `\s*,\s*`, _flag, `\s*,\s*(.*)$`]), args, 1)
	count(m) > 0
	s := m[0][1]
}

# The script's own expression: everything up to the first top-level comma
# that follows a closed string, or the closing paren. Approximated by cutting
# at '", ' (the start of a positional parameter list).
_script_expr(s) := regex.replace(s, `^((?:"(?:[^"\\]|\\.)*"|\x60[^\x60]*\x60|[^,"\x60])*).*$`, "$1")

_injectable(_, _, args) if {
	s := _script_expr(_script(args))
	regex.match(_built, s)
	not _quoted(s)
}

_injectable(_, _, args) if {
	s := _script_expr(_script(args))
	regex.match(_request, s)
}

_injectable(lines, i, args) if {
	s := _script(args)
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:[,)]|$)`, s, 1)
	count(m) > 0
	v := m[0][1]
	v in _tainted(lines, i)
}

# ── the program itself ──────────────────────────────────────────────────
_program(args) := p if {
	m := regex.find_all_string_submatch_n(`^\s*((?:"(?:[^"\\]|\\.)*"|[^,"])*)`, args, 1)
	count(m) > 0
	p := m[0][1]
}

_injectable(_, _, args) if {
	p := _program(args)
	regex.match(`^\s*fmt\.Sprintf\(|^\s*"[^"]*"\s*\+|^\s*[A-Za-z_][\w\.]*\s*\+`, p)
}

_injectable(_, _, args) if {
	p := _program(args)
	regex.match(_request, p)
}

_injectable(lines, i, args) if {
	p := trim_space(_program(args))
	regex.match(`^[A-Za-z_]\w*$`, p)
	some v in helpers.tainted_names(lines, i, 30, _request)
	v == p
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "exec.Command")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "exec.Command")
	not helpers.is_comment_line(line)
	_outside_string(line)
	args := _args(_stmt(lines, i, line))
	_injectable(lines, i, args)
	finding := {
		"rule_id": metadata.id,
		"message": "exec.Command runs a shell script or program name built from formatted or request-supplied text; pass the program and each argument separately, without sh -c",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
