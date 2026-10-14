package vulnetix.rules.vnx_py_007

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-007",
	"name": "subprocess with shell=True",
	"description": "A shell command line is built from non-constant text and run by /bin/sh: subprocess.call/run/Popen/check_call/check_output with shell=True (through the module, an `import subprocess as sp` alias or a name imported from subprocess, with the keyword anywhere in a call broken over several lines), or subprocess.getoutput/getstatusoutput and asyncio.create_subprocess_shell, which always use the shell, whose command is a variable, an f-string, a concatenation, a %-format or a .format() call; and the same call without shell=True whose argument list starts an explicit shell on a non-constant script (a list such as [sh, -c, f-string] or [cmd.exe, /c, name], inline or appended to a list in the 20 lines above). Shell metacharacters in any interpolated value (; | $() `) then run commands. Not reported: a constant command string, or a variable assigned only constant strings in the 30 lines above, an argument list that does not start sh -c / cmd /c with a non-constant script, shell=False or a shell flag that is not the literal True, a command whose interpolations go through shlex.quote()/pipes.quote(), run methods of other objects (conn.run in Fabric), os.system/os.popen, and the names in comments or string literals. Whether the interpolated value is attacker-controlled is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-007/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059.006"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["command-injection", "subprocess", "dangerous-function"],
}

_flag_fns := {"call", "run", "Popen", "check_call", "check_output"}

_shell_fns := {"getoutput", "getstatusoutput", "create_subprocess_shell"}

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_mods(content) := array.concat(["subprocess"], [m[1] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+subprocess\s+as\s+(\w+)`, content, -1)
])

# `from subprocess import call, check_call as run_checked`
_bare(content) := {alias: ws[0] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+subprocess\s+import\s+\(?([^\n)#]+)`, content, -1)
	some part in split(m[1], ",")
	ws := regex.split(`\s+as\s+`, trim_space(part))
	_known(ws[0])
	alias := ws[count(ws) - 1]
}

_known(f) if f in _flag_fns

_known(f) if f in {"getoutput", "getstatusoutput"}

_call_re(content) := re if {
	fns := `(?:call|run|Popen|check_call|check_output|getoutput|getstatusoutput)`
	mods := concat("", [`(?:`, concat("|", _mods(content)), `)\.`, fns])
	alts := array.concat([mods, `asyncio\.create_subprocess_shell`], [a | some a, _ in _bare(content)])
	re := concat("", [`(?:^|[^\w.])(`, concat("|", alts), `)\s*\((.*)$`])
}

_fn(callee, bare) := bare[callee]

_fn(callee, bare) := f if {
	not bare[callee]
	parts := split(callee, ".")
	f := parts[count(parts) - 1]
}

_depth(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

_close_index(lines, i, rest) := k if {
	end := min([count(lines) - 1, i + 8])
	end >= i + 1
	d0 := _depth(rest) + 1
	ks := [j |
		some j in numbers.range(i + 1, end)
		d0 + sum([_depth(_code(lines[x])) | some x in numbers.range(i + 1, j)]) <= 0
	]
	count(ks) > 0
	k := ks[0]
}

# The call's argument text (strings blanked) up to the balancing parenthesis.
_call_text(_, _, rest) := rest if _depth(rest) < 0

_call_text(lines, i, rest) := rest if {
	_depth(rest) >= 0
	not _close_index(lines, i, rest)
}

_call_text(lines, i, rest) := txt if {
	_depth(rest) >= 0
	k := _close_index(lines, i, rest)
	more := [_code(lines[j]) | some j in numbers.range(i + 1, k); not helpers.is_comment_line(lines[j])]
	txt := concat("\n", array.concat([rest], more))
}

# The same span with strings intact, for the quoting check.
_raw_text(lines, i, n) := concat("\n", [lines[j] | some j in numbers.range(i, min([count(lines) - 1, i + n]))])

_needs_shell_flag(fn) if fn in _flag_fns

_shell_on(fn, _) if fn in _shell_fns

_shell_on(fn, args) if {
	_needs_shell_flag(fn)
	regex.match(`\bshell\s*=\s*True\b`, args)
}

# The command: the first argument, or args=.
_command(args) := trim_space(regex.replace(args, `^\s*args\s*=\s*`, ""))

_constant(cmd) if regex.match(`^[rRbBuU]{0,2}(?:""|'')\s*(?:[,)]|$)`, cmd)

_list(cmd) if regex.match(`^[\[(]`, cmd)

# A bare name whose every assignment in the 30 lines above is a constant string.
_constant_var(lines, i, cmd) if {
	m := regex.find_all_string_submatch_n(`^([A-Za-z_]\w*)\s*(?:[,)]|$)`, cmd, 1)
	count(m) > 0
	v := m[0][1]
	re := concat("", [`^\s*`, v, `\s*(?:[-+*/%|&^]|//|<<|>>)?=[^=]`])
	assigns := [_code(lines[j]) |
		some j in numbers.range(max([0, i - 30]), i - 1)
		regex.match(re, lines[j])
	]
	count(assigns) > 0
	every a in assigns {
		regex.match(concat("", [`^\s*`, v, `\s*=\s*[rRbBuU]{0,2}(?:""|'')\s*(?:#.*)?$`]), a)
	}
}

_quoted(raw) if regex.match(`\b(?:shlex|pipes)\.quote\s*\(`, raw)

# ── An explicit shell in the argument list: ["sh", "-c", cmd] ────────────

_shell_prog := `[rbuRBU]?["'](?:/usr)?(?:/bin/)?(?:ba|z|da|k)?sh["']\s*,\s*["']-c["']|[rbuRBU]?["']cmd(?:\.exe)?["']\s*,\s*["']/[cCkK]["']`

# The script element is an f-string, a name or call, or a concatenation/format.
_dynamic_elem := `(?:[fF][rR]?["']|[A-Za-z_(]|["'][^"'\n]*["']\s*(?:[+%]|\.format\b))`

_inline_shell_list(raw) if regex.match(concat("", [`\[\s*(?:`, _shell_prog, `)\s*,\s*`, _dynamic_elem]), raw)

# A list variable assembled just above: v.append("sh"); v.append("-c");
# v.append(f"echo {x}"), or v = ["sh", "-c", x].
_built_shell_list(lines, i, cmd) if {
	m := regex.find_all_string_submatch_n(`^([A-Za-z_]\w*)\s*(?:[,)]|$)`, cmd, 1)
	count(m) > 0
	v := m[0][1]
	win := concat("\n", [lines[j] | some j in numbers.range(max([0, i - 20]), i - 1)])
	contains(win, v)
	_appended_shell(win, v)
}

_appended_shell(win, v) if {
	regex.match(concat("", [`\b`, v, `\.append\(\s*[rbu]?["'](?:/usr)?(?:/bin/)?(?:(?:ba|z|da|k)?sh|cmd(?:\.exe)?)["']\s*\)`]), win)
	regex.match(concat("", [`\b`, v, `\.append\(\s*["'](?:-c|/[cCkK])["']\s*\)`]), win)
	regex.match(concat("", [`\b`, v, `\.append\(\s*`, _dynamic_elem]), win)
}

_appended_shell(win, v) if {
	regex.match(concat("", [`(?m)^\s*`, v, `\s*=\s*\[\s*(?:`, _shell_prog, `)\s*,\s*`, _dynamic_elem]), win)
}

_explicit_shell(lines, i, raw, cmd) if _inline_shell_list(raw)

_explicit_shell(lines, i, _, cmd) if _built_shell_list(lines, i, cmd)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "subprocess")
	regex.match(`["'](?:/usr)?(?:/bin/)?(?:(?:ba|z|da|k)?sh|cmd(?:\.exe)?)["']`, content)
	re := _call_re(content)
	bare := _bare(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(re, _code(line), 1)
	count(m) > 0
	fn := _fn(m[0][1], bare)
	_needs_shell_flag(fn)
	args := _call_text(lines, i, m[0][2])
	not _shell_on(fn, args)
	cmd := _command(args)
	raw := _raw_text(lines, i, count(split(args, "\n")) - 1)
	_explicit_shell(lines, i, raw, cmd)
	not _quoted(raw)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s() runs a shell (sh -c / cmd /c) on a command built from non-constant text; pass the program and its arguments as a list without a shell", [fn]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`subprocess|create_subprocess_shell`, content)
	re := _call_re(content)
	regex.match(concat("", ["(?m)", re]), content)
	bare := _bare(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(re, _code(line), 1)
	count(m) > 0
	fn := _fn(m[0][1], bare)
	args := _call_text(lines, i, m[0][2])
	_shell_on(fn, args)
	cmd := _command(args)
	not _constant(cmd)
	not _list(cmd)
	not _constant_var(lines, i, cmd)
	not _quoted(_raw_text(lines, i, count(split(args, "\n")) - 1))
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s() runs a command line built from non-constant text through the shell; pass an argument list with shell=False, or shlex.quote() every interpolated value", [fn]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
