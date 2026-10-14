package vulnetix.rules.vnx_py_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-002",
	"name": "eval()/exec() usage in Python",
	"description": "A call to the eval() or exec() builtin (bare, or as builtins.eval/builtins.exec), or to Pillow ImageMath.eval()/ImageMath.unsafe_eval() (which hand their expression to eval), in a .py file whose code argument is not a constant string: a variable, a request value, an f-string, a concatenation, a %-format or a .format() call, on the call line or on the next line of a call broken across lines. Whatever reaches that argument runs as Python with the process's privileges, and restricting globals (an empty __builtins__) does not sandbox it. Not reported: ast.literal_eval and other functions whose names merely contain eval, methods and definitions named eval/exec (model.eval(), app.exec(), def eval(self)), eval/exec of a constant string literal, executing the source of a file the code opens itself (exec(compile(f.read(), ...)), exec(open(path).read()), how config and startup files are loaded), and the names in comments or string literals. Whether the argument is attacker-controlled is not judged; VNX-94 reports eval/exec of request data.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-002/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-35"],
	"attack_technique": ["T1059.006"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["code-injection", "dangerous-function"],
}

# String literal contents are blanked so a call named inside a string is not
# a call, while the literal's quotes (and an f/r prefix) stay visible.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# The builtin: not a method (`model.eval(`), not a definition, not a longer
# name (`literal_eval(`). builtins.eval / builtins.exec are the same function.
_call_re := `(?:^|[^\w.]|\bbuiltins\.|\bImageMath\.(?:unsafe_)?)(eval|exec)\s*\((.*)$`

# The argument is one constant literal: "...", '...', r"..." or b"...".
_constant(arg) if regex.match(`^\s*[rRbBuU]{0,2}(?:""|'')\s*(?:[,)]|$)`, arg)

# Source read from a file the code opened itself.
_file_source(arg) if regex.match(`^\s*compile\s*\(\s*[\w.]+\.read(?:_text)?\(\)`, arg)

_file_source(arg) if regex.match(`^\s*(?:compile\s*\(\s*)?(?:open|[\w.]*Path)\s*\([^()]*\)\.read(?:_text)?\(\)`, arg)

# The first argument, from the call line or (for `exec(` alone) the next
# code line.
_arg(lines, i, rest) := rest if trim_space(rest) != ""

_arg(lines, i, rest) := _code(lines[j]) if {
	trim_space(rest) == ""
	j := helpers.next_code_index(lines, i, 3)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?:^|[^\w.]|builtins\.|ImageMath\.(?:unsafe_)?)(?:eval|exec)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:eval|exec)\s*\(`, line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:async\s+)?def\s`, line)
	c := _code(line)
	m := regex.find_all_string_submatch_n(_call_re, c, 1)
	count(m) > 0
	fn := m[0][1]
	arg := _arg(lines, i, m[0][2])
	not _constant(arg)
	not _file_source(arg)
	not regex.match(`^\s*\)`, arg)
	finding := {
		"rule_id": metadata.id,
		"message": _message(fn),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_message("eval") := "eval() of a non-constant expression executes arbitrary code; use ast.literal_eval() for literals or a dedicated parser"

_message("exec") := "exec() of non-constant code executes arbitrary Python; replace dynamic code with explicit dispatch or importlib with an allowlist"
