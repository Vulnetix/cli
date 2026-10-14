package vulnetix.rules.vnx_ruby_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUBY-002",
	"name": "eval() or system() in Ruby",
	"description": "Request input reaches a Ruby code or shell evaluator: eval, instance_eval, class_eval or module_eval given a string, or a shell command run by system, exec, spawn, Kernel#open, IO.popen, backticks or %x() in its single-string (shell) form. Request input is params, request.params/body/query_string/headers/cookies/env/path/url/referer/user_agent, cookies, Rack env request keys or an upload's original_filename, used on the call line or through a variable assigned from it (up to two assignments) in the 12 lines above. Not reported: constant commands and code strings, the argument-list form (system(\"ping\", \"-c\", \"1\", host), IO.popen([...])), input passed through Shellwords.escape/shellescape or converted with to_i/to_f, block forms (instance_eval do ... end), receivers other than Kernel/Process (File.open, conn.exec), text inside string literals and comments. Metaprogramming that interpolates method names, ARGV and data read from local files are deliberately out of scope; Open3 calls are VNX-RUBY-008.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-002/",
	"languages": ["ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-35"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["code-injection", "command-injection", "dangerous-function"],
}

# Request input in Rails, Sinatra and Rack.
_src_re := `\bparams\b\s*(?:[\[\.\),]|$)|\brequest\.(?:params|query_parameters|request_parameters|body|raw_post|query_string|headers|env|path|fullpath|url|original_url|referr?er|user_agent|cookies|POST|GET)\b|\bcookies\s*[\[\.]|\.original_filename\b|\benv\[\s*["'](?:QUERY_STRING|PATH_INFO|REQUEST_URI|HTTP_\w+|rack\.input)|\breq\.(?:params|body|query_string|path|cookies)\b`

# A Ruby local, instance or class variable assigned on the line.
_assign_re := `^\s*(@{0,2}[A-Za-z_]\w*)\s*(?:\|\||\+)?=\s*[^=~>]`

# Input converted to a number cannot carry shell or Ruby syntax.
_numeric_re := `(?:params\s*\[[^\]]*\]|@?\w+)\.to_(?:i|f|r)\b`

_strip_comment(line) := regex.replace(line, `\s#[^{].*$`, "")

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	v := m[0][1]
}

_ident_re(v) := concat("", [`(?:^|[^\w@])`, v, `\b`])

# Variables assigned from request input above line i, and one more hop.
_tainted(lines, i) := t1 | t2 if {
	i > 0
	lo := max([0, i - 12])
	t1 := {v |
		some j in numbers.range(lo, i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		regex.match(_src_re, regex.replace(l, _numeric_re, ""))
		v := _assigned(l)
	}
	t2 := {w |
		some k in numbers.range(lo, i - 1)
		l := lines[k]
		not helpers.is_comment_line(l)
		w := _assigned(l)
		some v in t1
		v != w
		regex.match(_ident_re(v), regex.replace(l, `^\s*@{0,2}\w+\s*(?:\|\||\+)?=`, ""))
	}
}

_tainted(_, 0) := set()

_sanitised(args) if regex.match(`Shellwords|shellescape|\bescape_shell`, args)

_uses_input(lines, i, args) if {
	not _sanitised(args)
	a := regex.replace(args, _numeric_re, "")
	regex.match(_src_re, a)
}

_uses_input(lines, i, args) if {
	not _sanitised(args)
	a := regex.replace(args, _numeric_re, "")
	some v in _tainted(lines, i)
	regex.match(_ident_re(v), a)
}

# The token at the start of `rest` sits outside any string literal of the line.
_outside_string(line, tok) if {
	prefix := substring(line, 0, indexof(line, tok))
	stripped := regex.replace(prefix, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, "")
	not contains(stripped, `"`)
	not contains(stripped, "'")
}

# Argument-list form: an array, or a literal program followed by more arguments.
_exec_form(args) if regex.match(`^\s*\(?\s*(?:\[|(?:"[^"#]*"|'[^']*')\s*,|\{[^}]*\}\s*,\s*(?:"[^"#]*"|'[^']*')\s*,)`, args)

_shell_re := `(?:^|[^\w\.:@$])((?:(?:Kernel|Process)\.)?(?:system|exec|spawn|open)\b(.*))$`

_popen_re := `\b(IO\.popen\b(.*))$`

_eval_re := `(?:^|[^\w@$])((?:[\w\)\]]+\.)?(?:eval|instance_eval|class_eval|module_eval)\b(.*))$`

# Each sink kind with its regex: group 1 is the call from its name onward,
# group 2 its arguments (for backticks, the command text).
_sink_res := [
	["shell", _shell_re],
	["shell", _popen_re],
	["eval", _eval_re],
	["shell", "(`([^`]*#\\{[^`]*)`)"],
	["shell", `(%x[\(\{\[\|!](.*))$`],
]

_sinks(code) := {[r[0], m[1], m[2]] |
	some r in _sink_res
	some m in regex.find_all_string_submatch_n(r[1], code, -1)
}

# A call, not a hash key, a declaration or an assignment to the name.
_call_args(args) if regex.match("^(?:\\s*\\(|\\s+[\"'%@\\w$`])", args)

_reportable("shell", tok, args) if {
	not startswith(tok, "`")
	not startswith(tok, "%x")
	_call_args(args)
	not _exec_form(args)
}

_reportable("shell", tok, _) if startswith(tok, "`")

_reportable("shell", tok, _) if startswith(tok, "%x")

_reportable("eval", _, args) if {
	regex.match("^(?:\\s*\\(|\\s+[\"'%@\\w$`])", args)
	not regex.match(`^\s*(?:do\b|\{)`, args)
}

_message("shell") := "Request input reaches a shell command string (system/exec/spawn/open/IO.popen/backticks/%x); pass the program and its arguments as separate values, e.g. system(\"convert\", file, \"out.png\"), and validate the input against an allowlist"

_message("eval") := "Request input reaches eval/instance_eval/class_eval/module_eval and runs as Ruby code; dispatch through an explicit allowlist instead of evaluating strings"

findings contains finding if {
	some path, content in input.file_contents
	_is_ruby(path)
	regex.match("\\b(?:system|exec|spawn|open|popen|eval|instance_eval|class_eval|module_eval)\\b|`|%x", content)
	regex.match(`\b(?:params|request|cookies|original_filename|env|req)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match("\\b(?:system|exec|spawn|open|popen|eval)\\b|_eval\\b|`|%x", line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:def|alias|alias_method|attr_\w+)\s`, line)
	code := _strip_comment(line)
	some s in _sinks(code)
	_outside_string(code, s[1])
	args := _full_args(lines, i, s[2])
	_reportable(s[0], s[1], args)
	_uses_input(lines, i, args)
	finding := {
		"rule_id": metadata.id,
		"message": _message(s[0]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A call broken right after its opening parenthesis takes its first argument
# from the next code line.
_full_args(_, _, args) := args if not regex.match(`^\s*\(\s*$`, args)

_full_args(lines, i, args) := concat("", ["(", _strip_comment(lines[j])]) if {
	regex.match(`^\s*\(\s*$`, args)
	j := helpers.next_code_index(lines, i, 2)
}

_is_ruby(path) if endswith(path, ".rb")

_is_ruby(path) if endswith(path, ".rake")
