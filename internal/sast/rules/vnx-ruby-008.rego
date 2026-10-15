package vulnetix.rules.vnx_ruby_008

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUBY-008",
	"name": "Open3 shell command built from request input",
	"description": "Request input reaches an Open3 call in its single-string (shell) form: Open3.pipeline, pipeline_r, pipeline_rw, pipeline_w, pipeline_start, popen3, popen2, popen2e, capture2, capture2e or capture3 (or the receiverless form after include Open3), where the command string interpolates, concatenates or formats request input, or the command is request input itself; the argument-list form that starts a shell (capture2(\"sh\", \"-c\", cmd), bash -lc) has its third argument read as the shell string. Request input is params, request.params/body/query_string/headers/cookies/env/path/url, cookies, Rack env request keys or an upload's original_filename, used on the call line or through a variable assigned from it (up to two assignments) in the 12 lines above; a call that spans lines is read up to 4 lines on. Not reported: argument-list and array forms (Open3.capture2(\"convert\", params[:f]), pipeline_r([\"cat\", f])), splatted argument arrays, constant commands, input passed through Shellwords.escape/shellescape or converted with to_i/to_f, an env hash as the first argument, other receivers (MyOpen3, redis.pipeline), text inside string literals and comments. Method arguments, ARGV and data read from local files are deliberately out of scope; Kernel#system, exec, spawn, backticks and IO.popen are VNX-RUBY-002.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-008/",
	"languages": ["ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["command-injection", "open3", "ruby"],
}

# Request input in Rails, Sinatra and Rack.
_src_re := `\bparams\b\s*(?:[\[\.\),]|$)|\brequest\.(?:params|query_parameters|request_parameters|body|raw_post|query_string|headers|env|path|fullpath|url|original_url|referr?er|user_agent|cookies|POST|GET)\b|\bcookies\s*[\[\.]|\.original_filename\b|\benv\[\s*["'](?:QUERY_STRING|PATH_INFO|REQUEST_URI|HTTP_\w+|rack\.input)|\breq\.(?:params|body|query_string|path|cookies)\b`

_methods := `pipeline(?:_rw?|_w|_start)?|popen3|popen2e?|capture2e?|capture3`

_call_re := concat("", [`\bOpen3\s*\.\s*(`, _methods, `)\b\s*\(?`])

_bare_call_re := concat("", [`(?:^|[^\w.:])(`, _methods, `)\b\s*\(?`])

_assign_re := `^\s*(@{0,2}[A-Za-z_]\w*)\s*(?:\|\||\+)?=\s*[^=~>]`

_numeric_re := `(?:params\s*\[[^\]]*\]|@?\w+)\.to_(?:i|f|r)\b`

_strip_comment(line) := regex.replace(line, `\s#[^{].*$`, "")

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	v := m[0][1]
}

_rhs(line) := regex.replace(line, `^\s*@{0,2}\w+\s*(?:\|\||\+)?=\s*`, "")

_ident_re(v) := concat("", [`(?:^|[^\w@])`, v, `\b`])

# An array literal holds an argument list, not a shell string.
_array_rhs(line) if regex.match(`^\s*(?:\[|%[wWiI][\[({])`, _rhs(line))

_tainted(lines, i) := t1 | t2 if {
	i > 0
	lo := max([0, i - 12])
	t1 := {v |
		some j in numbers.range(lo, i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		not _array_rhs(l)
		not _sanitised(l)
		regex.match(_src_re, regex.replace(_strip_comment(l), _numeric_re, ""))
		v := _assigned(l)
	}
	t2 := {w |
		some k in numbers.range(lo, i - 1)
		l := lines[k]
		not helpers.is_comment_line(l)
		not _array_rhs(l)
		not _sanitised(l)
		w := _assigned(l)
		some v in t1
		v != w
		regex.match(_ident_re(v), _rhs(_strip_comment(l)))
	}
}

_tainted(_, 0) := set()

_sanitised(text) if regex.match(`Shellwords|shellescape|\bescape_shell`, text)

# Is the expression request input, or does it name a tainted variable?
_is_input(lines, i, expr) if regex.match(_src_re, regex.replace(expr, _numeric_re, ""))

_is_input(lines, i, expr) if {
	e := regex.replace(expr, _numeric_re, "")
	some v in _tainted(lines, i)
	regex.match(_ident_re(v), e)
}

# The call's argument text: the rest of the line, and up to 4 more lines
# while the parenthesis stays open.
_args(lines, i, rest) := rest if not _open_paren(rest)

_args(lines, i, rest) := concat(" ", array.concat([rest], [_strip_comment(l) | some l in array.slice(lines, i + 1, i + 5)])) if _open_paren(rest)

_open_paren(rest) if count(regex.find_all_string_submatch_n(`\(`, rest, -1)) > count(regex.find_all_string_submatch_n(`\)`, rest, -1))

_open_paren(rest) if regex.match(`[(,]\s*$`, rest)

# The call opened its parenthesis at the end of the line.
_open_paren(rest) if regex.match(`^\s*$`, rest)

# Drop array literals (argument lists) and a leading env hash or env variable.
_shell_args(args) := regex.replace(
	regex.replace(regex.replace(args, `\[[^\[\]]*\]`, "[]"), `\[[^\[\]]*\]`, "[]"),
	`^\s*(?:\{[^{}]*\}|[a-z_]*env\w*|ENV(?:\.to_h)?)\s*,\s*`,
	"",
)

# A double-quoted string or %Q literal that interpolates input.
_shell_string(lines, i, args) if {
	some m in regex.find_all_string_submatch_n(`"((?:[^"\\]|\\.)*)"|%Q?\{([^}]*)\}`, args, -1)
	body := concat("", [m[1], m[2]])
	some it in regex.find_all_string_submatch_n(`#\{([^}]*)\}`, body, -1)
	not _sanitised(it[1])
	_is_input(lines, i, it[1])
}

# "cmd " + input, "cmd " << input, "cmd %s" % input, format("cmd %s", input).
_shell_string(lines, i, args) if {
	some m in regex.find_all_string_submatch_n(`(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*(?:\+|<<|%)\s*([^,)]+)`, args, -1)
	not _sanitised(m[1])
	_is_input(lines, i, m[1])
}

_shell_string(lines, i, args) if {
	some m in regex.find_all_string_submatch_n(`\b(?:format|sprintf)\s*\(\s*(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*,\s*([^)]+)`, args, -1)
	not _sanitised(m[1])
	_is_input(lines, i, m[1])
}

# The command is the input itself: Open3.capture2(params[:cmd]) or (cmd).
_shell_string(lines, i, args) if {
	m := regex.find_all_string_submatch_n(`^\s*(params\s*(?:\[[^\]]*\]\s*)*|request\.\w+(?:\[[^\]]*\])?|@{0,2}[a-z_]\w*)\s*(?:[,)]|\bdo\b|\{|$)`, args, 1)
	count(m) > 0
	not regex.match(`^\s*(?:do|nil|true|false|self)\s*$`, m[0][1])
	not _sanitised(m[0][1])
	_is_input(lines, i, m[0][1])
}

# Pipeline commands after the first are shell strings too.
_shell_string(lines, i, args) if {
	some m in regex.find_all_string_submatch_n(`,\s*(params\s*\[[^\]]*\]|@{0,2}[a-z_]\w*)\s*(?:[,)]|$)`, args, -1)
	not _sanitised(m[1])
	_is_input(lines, i, m[1])
}

_outside_string(line, tok) if {
	prefix := substring(line, 0, indexof(line, tok))
	stripped := regex.replace(prefix, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, "")
	not contains(stripped, `"`)
	not contains(stripped, "'")
}

_calls(content, code) := [[m[0], m[1]] | some m in regex.find_all_string_submatch_n(_call_re, code, -1)]

_receiverless(content, code) := [[m[0], m[1]] |
	regex.match(`(?m)^\s*(?:include|extend)\s+Open3\b`, content)
	some m in regex.find_all_string_submatch_n(_bare_call_re, code, -1)
]

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rb")
	contains(content, "Open3")
	regex.match(_src_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`pipeline|popen|capture`, line)
	not helpers.is_comment_line(line)
	code := _strip_comment(line)
	some c in array.concat(_calls(content, code), _receiverless(content, code))
	_outside_string(code, c[0])
	rest := substring(code, indexof(code, c[0]) + count(c[0]), -1)
	args := _shell_args(_args(lines, i, rest))
	_pipeline_or_first(c[1], args)
	_shell_string(lines, i, _first_only(c[1], args))
	finding := {
		"rule_id": metadata.id,
		"message": "Request input reaches an Open3 shell-string command; pass each command as an argument array (Open3.capture2(\"cmd\", arg) or pipeline([\"cmd\", arg])) so no shell parses it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A splatted argument list is never a shell string.
_pipeline_or_first(_, args) if not regex.match(`^\s*\*`, args)

# For non-pipeline methods only the first argument is a command; later
# arguments are argv entries passed without a shell.
_first_only(method, args) := args if startswith(method, "pipeline")

_first_only(method, args) := first if {
	not startswith(method, "pipeline")
	not regex.match(_sh_c_re, args)
	first := _first_arg(args)
}

# The argument-list form that starts a shell anyway: capture2("sh", "-c", cmd)
# makes the third argument the shell string.
_sh_c_re := `^\s*\(?\s*["'](?:/usr)?(?:/bin/)?(?:ba|z|da|k)?sh["']\s*,\s*["']-[a-z]*c["']\s*,`

_first_only(method, args) := rest if {
	not startswith(method, "pipeline")
	regex.match(_sh_c_re, args)
	rest := regex.replace(args, _sh_c_re, "")
}

# The first argument: a quoted string (with any + / % continuation) or the
# text up to the first comma outside a string.
_first_arg(args) := m[0][0] if {
	m := regex.find_all_string_submatch_n(`^\s*(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')(?:\s*(?:\+|<<|%)\s*[^,)]+)*`, args, 1)
	count(m) > 0
}

_first_arg(args) := m[0][0] if {
	not regex.match(`^\s*["']`, args)
	m := regex.find_all_string_submatch_n(`^\s*(?:\w+\s*\((?:[^()]|\([^()]*\))*\)|[^,]*)`, args, 1)
	count(m) > 0
}
