package vulnetix.rules.vnx_ruby_009

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUBY-009",
	"name": "Ruby dynamic method dispatch via send with user-controlled method name",
	"description": "Reports a Ruby send, public_send or __send__ call (with or without a receiver, with or without parentheses) and a receiver's try/try! call whose FIRST argument, the method name, comes from request input: params, request.params/query_parameters/request_parameters/headers or cookies, directly, inside an interpolated or concatenated string, with .to_sym, or through a variable assigned from such input within the 15 lines above, including one further hop (kind = job_params[:kind] after job_params = params.require(:job).permit(:kind)), in .rb, .rake and .ru files. The caller can then invoke any method on the receiver (destroy, delete_all, instance_variable_set, system on Kernel). Not reported: a symbol or plain string method name with user input only in later arguments, an allowlist check on the name (include?/member?/key?/in?/presence_in, or an equality test) in the lines above or on the same line, a name looked up from a constant table (HANDLERS.fetch(params[:x])), send_file/send_data, Socket#send, method definitions, comments and string literals. respond_to? is not treated as a guard, because every dangerous method responds. Flows through instance variables, helper methods or other files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-009/",
	"languages": ["ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [94, 470],
	"capec": ["CAPEC-153"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["reflection", "send", "code-injection", "ruby"],
}

# Request input in Rails, Sinatra and Rack.
_source_re := `\bparams\s*[\[.]|\brequest\.(?:params|query_parameters|request_parameters|GET|POST|headers|cookies)\b|\bcookies\s*\[`

# A dispatch call and its first argument. Receiver form: `.send(`, `&.send `,
# `.try(`; bare form (self dispatch): `send(`, `public_send x`.
_recv_re := `\.(?:send|public_send|__send__|try!?)(?:\(\s*|\s+)([^,]*)`

_bare_re := `(?:^|[\s(=!;{|&])(?:send|public_send|__send__)(?:\(\s*|\s+)([^,]*)`

# Empties string literals that carry no interpolation, so a sink spelled out in
# a message or log line is not code.
_strip(line) := regex.replace(line, `'[^']*'|"[^"#]*"`, `""`)

_args(code) := _trim_arg(a) if {
	m := regex.find_all_string_submatch_n(_recv_re, code, 1)
	count(m) > 0
	a := m[0][1]
}

_args(code) := _trim_arg(a) if {
	not regex.match(_recv_re, code)
	m := regex.find_all_string_submatch_n(_bare_re, code, 1)
	count(m) > 0
	a := m[0][1]
}

# The first argument ends before a block (`{ ... }`, `do`) or a trailing
# modifier (`if`, `unless`): `send(verb) { params[:a] }` dispatches `verb`.
_trim_arg(a) := regex.replace(a, `(?:(?:^|[^#])\{|\s(?:do|if|unless|rescue|and|or)\b).*$`, "")

# The receiver is a socket: Socket#send(mesg, flags) sends data, not a method.
_socket_send(code) if regex.match(`(?i)\b\w*sock(?:et)?\w*\s*\.\s*send\b`, code)

# `def send(msg)` / `alias send ...` declares, it does not dispatch.
_declares(code) if regex.match(`^\s*(?:def|alias|alias_method)\s`, code)

# The name is looked up in a constant table, or is itself a symbol literal.
_mapped(arg) if regex.match(`^\s*\(?\s*[A-Z][A-Za-z0-9_:]*\s*(?:\[|\.fetch\b|\.dig\b)`, arg)

# The first argument: on the call line, or on the next code line when the call
# breaks right after its opening parenthesis.
_first_arg(lines, i, code) := a if {
	a := _args(code)
	trim_space(a) != ""
}

_first_arg(lines, i, code) := a if {
	trim_space(_args(code)) == ""
	j := helpers.next_code_index(lines, i, 2)
	a := split(_strip(lines[j]), ",")[0]
}

_guard_kw := `(?:include\?|member\?|key\?|has_key\?|cover\?)`

# An allowlist check on request input in the lines above or on the call line.
_direct_guarded(lines, i) if {
	w := helpers.code_window(lines, i, 8, 0)
	regex.match(concat("", [_guard_kw, `\s*\(?\s*(?:params|request\.|cookies)`]), w)
}

_direct_guarded(lines, i) if {
	w := helpers.code_window(lines, i, 8, 0)
	regex.match(`(?:params|cookies)\s*\[[^\]]+\]\s*(?:\.(?:in\?|presence_in)\b|==|!=)`, w)
}

_var_guarded(lines, i, v) if {
	w := helpers.code_window(lines, i, 15, 0)
	regex.match(concat("", [_guard_kw, `\s*\(?\s*:?`, v, `\b`]), w)
}

_var_guarded(lines, i, v) if {
	w := helpers.code_window(lines, i, 15, 0)
	regex.match(concat("", [`\b`, v, `\s*(?:\.(?:in\?|presence_in)\b|==\s*['":]|!=\s*['":])`]), w)
}

# Variables assigned from request input, excluding constant-table lookups.
_tainted(lines, i) := {v |
	some v in helpers.tainted_names(lines, i, 15, _source_re)
	some j in numbers.range(max([0, i - 15]), i - 1)
	regex.match(_source_re, lines[j])
	helpers.assigned_first(lines[j]) == v
	not regex.match(`=\s*[A-Z][A-Za-z0-9_:]*\s*(?:\[|\.fetch\b|\.dig\b)`, lines[j])
}

_reportable(lines, i, arg) if {
	regex.match(_source_re, arg)
	not _mapped(arg)
	not _direct_guarded(lines, i)
}

# One more hop: a name assigned from a tainted variable, as in the Strong
# Parameters idiom `job = params.require(:job).permit(:kind)` then
# `kind = job[:kind]`.
_tainted2(lines, i) := {w |
	t := _tainted(lines, i)
	count(t) > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	w := helpers.assigned_first(lines[j])
	not w in t
	rhs := regex.replace(lines[j], `^[^=]*=`, "")
	some v in t
	regex.match(concat("", [`(?:^|[^\w:@.])`, v, `\b`]), rhs)
	not regex.match(`=\s*[A-Z][A-Za-z0-9_:]*\s*(?:\[|\.fetch\b|\.dig\b)`, lines[j])
}

_names(lines, i) := _tainted(lines, i) | _tainted2(lines, i)

# Ruby source: .rb, Rake tasks, Rack config and Rakefile.
_ruby_path(path) if regex.match(`(?:\.(?:rb|rake|ru)|(?:^|/)Rakefile)$`, path)

_reportable(lines, i, arg) if {
	not regex.match(_source_re, arg)
	not _mapped(arg)
	not regex.match(`^\s*:`, arg)
	some v in _names(lines, i)
	regex.match(concat("", [`(?:^|[^\w:@.])`, v, `\b`]), arg)
	not _var_guarded(lines, i, v)
}

findings contains finding if {
	some path, content in input.file_contents
	_ruby_path(path)
	regex.match(`(?:send|__send__)\b|\.try!?[\s(]`, content)
	regex.match(`\b(?:params|request|cookies)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:send|__send__)\b|\.try!?[\s(]`, line)
	not helpers.is_comment_line(line)
	code := _strip(line)
	regex.match(`(?:send|public_send|__send__|\.try!?)(?:\(|\s)`, code)
	not _declares(code)
	not _socket_send(code)
	arg := _first_arg(lines, i, code)
	_reportable(lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "Dynamic method dispatch (send/public_send/__send__/try) with a method name taken from request input; map the input to an explicit allowlist of method names before dispatching",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
