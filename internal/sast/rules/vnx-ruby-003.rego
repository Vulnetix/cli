package vulnetix.rules.vnx_ruby_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUBY-003",
	"name": "Insecure deserialization in Ruby",
	"description": "Untrusted bytes reach a Ruby deserializer that instantiates arbitrary classes: Marshal.load/Marshal.restore, Oj.load in its default object mode (no mode: :strict/:compat/:json/:null/:rails/:wab) or Oj.object_load, JSON.load, and JSON.parse with create_additions: true. Untrusted means request input (params, request.params/body/raw_post/headers/cookies, cookies, Rack env request keys), a Base64-decoded blob, an HTTP or message body (.body) or a socket read (a read on a *sock* variable or on a connection assigned from accept, or recv/recvfrom/recv_nonblock/recvmsg on any receiver), used in the call or through a variable assigned from it (up to two assignments) in the 12 lines above. Not reported: data the process wrote itself or read from a local file (Marshal.load(File.binread(path)), the Marshal.load(Marshal.dump(obj)) deep copy, even of params), Oj with a non-object mode, JSON.parse without create_additions, comments and strings. YAML.load and its relatives are VNX-RUBY-007.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-003/",
	"languages": ["ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["deserialization", "marshal", "dangerous-function"],
}

# Data from outside the process: request input, a decoded transport blob, a
# message or response body, a socket.
_src_re := `\bparams\b\s*(?:[\[\.\),]|$)|\brequest\.(?:params|query_parameters|request_parameters|body|raw_post|query_string|headers|env|cookies|POST|GET)\b|\bcookies\s*[\[\.]|\benv\[\s*["'](?:QUERY_STRING|HTTP_\w+|rack\.input)|\breq\.(?:params|body|cookies)\b|\bBase64\.(?:decode64|strict_decode64|urlsafe_decode64)\b|\.unpack1?\(\s*["']m|\.body\b|\b\w*sock(?:et)?\w*\.(?:read|recv|gets|readpartial)\b|\.(?:recv|recvfrom|recv_nonblock|recvmsg)\s*\(|=\s*\w+\.accept\b`

_assign_re := `^\s*(@{0,2}[A-Za-z_]\w*)\s*(?:\|\|)?=\s*[^=~>]`

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	v := m[0][1]
}

_ident_re(v) := concat("", [`(?:^|[^\w@])`, v, `\b`])

_tainted(lines, i) := t1 | t2 if {
	i > 0
	lo := max([0, i - 12])
	t1 := {v |
		some j in numbers.range(lo, i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		regex.match(_src_re, l)
		not regex.match(_serialised_here_re, l)
		v := _assigned(l)
	}
	t2 := {w |
		some k in numbers.range(lo, i - 1)
		l := lines[k]
		not helpers.is_comment_line(l)
		w := _assigned(l)
		some v in t1
		v != w
		regex.match(_ident_re(v), regex.replace(l, `^\s*@{0,2}\w+\s*(?:\|\|)?=`, ""))
	}
}

_tainted(_, 0) := set()

# A value the process serialised itself (a round trip) is not foreign data,
# even when what it serialised came from the request.
_serialised_here_re := `\b(?:Marshal|Oj|JSON)\.(?:dump|generate)\b|\.to_json\b`

# The deep-copy idiom: the argument is the process's own dump of an object.
_round_trip(args) if regex.match(`^\s*\(?\s*(?:Marshal|Oj|JSON)\.(?:dump|generate)\s*\(`, args)

_untrusted(_, _, args) if {
	not _round_trip(args)
	regex.match(_src_re, args)
}

_untrusted(lines, i, args) if {
	not _round_trip(args)
	some v in _tainted(lines, i)
	regex.match(_ident_re(v), args)
}

# Each deserializer with the text from its name onward.
_sink_re := `\b((?:Marshal\.(?:load|restore)|Oj\.(?:load|object_load)|JSON\.(?:load|parse))\b(.*))$`

_kind(call) := "marshal" if startswith(call, "Marshal.")

_kind(call) := "oj" if startswith(call, "Oj.load")

_kind(call) := "oj" if startswith(call, "Oj.object_load")

_kind(call) := "json" if startswith(call, "JSON.")

# Oj's object mode is the default; any other explicit mode builds plain data.
_dangerous(call) if startswith(call, "Marshal.")

_dangerous(call) if startswith(call, "Oj.object_load")

_dangerous(call) if {
	startswith(call, "Oj.load")
	not regex.match(`mode:\s*:(?:strict|compat|json|null|rails|wab|custom)\b|:mode\s*=>\s*:(?:strict|compat|json|null|rails|wab|custom)\b`, call)
}

_dangerous(call) if startswith(call, "JSON.load")

_dangerous(call) if {
	startswith(call, "JSON.parse")
	regex.match(`create_additions:\s*true|:create_additions\s*=>\s*true`, call)
}

_outside_string(line, tok) if {
	prefix := substring(line, 0, indexof(line, tok))
	stripped := regex.replace(prefix, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, "")
	not contains(stripped, `"`)
	not contains(stripped, "'")
}

# A call broken right after its opening parenthesis takes its argument from
# the next code line.
_full_args(_, _, args) := args if not regex.match(`^\s*\(\s*$`, args)

_full_args(lines, i, args) := lines[j] if {
	regex.match(`^\s*\(\s*$`, args)
	j := helpers.next_code_index(lines, i, 2)
}

_message("marshal") := "Marshal.load/restore on untrusted data instantiates arbitrary objects and leads to remote code execution; exchange JSON (JSON.parse) instead, or sign and verify the payload before loading"

_message("oj") := "Oj.load in object mode on untrusted data instantiates arbitrary classes; pass mode: :strict (or :compat) or use JSON.parse"

_message("json") := "JSON.load (or JSON.parse with create_additions: true) on untrusted data can instantiate arbitrary classes via json_create; use JSON.parse without create_additions"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rb")
	regex.match(`\b(?:Marshal\.(?:load|restore)|Oj\.(?:load|object_load)|JSON\.load)\b|create_additions`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\b(?:Marshal|Oj|JSON)\.`, line)
	not helpers.is_comment_line(line)
	code := regex.replace(line, `\s#[^{].*$`, "")
	some m in regex.find_all_string_submatch_n(_sink_re, code, 1)
	call := m[1]
	_dangerous(call)
	_outside_string(code, call)
	_untrusted(lines, i, _full_args(lines, i, m[2]))
	finding := {
		"rule_id": metadata.id,
		"message": _message(_kind(call)),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
