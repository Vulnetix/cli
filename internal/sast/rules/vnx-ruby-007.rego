package vulnetix.rules.vnx_ruby_007

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUBY-007",
	"name": "YAML.load() insecure deserialization",
	"description": "Untrusted YAML reaches a Psych loader that can instantiate arbitrary Ruby objects: YAML.load or Psych.load (unsafe before Psych 4 / Ruby 3.1), YAML.unsafe_load, YAML.load_stream and YAML.load_documents on a string, or YAML.load_file / YAML.unsafe_load_file on a path. Untrusted means request input (params, request.params/body/raw_post/headers/cookies, cookies, Rack env request keys, an upload), a Base64-decoded blob or an HTTP or message body (.body), used in the call or through a variable assigned from it (up to two assignments) in the 12 lines above. Not reported: YAML.safe_load and Psych.safe_load, a load given permitted_classes: or safe: true, YAML read from the application's own files (YAML.load_file(\"config/settings.yml\"), YAML.load(File.read(path)) with a local path), comments and strings. Marshal, Oj and JSON.load are VNX-RUBY-003.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-007/",
	"languages": ["ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["deserialization", "yaml", "rce", "ruby"],
}

_src_re := `\bparams\b\s*(?:[\[\.\),]|$)|\brequest\.(?:params|query_parameters|request_parameters|body|raw_post|query_string|headers|env|cookies|POST|GET)\b|\bcookies\s*[\[\.]|\benv\[\s*["'](?:QUERY_STRING|HTTP_\w+|rack\.input)|\breq\.(?:params|body|cookies)\b|\.original_filename\b|\.tempfile\b|\bBase64\.(?:decode64|strict_decode64|urlsafe_decode64)\b|\.unpack1?\(\s*["']m|\.body\b`

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

_untrusted(_, _, args) if regex.match(_src_re, args)

_untrusted(lines, i, args) if {
	some v in _tainted(lines, i)
	regex.match(_ident_re(v), args)
}

_sink_re := `\b((?:YAML|Psych)\.(?:load|unsafe_load|load_stream|load_documents|load_file|unsafe_load_file)\b(.*))$`

# Psych 4 load accepts the safe_load keywords; SafeYAML adds safe: true.
_restricted(call) if regex.match(`permitted_classes:|:permitted_classes\s*=>|\bsafe:\s*true|:safe\s*=>\s*true`, call)

_outside_string(line, tok) if {
	prefix := substring(line, 0, indexof(line, tok))
	stripped := regex.replace(prefix, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, "")
	not contains(stripped, `"`)
	not contains(stripped, "'")
}

_full_args(_, _, args) := args if not regex.match(`^\s*\(\s*$`, args)

_full_args(lines, i, args) := lines[j] if {
	regex.match(`^\s*\(\s*$`, args)
	j := helpers.next_code_index(lines, i, 2)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rb")
	regex.match(`\b(?:YAML|Psych)\.(?:load|unsafe_load)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\b(?:YAML|Psych)\.(?:load|unsafe_load)`, line)
	not helpers.is_comment_line(line)
	code := regex.replace(line, `\s#[^{].*$`, "")
	some m in regex.find_all_string_submatch_n(_sink_re, code, 1)
	call := m[1]
	not _restricted(call)
	_outside_string(code, call)
	_untrusted(lines, i, _full_args(lines, i, m[2]))
	finding := {
		"rule_id": metadata.id,
		"message": "YAML.load/unsafe_load on untrusted input can instantiate arbitrary Ruby objects and lead to remote code execution; use YAML.safe_load (with an explicit permitted_classes list if needed)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
