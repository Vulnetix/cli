package vulnetix.rules.vnx_py_019

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-019",
	"name": "Paramiko implicit host key trust",
	"description": "A paramiko SSH client is told to accept a server host key it does not know, in a .py file. Reported: set_missing_host_key_policy() given AutoAddPolicy or WarningPolicy (instance or class, through any module alias or from-import, with the argument on the call line or the next line), or given a variable assigned from one in the 15 lines above; a policy assigned straight to client._policy; and a missing_host_key() method (one-line or multi-line signature) whose body never raises and does not delegate to another policy's missing_host_key(), which accepts every key (pass, return, or logging and adding the key). Accepting an unknown key lets anyone on the network path impersonate the server and read the credentials and commands sent to it (CWE-322). Use RejectPolicy with load_system_host_keys()/load_host_keys(), or a policy that checks the key against a pinned fingerprint. Not reported: RejectPolicy, a missing_host_key() that raises (for example when the key does not match a pin) or delegates to RejectPolicy, imports of the policy names, isinstance checks, and the names in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-019/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [322],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["paramiko", "ssh", "mitm", "python"],
}

_code(line) := regex.replace(
	regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`),
	`#.*$`, "",
)

_lax_re := `(?:^|[^\w])(AutoAddPolicy|WarningPolicy)\b`

# The policy argument: on the call line, or the next code line when the call
# is broken after its parenthesis.
_arg(_, _, rest) := rest if trim_space(rest) != ""

_arg(lines, i, rest) := _code(lines[j]) if {
	trim_space(rest) == ""
	j := helpers.next_code_index(lines, i, 3)
}

_policy(lines, i, arg) := m[0][1] if {
	m := regex.find_all_string_submatch_n(_lax_re, arg, 1)
	count(m) > 0
}

# set_missing_host_key_policy(policy) with policy = AutoAddPolicy() above.
_policy(lines, i, arg) := m[0][1] if {
	not regex.match(_lax_re, arg)
	a := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*\)`, arg, 1)
	count(a) > 0
	v := a[0][1]
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := _code(lines[j])
	regex.match(concat("", [`^\s*`, v, `\s*=[^=]`]), prev)
	m := regex.find_all_string_submatch_n(_lax_re, prev, 1)
	count(m) > 0
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "set_missing_host_key_policy")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "set_missing_host_key_policy")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\.set_missing_host_key_policy\s*\((.*)$`, _code(line), 1)
	count(m) > 0
	arg := _arg(lines, i, m[0][1])
	p := _policy(lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("paramiko %v accepts any unknown SSH host key, allowing man-in-the-middle; use RejectPolicy with known_hosts or a fingerprint-pinning policy", [p]),
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
	contains(content, "_policy")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "_policy")
	m := regex.find_all_string_submatch_n(concat("", [`\._policy\s*=\s*.*`, _lax_re]), _code(line), 1)
	count(m) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("paramiko %v assigned as the client policy accepts any unknown SSH host key; use RejectPolicy with known_hosts", [m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A custom policy that accepts every key.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "def missing_host_key")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*def\s+missing_host_key\s*\(`, line)
	body := _def_body(lines, i, line)
	count(body) > 0
	text := concat("\n", [_code(l) | some l in body])
	# A key is accepted unless the method raises; delegating to another
	# policy's missing_host_key (RejectPolicy, a fallback) may raise.
	not regex.match(`\braise\b|missing_host_key\s*\(`, text)
	finding := {
		"rule_id": metadata.id,
		"message": "missing_host_key() accepts every unknown SSH host key, allowing man-in-the-middle; reject keys that do not match a pinned fingerprint",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# A one-line method (def missing_host_key(...): pass) is its own body.
_def_body(_, _, line) := [m[0][1]] if {
	m := regex.find_all_string_submatch_n(`\)\s*(?:->\s*[\w.\[\]]+\s*)?:\s*(\S.*)$`, _code(line), 1)
	count(m) > 0
}

_def_body(lines, i, line) := _body(lines, s, _indent(line)) if {
	not regex.match(`\)\s*(?:->\s*[\w.\[\]]+\s*)?:\s*\S`, _code(line))
	# a signature broken over lines ends at the line with `):`
	sig := [k |
		some k in numbers.range(i, min([count(lines) - 1, i + 6]))
		regex.match(`\)\s*(?:->\s*[\w.\[\]]+\s*)?:\s*$`, _code(lines[k]))
	]
	count(sig) > 0
	s := sig[0]
}

# The method body: the code lines after line s that are indented deeper than
# the def, up to the first dedent (at most 40 lines).
_body(lines, s, ind) := [lines[k] |
	some k in helpers.span(s + 1, e - 1)
	trim_space(lines[k]) != ""
	not startswith(trim_space(lines[k]), "#")
] if {
	n := count(lines)
	last := min([n - 1, s + 40])
	s + 1 <= last
	ends := [k |
		some k in numbers.range(s + 1, last)
		trim_space(lines[k]) != ""
		not startswith(trim_space(lines[k]), "#")
		_indent(lines[k]) <= ind
	]
	e := _first_or(ends, last + 1)
	e > s + 1
}

_first_or(xs, _) := xs[0] if count(xs) > 0

_first_or(xs, d) := d if count(xs) == 0
