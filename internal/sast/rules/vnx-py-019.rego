package vulnetix.rules.vnx_py_019

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-019",
	"name": "Paramiko implicit host key trust",
	"description": "A paramiko SSH client is told to accept a server host key it does not know, in a .py file. Reported: set_missing_host_key_policy() given AutoAddPolicy or WarningPolicy (instance or class, through any module alias or from-import, with the argument on the call line or the next line), or given a variable assigned from one in the 15 lines above; a policy assigned straight to client._policy; and a MissingHostKeyPolicy subclass whose missing_host_key() body is only pass, return, return None/True or an ellipsis, which accepts every key. Accepting an unknown key lets anyone on the network path impersonate the server and read the credentials and commands sent to it (CWE-322). Use RejectPolicy with load_system_host_keys()/load_host_keys(), or a policy that checks the key against a pinned fingerprint. Not reported: RejectPolicy, a missing_host_key() that inspects the key or raises, imports of the policy names, isinstance checks, and the names in comments or string literals.",
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
	j := helpers.next_code_index(lines, i, 6)
	regex.match(`^\s*(?:pass|return(?:\s+(?:None|True))?|\.\.\.)\s*(?:#.*)?$`, lines[j])
	k := _after(lines, j)
	not _body_continues(line, lines, k)
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

_after(lines, j) := k if k := helpers.next_code_index(lines, j, 6)

_after(lines, j) := -1 if not helpers.next_code_index(lines, j, 6)

# The method body goes on after the bare statement (a pass before real code).
_body_continues(def_line, lines, k) if {
	k >= 0
	_indent(lines[k]) > _indent(def_line)
}
