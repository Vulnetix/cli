# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_447

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-447",
	"name": "Unimplemented or Unsupported Feature in UI",
	"description": "Reports Java features that are offered to the user but do nothing: a security operation (a set/enable/disable/change/reset/revoke/verify method whose name names a password, MFA/2FA/OTP, encryption, SSL/TLS, audit, lockout, CAPTCHA, CSRF, session, permission, role, token, credential, signature or certificate) whose body is empty, only comments, or only 'return true' / 'return', so the UI reports a protection as on while nothing changed; and a request handler (Spring @*Mapping, JAX-RS @GET/@POST/..., servlet doGet/doPost/...) whose whole body is a throw of UnsupportedOperationException or NotImplementedException, an exposed endpoint for a feature that does not exist. Not reported: UnsupportedOperationException in ordinary methods (read-only collections, iterators, immutable setters fail loudly, which is correct), a throw inside a branch of an implemented handler, empty non-security methods (listeners, callbacks), dependency setters whose name only contains a security word (setSessionFactory, setTokenizer, setPasswordEncoder), comments, string literals and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-447/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [447],
	"capec": [],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["unimplemented-function", "cwe-447"],
}

_decl_re := `^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|synchronized|default)\s+)*(?:<[^>]+>\s+)?[\w.\[\]?]+(?:<[\w.<>\[\],?\s]*>)?(?:\s*\[\s*\])*\s+(\w+)\s*\(`

_security_name := `(?i)^(?:set|enable|disable|toggle|configure|change|reset|update|revoke|invalidate|lock|unlock|apply|verify|validate|check|enforce|require)\w*(?:password|passwd|mfa|2fa|twofactor|otp|encrypt|ssl|tls|audit|lockout|captcha|csrf|session|permission|role|security|privacy|consent|token|credential|signature|certificate)\w*$`

# A security word inside the name of an infrastructure object: setSessionFactory,
# setTokenizer, setRoleRepository are dependency setters, not security switches.
_lookalike := `(?i)(?:session|token|role|certificate|credential|permission|password|audit)(?:factory|izer|ize|encoder|manager|repository|repo|dao|store|service|provider|listener|holder|bean|registry)`

_handler_ann := `@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b|@(?:GET|POST|PUT|DELETE|PATCH)\b`

_not_decl := {"return", "new", "else", "throw", "if", "while", "for", "switch", "catch", "synchronized"}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_strip(l) := trim_space(regex.replace(l, `//.*$`, ""))

# The line holding the method's opening brace: the declaration line or one of
# the next three (wrapped parameters or a throws clause), with no ';' before it
# (an abstract or interface declaration, or a call).
_open(lines, i) := o if {
	cands := [k |
		some k in numbers.range(i, min([count(lines) - 1, i + 3]))
		contains(lines[k], "{")
	]
	count(cands) > 0
	o := cands[0]
	not _semicolon_before(lines, i, o)
}

_semicolon_before(lines, i, o) if {
	some k in numbers.range(i, o)
	contains(regex.replace(lines[k], `\{.*$`, ""), ";")
}

# The body text, comments removed, when the method is at most six lines long.
_body(lines, i, o) := b if {
	m := regex.find_all_string_submatch_n(`\{(.*)\}\s*$`, lines[o], 1)
	count(m) > 0
	b := _strip(m[0][1])
}

_body(lines, i, o) := b if {
	not regex.match(`\{.*\}\s*$`, lines[o])
	ends := [k |
		some k in numbers.range(o + 1, min([count(lines) - 1, o + 6]))
		startswith(trim_space(lines[k]), "}")
		_indent(lines[k]) <= _indent(lines[i])
	]
	count(ends) > 0
	k := ends[0]
	after := regex.replace(lines[o], `^[^{]*\{`, "")
	inner := [_strip(l) | some j in helpers.span(o + 1, k - 1); j > o; j < k; l := lines[j]; not helpers.is_comment_line(l)]
	b := trim_space(concat(" ", array.concat([_strip(after)], inner)))
}

_silent(b) if regex.match(`^(?:return\s*(?:true|Boolean\.TRUE)?\s*;)?$`, b)

_unimplemented(b) if regex.match(`^throw\s+new\s+(?:[\w.]+\.)?(?:UnsupportedOperationException|NotImplementedException)\s*\([^;]*\)\s*;$`, b)

_handler(lines, i, _) if {
	some k in numbers.range(max([0, i - 4]), i)
	regex.match(_handler_ann, lines[k])
	not helpers.is_comment_line(lines[k])
}

_handler(_, _, name) if regex.match(`^do(?:Get|Post|Put|Delete|Patch)$`, name)

_message(true) := "A security operation is a stub that does nothing (or reports success): users who turn it on are told they are protected while nothing changed. Implement it, or remove it from the interface and the UI"

_message(false) := "A request handler exposes a feature that is not implemented and only throws: remove the endpoint (and the UI that calls it) until the feature exists"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_decl_re, line, 1)
	count(m) > 0
	name := m[0][1]
	first := regex.find_all_string_submatch_n(`^\s*(?:@\w+(?:\([^)]*\))?\s+)*(\w+)`, line, 1)[0][1]
	not first in _not_decl
	o := _open(lines, i)
	b := _body(lines, i, o)
	security := _kind(lines, i, name, b)
	finding := {
		"rule_id": metadata.id,
		"message": _message(security),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_kind(_, _, name, b) := true if {
	regex.match(_security_name, name)
	not regex.match(_lookalike, name)
	_silent(b)
}

_kind(lines, i, name, b) := false if {
	not _silent_security(name, b)
	_unimplemented(b)
	_handler(lines, i, name)
}

_silent_security(name, b) if {
	regex.match(_security_name, name)
	not regex.match(_lookalike, name)
	_silent(b)
}
