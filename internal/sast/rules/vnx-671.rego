# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_671

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-671",
	"name": "Application overrides an operator-controlled security switch in the environment",
	"description": "Production Python or Node.js code unconditionally writes a process-wide security switch into its own environment, taking a decision that belongs to whoever deploys it and making it impossible to turn back on without changing code: OAUTHLIB_INSECURE_TRANSPORT / AUTHLIB_INSECURE_TRANSPORT set to a true value (OAuth over plain HTTP), GIT_SSL_NO_VERIFY set to a true value, PYTHONHTTPSVERIFY or NODE_TLS_REJECT_UNAUTHORIZED set to 0, and CURL_CA_BUNDLE / REQUESTS_CA_BUNDLE set to an empty string (requests then skips certificate verification). Recognised writes: os.environ[...] = / environ[...] =, os.putenv(...), os.environ.update({...}) and os.environ.update(NAME=...), process.env.NAME = and process.env['NAME'] =. Only a literal value is reported. Not reported: a value read from another environment variable, a config object or a ternary (the operator still decides), a write inside an if/elif/else block or on a one-line if (a debug or development switch the operator controls), os.environ.setdefault (the operator's value still wins), safe values (1, a CA bundle path, 0 for the insecure-transport flags), reading or removing the variable, test files, comments and string literals. The NODE_TLS_REJECT_UNAUTHORIZED case is also reported by VNX-CRYPTO-005; shell and Dockerfile settings of these variables belong to VNX-SEC-016.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-671/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [671],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["lack-of-administrator-control-over-security", "cwe-671", "configuration"],
}

_names := `OAUTHLIB_INSECURE_TRANSPORT|AUTHLIB_INSECURE_TRANSPORT|GIT_SSL_NO_VERIFY|PYTHONHTTPSVERIFY|NODE_TLS_REJECT_UNAUTHORIZED|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE`

_gate := concat("", [`(?m)^\s*(?:os\.environ|environ|os\.putenv|process\.env)\b.*\b(?:`, _names, `)\b`])

_write_res := [
	concat("", [`^\s*(?:os\.)?environ\s*\[\s*['"](`, _names, `)['"]\s*\]\s*=\s*([^=].*)$`]),
	concat("", [`^\s*process\.env\.(`, _names, `)\s*=\s*([^=].*)$`]),
	concat("", [`^\s*process\.env\s*\[\s*['"](`, _names, `)['"]\s*\]\s*=\s*([^=].*)$`]),
	concat("", [`^\s*os\.putenv\(\s*['"](`, _names, `)['"]\s*,\s*([^)]*)\)`]),
	concat("", [`^\s*(?:os\.)?environ\.update\(.*['"](`, _names, `)['"]\s*:\s*([^,}]*)`]),
	concat("", [`^\s*(?:os\.)?environ\.update\((?:.*[(,])?\s*(`, _names, `)\s*=\s*([^,)]*)`]),
]

# Only a literal value is a decision taken in code; a value read from the
# environment, a config object or a ternary is still the operator's.
_literal(raw) if regex.match(concat("", [`^\s*(?:'[^']*'|"[^"]*"|`, "`[^`$]*`", `|\d+|True|true|False|false)\s*;?\s*$`]), raw)

_value(raw) := lower(trim(trim_space(trim_right(trim_space(raw), ";")), "\"'`"))

_insecure(name, v) if {
	name in {"OAUTHLIB_INSECURE_TRANSPORT", "AUTHLIB_INSECURE_TRANSPORT", "GIT_SSL_NO_VERIFY"}
	v != ""
	not v in {"0", "false", "no", "off", "none", "null", "undefined"}
}

_insecure(name, v) if {
	name in {"PYTHONHTTPSVERIFY", "NODE_TLS_REJECT_UNAUTHORIZED"}
	v in {"0", "false"}
}

_insecure(name, v) if {
	name in {"CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE"}
	v == ""
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The nearest enclosing (shallower) code line above is a conditional.
_conditional(lines, i) if {
	ind := _indent(lines[i])
	ind > 0
	above := [j |
		some j in numbers.range(max([0, i - 30]), i - 1)
		trim_space(lines[j]) != ""
		not helpers.is_comment_line(lines[j])
		_indent(lines[j]) < ind
	]
	count(above) > 0
	regex.match(`^\s*(?:\}\s*)?(?:if\b|elif\b|else\b|else\s+if\b)`, lines[max(above)])
}

findings contains finding if {
	some path, content in input.file_contents
	_lang_file(path)
	regex.match(_gate, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	some re in _write_res
	m := regex.find_all_string_submatch_n(re, line, 1)
	name := m[0][1]
	_literal(m[0][2])
	_insecure(name, _value(m[0][2]))
	not _conditional(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s is forced to an insecure value in code, overriding what the operator configured for the process; leave it to the deployment environment", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_lang_file(path) if endswith(path, ".py")

_lang_file(path) if {
	some ext in [".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"]
	endswith(path, ext)
}
