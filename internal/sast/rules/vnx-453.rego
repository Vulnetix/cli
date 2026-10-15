# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_453

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-453",
	"name": "Insecure default: a security parameter defaults to its unsafe value",
	"description": "Reports a Python or JavaScript/TypeScript function signature whose security-relevant parameter defaults to the weaker setting, so every caller that does not pass it gets the insecure behaviour: certificate or signature verification off by default (verify, verify_ssl, ssl_verify, check_hostname, validate_certs, verify_signature, rejectUnauthorized, strictSSL = False/false), cookie protection off (secure, httponly/httpOnly = False), template autoescape or CSRF protection off, authentication not required (require_auth, login_required = False), or an unsafe switch on (insecure, insecure_skip_verify, skip_verify, no_verify, skip_auth, allow_unsafe, allow_pickle, shell, debug = True/true). Python defs (single or multi-line signatures, with type annotations) and JS function declarations, arrow functions, methods, constructors and destructured option defaults are covered. Not reported: a call that passes the weak value explicitly (requests.get(url, verify=False) is a call-site concern for other rules), object literals ({ rejectUnauthorized: false }), ordinary variable assignments, safe defaults (verify=True, insecure=False), transport choices such as ssl=False or use_tls=False whose right value depends on the deployment, mutable default arguments (a correctness bug, not an insecure security default), comments, strings, docstrings and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-453/",
	"languages": ["python", "node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [453],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["insecure-default", "configuration", "cwe-453"],
}

# Parameters whose safe value is true: a false default is the weak one.
_off_names := `verify(?:_?(?:ssl|tls|certs?|certificates?|signatures?|host(?:name)?))?|(?:ssl|tls)_?verify|check_?hostname|validate_?certs?|secure|http_?only|auto_?escape|csrf(?:_?(?:protect(?:ion)?|enabled|check))?|check_?signature|require_?auth|auth_?required|login_?required|strict_?ssl|reject_?unauthorized`

# Parameters whose safe value is false: a true default is the weak one.
_on_names := `insecure(?:_?skip_?verify)?|skip_?(?:verify|tls_?verify|ssl_?verify|auth|csrf)|no_?verify|disable_?(?:ssl|tls|cert)_?verif\w*|disable_?(?:auth|csrf)|allow_?(?:insecure|unsafe|pickle)\w*|shell|debug|unsafe|csrf_?exempt`

_param(names, value) := concat("", [
	`(?i:(?:^|[(,{])\s*(`, names, `))\s*(?::\s*[\w\[\]. |]+?)?\s*=\s*`, value,
	`\s*(?:[,)}]|$)`,
])

_py_weak := concat("|", [_param(_off_names, "False"), _param(_on_names, "True")])

_js_weak := concat("|", [_param(_off_names, "false"), _param(_on_names, "true")])

_py_def := `^\s*(?:async\s+)?def\s+\w+\s*\(`

_py_sig_closed := `\)\s*(?:->[^:]*)?:\s*(?:#.*)?$`

# The line is part of a def signature: the def line itself, or a line after a
# def opener whose signature has not closed yet.
_in_py_sig(lines, i) if regex.match(_py_def, lines[i])

_in_py_sig(lines, i) if {
	not regex.match(_py_def, lines[i])
	some d in numbers.range(max([0, i - 10]), i - 1)
	regex.match(_py_def, lines[d])
	not _closed_between(lines, d, i)
}

_closed_between(lines, d, i) if {
	some j in numbers.range(d, i - 1)
	regex.match(_py_sig_closed, lines[j])
}

_closed_between(lines, d, i) if {
	some j in numbers.range(d + 1, i - 1)
	regex.match(_py_def, lines[j])
}

# Inside a Python docstring: an odd number of triple quotes above the line.
_in_docstring(lines, i) if {
	above := concat("\n", array.slice(lines, 0, i))
	count(regex.find_n(`"""|'''`, above, -1)) % 2 == 1
}

_in_string(line, re) if {
	prefix := regex.replace(line, concat("", ["(?:", re, ").*$"]), "")
	some q in [`"`, `'`, "`"]
	count(regex.find_n(q, prefix, -1)) % 2 == 1
}

# A JS function signature on one line.
_js_sig_line(line) if regex.match(`\bfunction\b[\s\w$*]*\(`, line)

_js_sig_line(line) if regex.match(`\)\s*(?::\s*[^=]+)?=>`, line)

_js_sig_line(line) if regex.match(`^\s*(?:(?:public|private|protected|static|async|override|readonly)\s+)*(?:constructor|[A-Za-z_$][\w$]*)\s*\(.*\)\s*(?::\s*[^{]+)?\{\s*$`, line)

# A parameter line of a signature opened above: `function f(` / `name(` / `= (`
# within eight lines, and the line itself is only `name = value,`.
_js_param_line(lines, i) if {
	_js_param_shape(lines[i])
	some d in numbers.range(max([0, i - 8]), i - 1)
	regex.match(`(?:\bfunction\b[\s\w$*]*|^\s*(?:(?:export|default|public|private|protected|static|async)\s+)*(?:constructor|[A-Za-z_$][\w$]*)|=\s*(?:async\s*)?)\(\s*\{?\s*$`, lines[d])
	not _js_closed_between(lines, d, i)
}

_js_param_shape(line) if regex.match(`^\s*\{?\s*[A-Za-z_$][\w$]*\s*(?::\s*[\w\[\]. |]+?)?\s*=\s*(?:true|false)\s*,?\s*\}?\s*,?\s*$`, line)

# A whole destructured options parameter on its own line, optionally typed and
# defaulted: `{ httpOnly = false, secure = true }: Opts = {},`.
_js_param_shape(line) if regex.match(`^\s*\{[^{}]*=\s*(?:true|false)[^{}]*\}\s*(?::\s*(?:\{[^{}]*\}|[\w$.<>\[\] |]+))?\s*(?:=\s*\{\s*\})?\s*,?\s*$`, line)

_js_closed_between(lines, d, i) if {
	some j in numbers.range(d + 1, i - 1)
	regex.match(`^\s*\)|\)\s*(?::[^{]*)?(?:=>)?\s*\{\s*$`, lines[j])
}

_message := "A security parameter defaults to its weaker value, so every caller that omits it gets the insecure behaviour. Make the safe value the default and let callers opt out explicitly"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(concat("", ["(?m)", _py_weak]), content)
	regex.match(`(?m)^\s*(?:async\s+)?def\s`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_py_weak, line)
	not helpers.is_comment_line(line)
	not _in_string(line, _py_weak)
	_in_py_sig(lines, i)
	not _in_docstring(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`\.(?:js|mjs|cjs|jsx|ts|tsx)$`, path)
	not helpers.is_test_path(path)
	regex.match(concat("", ["(?m)", _js_weak]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_js_weak, line)
	not helpers.is_comment_line(line)
	not _in_string(line, _js_weak)
	_js_sig(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_js_sig(_, _, line) if _js_sig_line(line)

_js_sig(lines, i, line) if {
	not _js_sig_line(line)
	_js_param_line(lines, i)
}
