# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_439

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-439",
	"name": "Behavioral Change in New Version or Environment",
	"description": "Python security APIs whose behaviour depends on the interpreter version the code happens to run on, so the same line is weak on one runtime and broken or different on another. Reported: hmac.new() or hmac.HMAC() without a digest (no digestmod= and fewer than three positional arguments), which silently uses MD5 before Python 3.8 and raises TypeError from 3.8; ssl.SSLContext() with no protocol, or with the deprecated generic ssl.PROTOCOL_TLS/PROTOCOL_SSLv23, whose client/server role, certificate verification and hostname checking defaults differ between versions (deprecated since 3.10; use PROTOCOL_TLS_CLIENT or ssl.create_default_context()); the module-level ssl.wrap_socket(), which performs no certificate or hostname verification by default and was removed in 3.12; ssl.match_hostname(), removed in 3.12 (3.7+ checks hostnames inside the context); and cgi.escape(), removed in 3.8 and, where it still exists, leaving quotes unescaped by default unlike html.escape(). From-imported names (from ssl import wrap_socket, from cgi import escape) are recognised. Not reported: hmac.new(key, msg, hashlib.sha256) or digestmod=, hmac.digest(), SSLContext(ssl.PROTOCOL_TLS_CLIENT/PROTOCOL_TLS_SERVER), context.wrap_socket(), html.escape(), comments and string literals. Explicitly obsolete TLS versions are VNX-PY-021; tar extraction without a filter (whose default changes in 3.14) is VNX-409.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-439/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [439],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["behavioral-change-new-version", "python-version", "cwe-439"],
}

_gate := `hmac\s*\.\s*(?:new|HMAC)|SSLContext|wrap_socket|match_hostname|escape`

# String literals blanked so an API named in a message is not a call.
_strip_strings(s) := regex.replace(s, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, `""`)

_stmt(lines, i) := concat("\n", [lines[j] | some j in numbers.range(i, min([count(lines) - 1, i + 5]))])

# ── hmac.new without a digest ────────────────────────────────────────────

_hmac_args(s) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`\bhmac\s*\.\s*(?:new|HMAC)\s*\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`, s, 1)
	count(m) > 0
}

_flat(args) := regex.replace(args, `\((?:[^()]|\([^()]*\))*\)|\[[^\]]*\]|\{[^}]*\}|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, "x")

_positional(args) := count([a | some a in split(_flat(args), ","); trim_space(a) != ""])

_reason(1, lines, i, _) := "hmac.new()/hmac.HMAC() without a digest: Python before 3.8 silently uses MD5, 3.8 and later raise TypeError. Pass digestmod explicitly (hashlib.sha256)" if {
	regex.match(`\bhmac\s*\.\s*(?:new|HMAC)\s*\(`, _strip_strings(lines[i]))
	args := _hmac_args(_strip_strings(_stmt(lines, i)))
	not contains(args, "digestmod")
	not contains(args, "**")
	_positional(args) < 3
}

# ── ssl.SSLContext with the version-dependent generic protocol ───────────

_ctx_re := `(?:\bssl\s*\.\s*|(?:^|[^\w.]))SSLContext\s*\(\s*(?:(?:protocol\s*=\s*)?(?:ssl\s*\.\s*)?PROTOCOL_(?:TLS|SSLv23)\s*,?\s*)?\)`

_reason(2, lines, i, content) := "ssl.SSLContext() with no protocol or the generic PROTOCOL_TLS/PROTOCOL_SSLv23: its role and its certificate and hostname verification defaults depend on the Python version (deprecated since 3.10). Use ssl.create_default_context() or SSLContext(ssl.PROTOCOL_TLS_CLIENT)" if {
	contains(lines[i], "SSLContext")
	regex.match(_ctx_re, _strip_strings(lines[i]))
	_ssl_name(lines[i], content, "SSLContext")
}

# ── removed or changed ssl / cgi functions ───────────────────────────────

_reason(3, lines, i, content) := "ssl.wrap_socket() verifies neither the certificate nor the hostname by default and was removed in Python 3.12. Wrap through a context: ssl.create_default_context().wrap_socket(sock, server_hostname=host)" if {
	contains(lines[i], "wrap_socket")
	regex.match(`(?:\bssl\s*\.\s*|(?:^|[^\w.]))wrap_socket\s*\(`, _strip_strings(lines[i]))
	_ssl_name(lines[i], content, "wrap_socket")
}

_reason(4, lines, i, content) := "ssl.match_hostname() was removed in Python 3.12: the check silently disappears from code that guards it with hasattr/try, and fails elsewhere. Let the context check the hostname (check_hostname=True with server_hostname=)" if {
	contains(lines[i], "match_hostname")
	regex.match(`(?:\bssl\s*\.\s*|(?:^|[^\w.]))match_hostname\s*\(`, _strip_strings(lines[i]))
	_ssl_name(lines[i], content, "match_hostname")
}

_reason(5, lines, i, content) := "cgi.escape() was removed in Python 3.8 and, where it exists, leaves quotes unescaped by default, so output placed in an attribute is not safe. Use html.escape(), which escapes quotes" if {
	contains(lines[i], "escape")
	_cgi_escape(lines[i], content)
}

_cgi_escape(line, _) if regex.match(`\bcgi\s*\.\s*escape\s*\(`, _strip_strings(line))

_cgi_escape(line, content) if {
	regex.match(`(?m)^\s*from\s+cgi\s+import\s+[^\n]*\bescape\b`, content)
	regex.match(`(?:^|[^\w.])escape\s*\(`, _strip_strings(line))
}

# The name is ssl.<name>, or a bare <name> that the file imports from ssl.
_ssl_name(line, _, name) if regex.match(concat("", [`\bssl\s*\.\s*`, name, `\s*\(`]), _strip_strings(line))

_ssl_name(line, content, name) if {
	not regex.match(concat("", [`\bssl\s*\.\s*`, name, `\s*\(`]), _strip_strings(line))
	regex.match(concat("", [`(?m)^\s*from\s+ssl\s+import\s+[^\n]*\b`, name, `\b`]), content)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	some k in [1, 2, 3, 4, 5]
	msg := _reason(k, lines, i, content)
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
