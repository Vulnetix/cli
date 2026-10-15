# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1275

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1275",
	"name": "Sensitive Cookie with Improper SameSite Attribute",
	"description": "A cookie is configured with SameSite=None, or with the SameSite attribute switched off, so the browser attaches it to cross-site requests and a session cookie becomes usable for cross-site request forgery. Reported in JavaScript/TypeScript: a sameSite: 'none' (any case, any quote, quoted or bare key) or sameSite: false property in cookie options (res.cookie, express-session, cookie-session, cookie.serialize and similar option objects, on the call line or on its own line), an assignment such as req.session.cookie.sameSite = 'none', and a Set-Cookie header or document.cookie string containing SameSite=None. Python: SESSION_COOKIE_SAMESITE, CSRF_COOKIE_SAMESITE, LANGUAGE_COOKIE_SAMESITE or REMEMBER_COOKIE_SAMESITE set to None, False or \"None\" in any case (Django settings, Flask app.config[...] or config.update(...)), and set_cookie()/set_signed_cookie() calls with samesite=None or samesite=\"none\" (on the call line or a continuation line of it), and Starlette/FastAPI SessionMiddleware with same_site=\"none\". Not reported: Lax, Strict or true, a value computed at run time, a TypeScript type that lists 'none' among the allowed values, a set_cookie method signature whose parameter defaults to None, comparisons, the text inside comments and string literals, and test files. SameSite=None is sometimes required for a cookie used in a cross-site embed; such a cookie must not carry a session or credential.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1275/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1275],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["samesite", "cookie", "csrf", "cwe-1275"],
}

_msg := "Cookie SameSite is None (or switched off): the browser sends it on cross-site requests, which exposes a session cookie to CSRF. Use SameSite=Lax or Strict for session and credential cookies"

_js_exts := {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

_count(s, ch) := count(split(s, ch)) - 1

# The first occurrence of needle is not inside a string literal: the text
# before it holds an even number of each quote character.
_outside_string(line, needle) if {
	prefix := split(line, needle)[0]
	_count(prefix, "\"") % 2 == 0
	_count(prefix, "'") % 2 == 0
	_count(prefix, "`") % 2 == 0
}

# ── JavaScript / TypeScript ─────────────────────────────────────────────

_js_none := "(?:['\"`](?i:none)['\"`]|false\\b)"

# A TypeScript type (`sameSite: 'none' | 'lax'`) names the allowed values; it
# configures nothing.
_js_type_union(line) if regex.match("['\"`]\\s*\\|", line)

_js_type_union(line) if regex.match("\\|\\s*['\"`](?i:none)['\"`]", line)

_js_bad(line) if {
	regex.match(concat("", ["\\bsameSite\\s*:\\s*", _js_none]), line)
	_outside_string(line, "sameSite")
	not _js_type_union(line)
}

# A quoted option key: { 'sameSite': 'none' }.
_js_bad(line) if {
	regex.match(concat("", ["^\\s*['\"]sameSite['\"]\\s*:\\s*", _js_none]), line)
	not _js_type_union(line)
}

# Assigned on an existing options object: req.session.cookie.sameSite = "none".
_js_bad(line) if {
	regex.match(concat("", ["\\.\\s*sameSite\\s*=\\s*", _js_none, "\\s*(?:;|$)"]), line)
	_outside_string(line, "sameSite")
}

# A cookie string: a Set-Cookie header, or one written to document.cookie.
_js_bad(line) if {
	regex.match(`(?i)set-cookie|\bdocument\.cookie\s*=`, line)
	regex.match(`(?i)\bSameSite\s*=\s*None\b`, line)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _js_exts
	endswith(path, ext)
	not endswith(path, ".min.js")
	regex.match(`(?i)samesite`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)samesite`, line)
	not helpers.is_comment_line(line)
	_js_bad(line)
	finding := _finding(path, i, line)
}

# ── Python ──────────────────────────────────────────────────────────────

# Django and Starlette compare the value case-insensitively; False switches
# the attribute off.
_py_none := `(?:None|False|['"](?i:none)['"])`

_py_setting_re := concat("", [`\b(?:SESSION|CSRF|LANGUAGE|REMEMBER)_COOKIE_SAMESITE['"]?\s*\]?\s*=\s*`, _py_none, `\s*(?:[,)#]|$)`])

_py_bad(_, _, line) if {
	regex.match(_py_setting_re, line)
	_outside_string(line, "_COOKIE_SAMESITE")
}

# app.config["SESSION_COOKIE_SAMESITE"] = None: the key is itself a string.
_py_bad(_, _, line) if {
	regex.match(concat("", [`^\s*[\w.]+\s*\[\s*['"](?:SESSION|CSRF|LANGUAGE|REMEMBER)_COOKIE_SAMESITE['"]\s*\]\s*=\s*`, _py_none, `\s*(?:#|$)`]), line)
}

_py_bad(lines, i, line) if {
	regex.match(concat("", [`\bsamesite\s*=\s*`, _py_none, `\s*(?:[,)#]|$)`]), line)
	_outside_string(line, "samesite")
	j := max([k |
		some k in numbers.range(max([0, i - 6]), i)
		regex.match(`\bset_(?:signed_)?cookie\s*\(`, lines[k])
	])
	not regex.match(`^\s*(?:async\s+)?def\s`, lines[j])
}

# Starlette/FastAPI SessionMiddleware(..., same_site="none").
_py_bad(lines, i, line) if {
	regex.match(concat("", [`\bsame_site\s*=\s*`, _py_none, `\s*(?:[,)#]|$)`]), line)
	_outside_string(line, "same_site")
	j := max([k |
		some k in numbers.range(max([0, i - 6]), i)
		regex.match(`SessionMiddleware\s*[,(]`, lines[k])
	])
	not _def_between(lines, j, i)
}

_def_between(lines, j, i) if {
	some k in numbers.range(j, i)
	regex.match(`^\s*(?:async\s+)?def\s`, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?i)same_?site`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)same_?site`, line)
	not helpers.is_comment_line(line)
	_py_bad(lines, i, line)
	finding := _finding(path, i, line)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
