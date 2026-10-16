# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_598

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-598",
	"name": "Credential or secret sent in a GET query string",
	"description": "A password, API key, client secret or access token is placed in a URL query string, where it is written to server and proxy access logs, browser history and Referer headers. Reported: a URL whose query (the line also opens one with ?name=) carries a parameter named password, passwd, pwd, pass, passphrase, secret, client_secret, api_key, apikey, api-key, access_token, auth_token, token, session_id, sessionid or ssn whose value is interpolated from code, or a ?key= parameter whose interpolated value is named for an API key or secret (?key= followed by apiKey) (string concatenation, f-string or template-literal placeholder, %s/%v format verb, PHP $variable); a request helper (requests.get/post, axios.get, http.get and the like) given such a key in its params object on the same line, which always goes into the query string; and an HTML/template <form> that submits a password input by GET, either method=get or no method attribute (GET is the default) in .html, .htm, .php, .jsp, .ejs, .hbs, .twig, .jinja and .erb files. Not reported: form-encoded POST bodies (grant_type=password&password=...), credentials in headers or POST data, constant example URLs (?api_key=YOUR_API_KEY), lookalike parameters (pageToken, next_token, show_password_field), forms submitted by POST or by a script handler (onsubmit, ngSubmit, @submit), comments, and JSX/Vue forms (submitted by script).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-598/",
	"languages": ["go", "java", "node", "php", "python", "html"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [598],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["sensitive-data-in-url", "credentials", "logging", "cwe-598"],
}

_names := `(?i:password|passwd|pwd|pass|passphrase|secret|client_secret|api_key|apikey|api-key|access_token|auth_token|token|session_id|sessionid|ssn)`

_dynamic := "(?:[\"'`]\\s*[+.]|\\$\\{|\\{|%[sdv]|\\$[A-Za-z_])"

_param_re := concat("", [`[?&]`, _names, `=`, _dynamic])

_query_open := `\?[\w\-\[\]]+=`

_params_re := concat("", [`\.(?:get|post|put|patch|delete|request)\s*\(.*\bparams\s*[=:]\s*(?:dict\s*\(|\{).*(?:["']`, _names, `["']\s*:|\b`, _names, `\s*[:=][^=])`])

_code_ext := {".py", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".java", ".go", ".php"}

_tpl_ext := {".html", ".htm", ".php", ".jsp", ".ejs", ".hbs", ".twig", ".jinja", ".jinja2", ".j2", ".erb"}

_ext(path) := e if {
	parts := split(path, ".")
	count(parts) > 1
	e := concat("", [".", lower(parts[count(parts) - 1])])
}

_msg_url := "A credential or secret is placed in a URL query string, which is recorded in access logs, browser history and Referer headers. Send it in a POST body or an Authorization header"

_msg_form := "This form submits a password field by GET, putting the password in the URL, access logs and browser history. Use method=\"post\""

# Query strings built in code.
findings contains finding if {
	some path, content in input.file_contents
	_ext(path) in _code_ext
	regex.match(concat("", [`(?:[?&]`, _names, `=|[?&]key=|params)`]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`[=:]`, line)
	not helpers.is_comment_line(line)
	_url_secret(line)
	finding := _finding(path, i, line, _msg_url)
}

_url_secret(line) if {
	contains(line, "=")
	regex.match(_param_re, line)
	not contains(line, "otpauth://")
	regex.match(_query_open, line)
}

# ?key= is reported only when the value interpolated into it is named for a
# key or secret (Google-style ?key=<api key>); a bare ?key= is often a cache
# or lookup key.
_url_secret(line) if {
	contains(line, "key=")
	regex.match(`[?&]key=(?:["'\x60]\s*[+.]\s*|\$\{\s*|\{\s*|\$)[\w.>$-]*?(?i:api_?key|secret|access_?key|private_?key)`, line)
	regex.match(_query_open, line)
}

_url_secret(line) if {
	contains(line, "params")
	regex.match(_params_re, line)
}

# Password forms submitted by GET.
findings contains finding if {
	some path, content in input.file_contents
	_ext(path) in _tpl_ext
	regex.match(`(?i)type\s*=\s*["']?password`, content)
	regex.match(`(?i)<form\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)<form\b`, line)
	tag := _tag(lines, i)
	_get_form(tag)
	_has_password_input(lines, i)
	finding := _finding(path, i, line, _msg_form)
}

_tag(lines, i) := t if {
	end := min([count(lines) - 1, i + 4])
	joined := concat(" ", [lines[k] | some k in numbers.range(i, end)])
	m := regex.find_all_string_submatch_n(`(?is)<form\b[^>]*>?`, joined, 1)
	t := m[0][0]
}

_get_form(tag) if regex.match(`(?i)\bmethod\s*=\s*["']?get\b`, tag)

_get_form(tag) if {
	not regex.match(`(?i)\bmethod\s*=`, tag)
	not regex.match(`(?i)onsubmit|ng-?submit|formgroup|@submit|v-on:|x-on:|hx-(?:post|put)|th:method|data-remote|wire:submit|\[\w+\]\s*=|\(\w+\)\s*=`, tag)
}

_has_password_input(lines, i) if {
	end := min([count(lines) - 1, i + 60])
	closes := [k | some k in numbers.range(i + 1, end); regex.match(`(?i)</form\s*>`, lines[k])]
	last := min(array.concat([end], closes))
	some k in numbers.range(i, last)
	regex.match(`(?i)<input\b[^>]*\btype\s*=\s*["']?password\b|^\s*type\s*=\s*["']?password\b`, lines[k])
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
