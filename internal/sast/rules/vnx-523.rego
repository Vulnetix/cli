# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_523

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-523",
	"name": "Unprotected Transport of Credentials",
	"description": "Credentials are sent to a remote host over plain http://, so anyone on the network path reads them. Reported: a URL that carries a user:password pair (http://user:pass@host); an HTTP client call to an http:// URL whose arguments carry credentials (Python requests/httpx/session/urllib3/urllib.request with auth=, an Authorization/Cookie/X-Api-Key header, or a password, token or API-key field in data/json/params; fetch/axios/jQuery with the same in its options; Go http.PostForm with a password field), the call broken across lines included; a request built on an http:// URL (Go http.NewRequest, Java new URL/URI.create/new HttpGet/HttpPost) that, within the next eight lines of the same function, gets SetBasicAuth or an Authorization, Cookie or X-Api-Key header; and an HTML login form (a page with a password input) whose action is an http:// URL. Not reported: https://, loopback, private-range, link-local, single-label (container or service names) and reserved example/test/local hosts, requests that carry no credentials, URLs in comments or prose strings, and test code. Cleartext endpoints in general are VNX-319; cleartext redis/amqp/ftp/ldap connection URLs are VNX-SEC-017.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-523/",
	"languages": ["go", "java", "node", "python", "html"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [523],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["unprotected-transport", "cleartext", "credentials", "cwe-523"],
}

_code_exts := {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".java"}

_tpl_exts := {".html", ".htm", ".jsp", ".ejs", ".hbs", ".j2", ".jinja", ".jinja2", ".vue"}

_ext_in(path, exts) if {
	some e in exts
	endswith(path, e)
}

_url_re := `\bhttp://(?:([^/\s:@'"\x60]+):([^/\s@'"\x60]+)@)?([A-Za-z0-9][A-Za-z0-9.-]*)`

# A host on the public network: it has a dot and is not loopback, private,
# link-local or a reserved/placeholder name.
_remote(host) if {
	h := lower(host)
	contains(h, ".")
	not _local(h)
}

_local(h) if regex.match(`^(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)`, h)

_local(h) if regex.match(`(?:^|\.)(?:localhost|example\.(?:com|org|net)|example|test|invalid|local|localdomain|internal|lan|home\.arpa)$`, h)

_first_remote(txt) := m if {
	ms := [x | some x in regex.find_all_string_submatch_n(_url_re, txt, -1); _remote(x[3])]
	count(ms) > 0
	m := ms[0]
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

# Text inside a quoted string containing a space is prose, not a URL to call.
_prose_url(line) if regex.match(`["'\x60][^"'\x60]*\s[^"'\x60]*http://[^"'\x60]*["'\x60]|["'\x60][^"'\x60]*http://[^"'\x60]*\s[^"'\x60]*["'\x60]`, line)

# ── user:password@ in the URL ────────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	_ext_in(path, _code_exts)
	contains(content, "http://")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "@")
	contains(line, "http://")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_url_re, line, -1)
	m[1] != ""
	_remote(m[3])
	f := _finding(path, i, line, "The URL embeds a username and password and uses plain http://, so the credentials cross the network in cleartext. Use https:// and pass the credentials from configuration")
}

# ── Client calls carrying credentials ────────────────────────────────────

_call_re := `(?:\b(?:requests|httpx|session|sess|client|http|aiohttp)\.(?:get|post|put|patch|delete|head|request)\(|(?:^|[^\w.])fetch\(|\baxios(?:\.(?:get|post|put|patch|delete|request))?\(|\$\.(?:ajax|post|get)\(|\bhttp\.(?:Post|PostForm|Get)\(|\burllib\.request\.(?:Request|urlopen)\()`

# A function declared with a client-like name (def fetch(token):) is not a call.
_declaration(line) if {
	not contains(line, "http://")
	regex.match(`\b(?:def|function|func|fun)\s+\w+\s*\(|^\s*(?:async\s+)?(?:fetch|get|post|request)\s*\([^)]*\)\s*(?::\s*[\w<>\[\], ]+)?\s*\{\s*$`, line)
}

_cred_re := `(?i)\bauth\s*[=:]|authorization|basicauth|passw(?:or)?d|\bpwd\b|passphrase|api[_-]?key|x-api-key|bearer|\btoken\b|(?:access|auth|id|refresh|session)_?token|cookie`

# The call: from line i to the line closing it, at most five lines.
_call(lines, i) := txt if {
	last := min([count(lines) - 1, i + 5])
	ends := [j |
		some j in numbers.range(i, last)
		regex.match(`\)\s*[;,]?\s*$|\)\s*\.`, lines[j])
	]
	end := min(array.concat([last], ends))
	txt := concat("\n", [lines[j] | some j in numbers.range(i, end); not helpers.is_comment_line(lines[j])])
}

findings contains f if {
	some path, content in input.file_contents
	_ext_in(path, _code_exts)
	contains(content, "http://")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_call_re, line)
	not _declaration(line)
	call := _call(lines, i)
	contains(call, "http://")
	not _prose_url(call)
	m := _first_remote(call)
	m[1] == "" # a userinfo URL is reported by the rule above
	rest := regex.replace(call, `http://[^\s'"\x60]*`, "")
	_carries_cred(rest)
	f := _finding(path, i, line, "Credentials are sent in a request to a plain http:// URL, so they cross the network in cleartext. Use https://")
}

# Credentials appear in the code of the call or in a key-like string
# ("Authorization", "password"). Prose strings with spaces ("Password reset
# requested") are messages, not credentials.
_carries_cred(rest) if regex.match(_cred_re, regex.replace(rest, `"[^"\n]*"|'[^'\n]*'`, `""`))

_carries_cred(rest) if {
	some s in regex.find_n(`"[^"\n]*"|'[^'\n]*'`, rest, -1)
	not regex.match(`\s`, s)
	regex.match(_cred_re, s)
}

# ── Request built on http://, credentials added below ────────────────────

_build_re := `\bhttp\.NewRequest(?:WithContext)?\(|\bnew URL\(|\bURI\.create\(|\bnew Http(?:Get|Post|Put|Patch|Delete)\(|\bHttpRequest\.newBuilder\(`

_auth_after_re := `SetBasicAuth\(|Header\.(?:Set|Add)\(\s*"(?i:authorization|cookie|x-api-key)"|(?:setRequestProperty|setHeader|addHeader|header)\(\s*"(?i:authorization|cookie|x-api-key)"`

_boundary_re := `^func\b|^\s*(?:public|private|protected)\s[^=;]*\(|^}|http\.NewRequest|new URL\(|URI\.create\(|new Http(?:Get|Post|Put|Patch|Delete)\(`

findings contains f if {
	some path, content in input.file_contents
	_ext_in(path, {".go", ".java"})
	contains(content, "http://")
	regex.match(_auth_after_re, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "http://")
	not helpers.is_comment_line(line)
	regex.match(_build_re, line)
	m := _first_remote(line)
	m[1] == ""
	last := min([count(lines) - 1, i + 8])
	some k in numbers.range(i + 1, last)
	regex.match(_auth_after_re, lines[k])
	not helpers.is_comment_line(lines[k])
	not _boundary_between(lines, i, k)
	f := _finding(path, i, line, "This request goes to a plain http:// URL and is given an Authorization/Basic credential below, so the credential crosses the network in cleartext. Use https://")
}

_boundary_between(lines, i, k) if {
	i + 1 <= k - 1
	some j in numbers.range(i + 1, k - 1)
	regex.match(_boundary_re, lines[j])
}

# ── HTML login form posting to http:// ───────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	_ext_in(path, _tpl_exts)
	contains(content, "http://")
	regex.match(`(?i)type\s*=\s*["']?password`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)<form\b`, line)
	ms := regex.find_all_string_submatch_n(`(?i)\baction\s*=\s*["']?http://([A-Za-z0-9][A-Za-z0-9.-]*)`, line, 1)
	count(ms) > 0
	_remote(ms[0][1])
	f := _finding(path, i, line, "This login form posts the password to a plain http:// URL, so it crosses the network in cleartext. Use an https:// action")
}
