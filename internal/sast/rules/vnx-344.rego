# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_344

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-344",
	"name": "Use of Invariant Value in Dynamically Changing Context",
	"description": "A value that must be fresh for every response or every login is written into the source as a constant. Reported: a Content-Security-Policy nonce source with a literal value ('nonce-abc123' in a header string, a helmet/CSP directive list, or an HTML meta policy) and a <script>/<style> nonce attribute with a literal value, in Go, Java, JavaScript/TypeScript, Python, PHP and HTML; and an OAuth authorisation request whose state parameter is a constant: a literal state=value in an authorize URL (one that also carries response_type= or redirect_uri=, or whose path is /authorize), requests-oauthlib/Authlib authorization_url()/authorize_redirect()/create_authorization_url() given state=\"literal\", golang.org/x/oauth2 AuthCodeURL(\"literal\"), and league/oauth2-client getAuthorizationUrl([... 'state' => 'literal' ...]) on one line or spread over the array's lines, and in JavaScript/TypeScript a state: 'literal' option given to simple-oauth2 authorizeURL(), openid-client authorizationUrl() or passport.authenticate() (on the call's line or inside its object literal). A fixed CSP nonce is known to every attacker who has loaded the page once, so an injected script carrying it runs; a fixed OAuth state gives no CSRF protection to the callback. Not reported: nonces and states interpolated from a variable (f-strings, template literals, %s, concatenation, {{ }} and <%= %> templates, JSX attributes), placeholders substituted at runtime ('nonce-__NONCE__'), ordinary REST filters such as ?client_id=5&state=open, passport's state: true (it generates one), state options holding a variable, state: 'open' in objects unrelated to an OAuth client call, comments, and other identifiers that merely contain the words. Constant IVs, nonces and salts passed to cipher or KDF calls are VNX-CRYPTO-010's concern, and hard-coded secrets belong to the secrets rules.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-344/",
	"languages": ["go", "java", "node", "python", "php", "html"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [344],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["invariant-value", "cwe-344", "csp", "oauth"],
}

_exts := {".php", ".go", ".java", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".html", ".htm"}

_ext_ok(path) if {
	some e in _exts
	endswith(path, e)
}

# A CSP nonce source whose value is spelled out: 'nonce-<base64ish>' closed
# by its quote. An interpolation ({nonce}, ${...}, %s, " + nonce + ") never
# matches, because its first character is not in the class or the quote
# closes immediately.
_csp_literal_re := `'nonce-[A-Za-z0-9+/=_-]{4,}'`

# A nonce attribute with a literal value.
_attr_literal_re := `<(?:script|style|link)\b[^>]*\bnonce\s*=\s*["'][A-Za-z0-9+/=_-]{4,}["']`

# A literal state in an authorisation URL.
_state_url_re := "[?&]state=[A-Za-z0-9_.~-]{2,}(?:[&\"'`]|$)"

# client_id= alone also appears in ordinary REST filters (?client_id=5&state=open),
# so it does not make a URL an authorisation request.
_authz_url_re := `(?i)(?:response_type=|redirect_uri=|/authori[sz]e)`

_state_kwarg_re := `\b(?:authorization_url|authorize_redirect|create_authorization_url|authorize_access_token_url)\s*\([^)]*\bstate\s*=\s*["'][A-Za-z0-9_.~-]+["']`

_kind(line) := "csp" if regex.match(_csp_literal_re, line)

_kind(line) := "csp" if {
	not regex.match(_csp_literal_re, line)
	regex.match(_attr_literal_re, line)
}

_kind(line) := "state" if {
	not regex.match(_csp_literal_re, line)
	not regex.match(_attr_literal_re, line)
	_state_line(line)
}

_state_line(line) if {
	regex.match(_state_url_re, line)
	regex.match(_authz_url_re, line)
}

_state_line(line) if regex.match(_state_kwarg_re, line)

# golang.org/x/oauth2: the first argument of AuthCodeURL is the state.
_state_line(line) if regex.match(`\.AuthCodeURL\(\s*"[^"]*"`, line)

# league/oauth2-client: getAuthorizationUrl(['state' => 'literal']) on one line.
_state_line(line) if regex.match(_league_state_re, line)

_league_state_re := `getAuthorizationUrl\(\s*\[[^\]]*['"]state['"]\s*=>\s*['"][A-Za-z0-9_.~-]+['"]`

_league_item_re := `^\s*['"]state['"]\s*=>\s*['"][A-Za-z0-9_.~-]+['"]`

# A placeholder substituted at runtime ('nonce-__NONCE__').
_placeholder(line) if regex.match(`(?i)'nonce-[_{%$]*(?:nonce|placeholder)[_}%]*'`, line)

_message("csp") := "A Content-Security-Policy nonce is a constant: anyone who has seen the page once knows it, so injected script carrying it runs. Generate a fresh random nonce for every response"

_message("state") := "The OAuth state parameter is a constant, so the callback cannot tell a login this browser started from one an attacker forced on it. Generate a random state per authorisation request, store it in the session and compare it on the callback"

findings contains finding if {
	some path, content in input.file_contents
	_ext_ok(path)
	not helpers.is_test_path(path)
	_cheap(content)
	regex.match(`'nonce-[A-Za-z0-9+/=_-]|nonce\s*=\s*["'][A-Za-z0-9+/=_-]|[?&]state=|state\s*=\s*["']|AuthCodeURL\(\s*"|getAuthorizationUrl\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`nonce|state|AuthCodeURL`, line)
	not helpers.is_comment_line(line)
	not startswith(trim_space(line), "<!--")
	k := _kind(line)
	not _placeholder(line)
	finding := {
		"rule_id": metadata.id,
		"message": _message(k),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The multi-line league/oauth2-client array: a 'state' => 'literal' item inside
# a getAuthorizationUrl([ ... ]) call opened in the 6 lines above.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	not helpers.is_test_path(path)
	contains(content, "getAuthorizationUrl(")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_league_item_re, line)
	w := helpers.code_window(lines, i, 6, 0)
	regex.match(`getAuthorizationUrl\(\s*(?:\[|array\()[^;]*$`, w)
	finding := {
		"rule_id": metadata.id,
		"message": _message("state"),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_cheap(content) if contains(content, "nonce")

_cheap(content) if contains(content, "AuthCodeURL(")

_cheap(content) if contains(content, "getAuthorizationUrl(")

_cheap(content) if contains(content, "state=")

_cheap(content) if contains(content, "state =")

# JavaScript OAuth clients that take the state as an option: simple-oauth2
# authorizeURL({... state: 'literal' }), openid-client authorizationUrl({...})
# and passport.authenticate(strategy, { state: 'literal' }) (state: true makes
# passport generate one). The item may sit on the call's line or inside the
# object opened in the 6 lines above.
_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_js_state_item_re := `\bstate\s*:\s*["'\x60][A-Za-z0-9_.~!#()/-]+["'\x60]`

_js_state_call_re := `\b(?:authorizeURL|authorizationUrl|authorizationURL|authorizeUrl|passport\.authenticate)\(`

findings contains finding if {
	some path, content in input.file_contents
	some e in _js_exts
	endswith(path, e)
	not helpers.is_test_path(path)
	regex.match(_js_state_call_re, content)
	contains(content, "state")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "state")
	regex.match(_js_state_item_re, line)
	not helpers.is_comment_line(line)
	above := helpers.code_window(lines, max([0, i - 1]), 5, 0)
	w := concat("\n", [above, substring(line, 0, indexof(line, "state"))])
	regex.match(concat("", [_js_state_call_re, `[^;]*$`]), w)
	finding := {
		"rule_id": metadata.id,
		"message": _message("state"),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
