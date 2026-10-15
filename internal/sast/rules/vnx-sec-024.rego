package vulnetix.rules.vnx_sec_024

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-SEC-024",
	"name": "OAuth token stored in localStorage",
	"description": "Reports browser code (JavaScript, TypeScript, and the script in .vue, .svelte and .html files) that writes an access token, refresh token, ID token, JWT or API key into localStorage, where any script that runs on the origin, including an XSS payload, can read it: localStorage.setItem(key, value) or window/$window.localStorage.setItem (the call may span lines), and property writes localStorage.token = ... or localStorage['jwt'] = .... It is reported when the key names a token (token, access_token, refreshToken, id_token, jwt, auth_token, user_api_key, oidc.refreshToken), when the key is a constant or member whose name or value in the same file names one (TOKEN_KEY = \"auth_token\", KEYS.ACCESS_TOKEN), or when the stored value is a token-named field (tokens.access_token, res.data.refreshToken) or a JSON.stringify() of an object with a token-named member ({ email, token: res.data.token }). Not reported: keys that describe a token rather than hold one (tokenExpiry, tokenType, hasToken, tokenCount, tokenRefreshedAt), CSRF and push-notification tokens, preferences, reads and removals (getItem, removeItem), sessionStorage and cookies, the call inside a string literal or a comment line, test, spec and Cypress files, and files of other languages.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-024/",
	"languages": ["javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [922],
	"capec": ["CAPEC-60"],
	"attack_technique": ["T1539"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["oauth", "token-storage", "xss"],
}

_exts := [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte", ".html", ".htm"]

_lang(path) if {
	some e in _exts
	endswith(path, e)
}

_skip(path) if endswith(path, ".min.js")

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`\.cy\.(js|jsx|ts|tsx)$|(^|/)cypress/`, path)

# Text before the match is code, not the inside of a string literal.
_pre := `^(?:[^"'\x60/]|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\x60[^\x60]*\x60|/[^/])*?`

# localStorage.setItem( KEY , VALUE   (KEY a literal or an expression)
_set_re := concat("", [_pre, `(?:^|[^\w$."'\x60]|\bwindow\.|\$window\.)localStorage\s*\.\s*setItem\s*\(\s*(?:(["'\x60])([^"'\x60]+)["'\x60]|([A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)*))\s*,\s*(.*)`])

# localStorage.token = VALUE / localStorage["token"] = VALUE
_prop_re := concat("", [_pre, `(?:^|[^\w$."'\x60]|\bwindow\.|\$window\.)localStorage\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*["'\x60]([^"'\x60]+)["'\x60]\s*\])\s*=[^=]\s*(.*)`])

_norm(k) := lower(regex.replace(k, `[-_.\s:/]`, ""))

_benign(n) if regex.match(`^(csrf|xsrf|push|fcm|apns|device|notification|has|is|page|next|captcha|recaptcha|cancel)`, n)

# A key that holds a token: it ends with the token word.
_token_key(k) if {
	n := _norm(k)
	regex.match(`(token|jwt|apikey|bearer|credentials)$`, n)
	not _benign(n)
}

_token_key(k) if {
	n := _norm(k)
	contains(n, "jwt")
	not regex.match(`(expir\w*|exp|type|count|at|time)$`, n)
}

# An identifier key: the constant's name minus a KEY/NAME suffix names a token.
_ident_key(_, ident) if {
	segs := split(ident, ".")
	last := segs[count(segs) - 1]
	base := regex.replace(last, `(?i)[_]?(storage)?[_]?(key|name|id)$`, "")
	base != ""
	_token_key(base)
}

# ...or the constant is assigned a token key in the same file.
_ident_key(content, ident) if {
	segs := split(ident, ".")
	last := segs[count(segs) - 1]
	regex.match(`^[A-Za-z_]\w*$`, last)
	some m in regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w$])`, last, `\s*[:=]\s*["'\x60]([^"'\x60]+)["'\x60]`]), content, 5)
	_token_key(m[1])
}

# The stored value is a token-named field or variable.
_token_value(v) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*|\[\s*["'][\w-]+["']\s*\])*)\s*(?:[,);]|$)`, v, 1)
	count(m) > 0
	segs := regex.split(`\??\.|\[\s*["']|["']\s*\]`, m[0][1])
	parts := [s | some s in segs; s != ""]
	last := parts[count(parts) - 1]
	regex.match(`(?i)^_*(access|refresh|id|auth|bearer|oauth)_?token$|^_*jwt$`, last)
}

_key_hit(_, m) if _token_key(m[2])

_key_hit(content, m) if {
	m[3] != ""
	_ident_key(content, m[3])
}

_key_hit(_, m) if _token_value(m[4])

_key_hit(_, m) if _token_json(m[4])

# JSON.stringify({ user, token: res.data.token }): an object with a
# token-named member is stored whole.
_token_json(v) if {
	regex.match(`^\s*JSON\s*\.\s*stringify\s*\(`, v)
	some p in regex.find_all_string_submatch_n(`[{,]\s*["']?([A-Za-z_$][\w$]*)["']?\s*:`, v, -1)
	_token_key(p[1])
}

_hit(content, text) if {
	some m in regex.find_all_string_submatch_n(_set_re, text, 1)
	_key_hit(content, m)
}

_hit(_, text) if {
	some m in regex.find_all_string_submatch_n(_prop_re, text, 1)
	some k in [m[1], m[2]]
	k != ""
	_token_key(k)
}

_hit(_, text) if {
	some m in regex.find_all_string_submatch_n(_prop_re, text, 1)
	_token_value(m[3])
}

# The call and up to three continuation lines while its parenthesis is open.
_text(lines, i) := lines[i] if count(indexof_n(lines[i], "(")) <= count(indexof_n(lines[i], ")"))

_text(lines, i) := t if {
	count(indexof_n(lines[i], "(")) > count(indexof_n(lines[i], ")"))
	end := min([count(lines) - 1, i + 3])
	t := concat(" ", [trim_space(lines[k]) | some k in numbers.range(i, end)])
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	not _skip(path)
	contains(content, "localStorage")
	regex.match(`localStorage\s*(?:\.\s*setItem\s*\(|\.\s*[A-Za-z_$][\w$]*\s*=[^=]|\[[^\]]+\]\s*=[^=])`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "localStorage")
	not helpers.is_comment_line(line)
	_hit(content, _text(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": "Authentication token written to localStorage, where any script on the origin (including an XSS payload) can read it; keep it in an httpOnly Secure cookie or a backend-for-frontend session, or in memory",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
