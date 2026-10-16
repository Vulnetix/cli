# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_603

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-603",
	"name": "Authentication decided in browser code",
	"description": "Browser JavaScript decides on its own that the user is authenticated or privileged, so anyone can pass the check by editing the page, the console or storage. Reported: a login or role flag written to localStorage/sessionStorage as a literal (setItem('isLoggedIn', 'true'), sessionStorage.isAdmin = true) or to document.cookie (loggedIn=true, role=admin); such a flag read back from storage and compared, negated or tested to gate the page (if (!localStorage.isLoggedIn)), including when it was first read into a variable that a condition tests within the next 10 lines; and a password, passcode or PIN (a variable so named, or the .value of an element whose id names one) compared with a non-empty string literal in a file that uses the DOM or is a React/Vue/Svelte component (.jsx, .tsx, .vue, .svelte). Flag names are isLoggedIn/loggedIn/logged_in, isAuthenticated/authenticated/auth, isAdmin/admin, role/userRole, isAuthorized/authorized. Not reported: a storage read used as a fallback value (props.role || localStorage.getItem('role')), tokens stored or sent to the server (the server verifies them), flags set from a server response rather than a literal, clearing a flag (removeItem, 'false'), unrelated preferences (theme, consent), empty-string checks, server-side password comparison (bcrypt.compare, req.body), comments and prose inside string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-603/",
	"languages": ["node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [603],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["javascript", "browser", "authentication", "client-side-auth", "cwe-603"],
}

_ext := {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".vue", ".svelte", ".html", ".htm"}

_ext_of(path) := concat("", [".", lower(parts[count(parts) - 1])]) if parts := split(path, ".")

_flag := `(?i:(?:is_?)?(?:logged_?in|authenticated|auth|admin|authori[sz]ed)|(?:user_?)?role)`

_truthy := "(?:true|1|yes|admin|['\"`](?:true|1|yes|admin|y)['\"`])"

_q := "['\"`]"

# A literal that holds prose (a space or a parenthesis) is blanked, so a
# message quoting the pattern is not code. Short values ('true', 'S3cret!')
# survive.
_lit_re := "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`]*`"

_norm(line) := strings.replace_n({l: `""` | some l in regex.find_n(_lit_re, line, -1); regex.match(`[ (]`, l)}, line)


_set_re := concat("", [
	`\b(?:local|session)Storage\s*(?:\.\s*setItem\s*\(\s*`, _q, _flag, _q, `\s*,\s*`, _truthy, `\s*\)`,
	`|\.\s*`, _flag, `\s*=\s*`, _truthy, `\s*;?\s*$`,
	`|\[\s*`, _q, _flag, _q, `\s*\]\s*=\s*`, _truthy, `\s*;?\s*$)`,
])

_get := concat("", [`\b(?:local|session)Storage\s*(?:\.\s*getItem\s*\(\s*`, _q, _flag, _q, `\s*\)|\.\s*`, _flag, `\b|\[\s*`, _q, _flag, _q, `\s*\])`])

_get_re := concat("", [
	_get, `\s*(?:===?|!==?)\s*\S`,
	`|(?:===?|!==?)\s*`, _get,
	`|\bif\s*\(\s*!?\s*`, _get, `\s*\)`,
	`|`, _get, `\s*(?:\?[^?.]|&&)`,
	`|(?:!|&&)\s*`, _get,
])

_cookie_re := concat("", [`\bdocument\.cookie\s*=\s*`, _q, `\s*`, _flag, `\s*=\s*(?:true|1|yes|admin)\b`])

_secret_ident := `(?i:pass|password|passwd|pwd|passcode|passphrase|pin|pincode|pin_code|\w+(?:Password|Passwd|Pass|Pwd|Pin|Passcode)|\w+_(?:password|pass|pwd|pin))`

_pw_re := concat("", [
	`(?:^|[^\w.$])`, _secret_ident, `(?:\.value)?\s*(?:===?|!==?)\s*`, _q, `[^'"\x60\s]+`, _q,
	`|(?:getElementById|querySelector)\s*\(\s*`, _q, `#?`, _secret_ident, _q, `\s*\)\s*\.value\s*(?:===?|!==?)\s*`, _q, `[^'"\x60\s]+`, _q,
])

_msg := "Authentication or privilege is decided in browser code (a literal login/role flag in storage or a cookie, or a password compared with a literal); anyone can bypass it from the console. Authenticate on the server and gate access there"

findings contains finding if {
	some path, content in input.file_contents
	_ext_of(path) in _ext
	_file_gate(path, content)
	dom := _dom(content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 2000
	_line_gate(line)
	not helpers.is_comment_line(line)
	n := _norm(line)
	_matches(n, dom)
	finding := _finding(path, i, line)
}

# document.cookie = "loggedIn=true; path=/" (checked on the raw line: the
# cookie string itself holds the flag).
findings contains finding if {
	some path, content in input.file_contents
	_ext_of(path) in _ext
	contains(content, "document.cookie")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "document.cookie")
	regex.match(concat("", [`^\s*(?:window\.)?`, _cookie_re]), trim_left(line, " \t"))
	finding := _finding(path, i, line)
}

# const role = sessionStorage.getItem('role'); ... if (role !== 'admin'):
# the flag is read into a variable and the page is gated on it a few lines
# later. The finding is the line that decides.
findings contains finding if {
	some path, content in input.file_contents
	_ext_of(path) in _ext
	contains(content, "Storage")
	lines := split(content, "\n")
	some j, l in lines
	contains(l, "Storage")
	not helpers.is_comment_line(l)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*`, _get, `\s*;?\s*$`]), l, 1)
	count(m) > 0
	v := m[0][1]
	some i in numbers.range(j + 1, min([count(lines) - 1, j + 10]))
	count(lines[i]) < 2000
	contains(lines[i], v)
	not helpers.is_comment_line(lines[i])
	_var_gate(_norm(lines[i]), v)
	finding := _finding(path, i, lines[i])
}

_var_gate(n, v) if {
	x := concat("", [`(?:^|[^\w$.])`, v, `\b`])
	regex.match(concat("", [x, `\s*(?:===?|!==?)\s*\S`]), n)
	not regex.match(concat("", [x, `\s*(?:===?|!==?)\s*(?:null|undefined)\b`]), n)
}

_var_gate(n, v) if {
	x := concat("", [`(?:^|[^\w$.])`, v, `\b`])
	regex.match(concat("", [`(?:===?|!==?)\s*`, x]), n)
	not regex.match(concat("", [`(?:null|undefined)\s*(?:===?|!==?)\s*`, x]), n)
}

_var_gate(n, v) if regex.match(concat("", [`\b(?:if|while)\s*\(\s*!?\s*`, v, `\s*\)`]), n)

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_file_gate(_, content) if contains(content, "Storage")

_file_gate(_, content) if contains(content, "document.")

# A component with no storage or DOM use can only match the password compare.
_file_gate(path, content) if {
	_ext_of(path) in {".jsx", ".tsx", ".vue", ".svelte"}
	_component_hint(content)
	regex.match(`(?i)(?:pass|pwd|pin)\w*(?:\.value)?\s*[=!]==?\s*['"\x60][^'"\x60\s]`, content)
	_component(content)
}

# A React, Vue or Svelte component renders in the browser.
_component(content) if {
	_component_hint(content)
	regex.match(`\buse(?:State|Ref)\s*\(|\bfrom\s+['"](?:react|vue|svelte)['"]|<script\b[^>]*setup`, content)
}

# Browser code that is not also a server: only there is a literal password
# comparison client-side authentication.
_dom(content) := true if {
	_browser(content)
	not regex.match(`\breq(?:uest)?\.body\b|require\(\s*['"](?:express|bcrypt)`, content)
} else := false

_line_gate(line) if contains(line, "Storage")

_line_gate(line) if contains(line, "document.cookie")

_line_gate(line) if {
	regex.match(`[=!]=`, line)
	regex.match(`(?i)pass|pwd|pin`, line)
}

_matches(n, _) if regex.match(_set_re, n)

_matches(n, _) if regex.match(_get_re, n)

_matches(n, true) if regex.match(_pw_re, n)

_browser(content) if contains(content, "document.")

_browser(content) if _component(content)

_component_hint(content) if contains(content, "useState")

_component_hint(content) if contains(content, "useRef")

_component_hint(content) if contains(content, "<script")

_component_hint(content) if regex.match(`from\s+['"](?:react|vue|svelte)['"]`, content)
