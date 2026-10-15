# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_315

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-315",
	"name": "Cleartext Storage of Sensitive Information in a Cookie",
	"description": "A password, payment card number, CVV, social security number, PIN, bank account number, API or private key is written into a cookie in cleartext, where it sits in the browser, in proxies and in logs and is sent with every request. Reported: a cookie whose name is such a value, or whose value expression names a password, card number, CVV or SSN, set through Flask/Django set_cookie/set_signed_cookie, Express res.cookie, Koa ctx.cookies.set, Fastify reply.setCookie, js-cookie Cookies.set, document.cookie = \"password=...\", Java new Cookie(...) and Spring ResponseCookie.from(...), PHP setcookie/setrawcookie, Rails cookies[...] / cookies.permanent / cookies.signed (signed cookies are readable), and Go http.Cookie{Name: ..., Value: ...} or Gin c.SetCookie(\"password\", ...). Not reported: values passed through a hash, encryption, HMAC or masking call, Rails cookies.encrypted, cookies being cleared (empty value or None), session ids, auth tokens, CSRF tokens and other identifiers, test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-315/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [315],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["sensitive-cookie", "cleartext-storage", "cwe-315"],
}

# A cookie name that is itself the sensitive value.
_sensitive_name := `(?i)^(?:[\w]*[_-])?(?:pass|password|passwd|passphrase|pwd|pass_?word|ssn|social_?security(?:_?number)?|credit_?card(?:_?number)?|card_?(?:number|num|no)|cc_?(?:number|num)?|cvv2?|cvc|pin|pin_?code|bank_?account(?:_?number)?|account_?number|routing_?number|iban|api_?key|private_?key|secret_?key)$`

# A value expression that names the sensitive value.
_sensitive_value := `(?i)(\b|_)(password|passwd|pwd|passphrase|ssn|credit_?card|card_?number|cardnumber|cvv|cvc)`

# The value is protected, or the cookie is being cleared.
_protected := `(?i)(hash|encrypt|cipher|crypt|hmac|digest|md5|sha\d|mask|redact|sign\w*\(|seal)`

_cleared(rest) if regex.match(`^\s*,?\s*(?:value\s*=\s*)?(?:''|""|None|null|nil|undefined)\s*(?:[,)]|$)`, rest)

_report(name, rest) if {
	regex.match(_sensitive_name, name)
	not _cleared(rest)
	not regex.match(_protected, rest)
}

_report(name, rest) if {
	not regex.match(_sensitive_name, name)
	regex.match(_sensitive_value, rest)
	not regex.match(_protected, rest)
	not regex.match(`(?i)(token|session|csrf|xsrf)`, name)
}

# language -> [file-gate literal, sink regex capturing (name, rest of line)]
_sinks := {
	".py": ["_cookie(", `\.set_(?:signed_)?cookie\(\s*(?:key\s*=\s*)?['"]([^'"]+)['"]\s*(.*)$`],
	".js": ["ookie", "(?:\\b(?:res|resp|response|reply|ctx\\.cookies|cookies|Cookies|jsCookie|cookie)\\.(?:cookie|set|setCookie|serialize)|\\w+[Rr]es(?:ponse)?\\.cookie)\\(\\s*['\"`]([^'\"`]+)['\"`]\\s*(.*)$"],
	".java": ["Cookie", `(?:new\s+(?:(?:javax|jakarta)\.servlet\.http\.)?Cookie|ResponseCookie\.from)\(\s*"([^"]+)"\s*(.*)$`],
	".php": ["cookie(", `(?i)\bset(?:raw)?cookie\(\s*['"]([^'"]+)['"]\s*(.*)$`],
	".go": ["SetCookie(\"", `\.SetCookie\(\s*"([^"]+)"\s*(.*)$`],
	".rb": ["cookies",`\bcookies(?:\.permanent|\.signed)*\[\s*:?['"]?([\w-]+)['"]?\s*\]\s*=(?:[^=](.*))?$`],
}

_lang(path) := ".js" if {
	some e in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, e)
}

_lang(path) := ext if {
	some ext in {".py", ".java", ".php", ".rb", ".go"}
	endswith(path, ext)
}

_finding(path, i, line, name) := {
	"rule_id": metadata.id,
	"message": sprintf("Sensitive value stored in cleartext in cookie %q: keep it server-side or encrypt it", [name]),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	sink := _sinks[lang]
	contains(content, sink[0])
	lines := split(content, "\n")
	some i, line in lines
	contains(lower(line), "cookie")
	not helpers.is_comment_line(line)
	not contains(line, ".encrypted")
	some m in regex.find_all_string_submatch_n(sink[1], line, 2)
	_report(m[1], _value_text(lines, i, m[2]))
	finding := _finding(path, i, line, m[1])
}

# A call broken over lines: the value is on the next line.
_value_text(lines, i, rest) := rest if not regex.match(`^[\s,]*$`, rest)

_value_text(lines, i, rest) := concat(" ", [lines[k] | some k in numbers.range(i + 1, min([count(lines) - 1, i + 2]))]) if regex.match(`^[\s,]*$`, rest)

# document.cookie = "password=" + pwd
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == ".js"
	not helpers.is_test_path(path)
	contains(content, "document.cookie")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "document.cookie")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n("document\\.cookie\\s*=\\s*['\"`]\\s*([\\w-]+)=(.*)$", line, 1)
	count(m) > 0
	_report(m[0][1], m[0][2])
	not regex.match(`^\s*;`, m[0][2])
	finding := _finding(path, i, line, m[0][1])
}

# Go: http.Cookie{Name: "password", Value: ...}, on one line or several.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	contains(content, "http.Cookie{")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "http.Cookie{")
	not helpers.is_comment_line(line)
	window := concat("\n", array.slice(lines, i, min([count(lines), i + 10])))
	block := regex.replace(window, `(?s)\n\s*\}.*$`, "")
	nm := regex.find_all_string_submatch_n(`Name:\s*"([^"]+)"`, block, 1)
	count(nm) > 0
	vm := regex.find_all_string_submatch_n(`Value:\s*([^\n]*)`, block, 1)
	count(vm) > 0
	_report(nm[0][1], vm[0][1])
	finding := _finding(path, i, line, nm[0][1])
}
