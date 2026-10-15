# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1290

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1290",
	"name": "Security identifier decoded from client data without verification",
	"description": "CWE-1290 (Incorrect Decoding of Security Identifiers) is a hardware weakness: a bus decoder that maps an agent's identifier to the wrong agent. Its nearest statically recognisable software form is reported: Python code that derives a security identifier (who the user is, their role, a serialized user object) by merely decoding a value the client holds, so any client can encode a different identity. Reported: base64 b64decode/urlsafe_b64decode/standard_b64decode/b32decode/b16decode/decodebytes, binascii.a2b_base64 and bytes.fromhex applied to a cookie (Flask request.cookies, Django request.COOKIES, Bottle/Tornado get_cookie) or to an identity-bearing custom header (a name containing token, session, auth, identity, user, jwt or sid, e.g. X-Auth-Token), directly (an argument split onto the next line included) or through a variable assigned from one in the 10 lines above. Not reported: decoding with an HMAC/signature check, compare_digest, itsdangerous/django.core.signing or a .verify() call within 10 lines before or 3 after, the HTTP Authorization header (Basic credentials are checked against a store afterwards), form fields and other data that is not an identifier, constants, comments and string literals. Unverified JWT decoding is VNX-JWT-004.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1290/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1290],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["incorrect-decoding", "security-identifier", "cwe-1290"],
}

_decode := `(?:^|[^\w.])(?:\w+\.)?(?:b64decode|urlsafe_b64decode|standard_b64decode|b32decode|b16decode|decodebytes|decodestring)\(|\bbinascii\.a2b_base64\(|\bbytes\.fromhex\(`

_hdr_name := `['"](?:HTTP_)?[\w-]*(?i:token|session|auth|identity|user|jwt|sid)[\w-]*['"]`

_src := concat("", [
	`\brequest\.(?:cookies|COOKIES)\b|\b(?:request|self)\.get_(?:secure_)?cookie\(|\brequest\.get_cookie\(`,
	`|\brequest\.headers(?:\.get\(\s*|\[\s*)`, _hdr_name,
	`|\brequest\.META(?:\.get\(\s*|\[\s*)`, _hdr_name,
])

_authz := `(?i)['"](?:HTTP_)?Authorization['"]`

_is_src(s) if {
	regex.match(_src, s)
	not regex.match(_authz, s)
	not regex.match(_benign_cookie, s)
}

# Cookies that hold a display preference or a consent record, not an identity.
_benign_cookie := `(?i)(?:cookies|COOKIES|get_cookie)(?:\.get)?[\(\[]\s*['"][\w-]*(?:theme|lang|locale|language|consent|layout|timezone|tz|pref|currency|banner|dismiss|tour|sidebar|font|colou?r|view|sort|tab)[\w-]*['"]`

_strip(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_tainted(lines, i) := {v |
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := lines[j]
	_is_src(prev)
	not helpers.is_comment_line(prev)
	v := helpers.assigned_first(prev)
}

_rests(c) := {r |
	parts := regex.split(_decode, c)
	count(parts) > 1
	some k in numbers.range(1, count(parts) - 1)
	r := parts[k]
}

# The original-text argument after the decode call: rest of the line, or the
# next line when the call is split after its paren.
_arg(lines, i, line) := a if {
	parts := regex.split(_decode, line)
	count(parts) > 1
	a := concat(" ", array.concat([parts[1]], [_next(lines, i, parts[1])]))
}

_next(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

_next(lines, i, rest) := "" if trim_space(rest) != ""

_next(lines, i, rest) := "" if {
	trim_space(rest) == ""
	i + 1 >= count(lines)
}

_reaches(lines, i, line, c) if {
	a := _arg(lines, i, line)
	_is_src(a)
}

_reaches(lines, i, _, c) if {
	some r in _rests(c)
	some v in _tainted(lines, i)
	regex.match(concat("", [`^\s*`, v, `\b`]), r)
}

_verified(lines, i) if {
	w := helpers.code_window(lines, i, 10, 3)
	regex.match(`\bhmac\b|compare_digest|[Ss]ignature|\.verify\(|itsdangerous|\bsigning\.|\.unsign\(|Signer\b|Serializer\b|check_signature`, w)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(_decode, content)
	regex.match(`cookie|COOKIE|headers|META`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	c := _strip(line)
	regex.match(_decode, c)
	_reaches(lines, i, line, c)
	not _verified(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Identity is decoded from a client-held cookie or token with no signature check; the client can encode any identity. Use a signed session (itsdangerous, django.core.signing) or verify an HMAC before trusting it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
