# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1023

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1023",
	"name": "Secret compared by prefix, suffix or truncation",
	"description": "A password, token, API key, signature, digest, HMAC, OTP or PIN is checked against another value by comparing only part of it, so the comparison is missing factors: an empty or short guess matches. Reported in Python and Java: X.startswith(Y)/endswith(Y) (Python) and X.startsWith(Y)/endsWith(Y)/regionMatches(...) (Java) where one side is named as a secret (password, passwd, pwd, secret, token, api_key, signature, sig, digest, hmac, otp, pin, passcode) and the other is a stored, expected or user-supplied value (expected, stored, actual, valid, provided, supplied, submitted, given, candidate, attempt, user_..., request..., a second secret name); and equality on truncated values: Python a[:n] == b, hmac.compare_digest(a[:n], ...), Java a.substring(0, n).equals(b) or a.equals(b.substring(0, n)), when either side is named as a secret. Not reported: a prefix check against a string literal or a name that says it is a prefix/scheme/type (token.startswith(\"Bearer \"), sig.startsWith(SHA256_PREFIX)), tokenizer code comparing a token with a delimiter, full-length comparisons, comments and string literals. Abstract CWE-1023 cases (comparisons that omit a non-secret factor such as a tenant or user id) are not statically recognisable and are not attempted.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1023/",
	"languages": ["java", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1023],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["incomplete-comparison", "authentication", "cwe-1023"],
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

_secret := `(?i:passw(?:or)?d|pwd|secret|token|api_?key|signature|digest|hmac|passcode)|(?:^|[^A-Za-z])(?i:sig|otp|pin|key)(?:$|[^a-z])|[a-z](?:Sig|Otp|OTP|Pin|PIN|Key)(?:$|[^a-z])`

_other := `(?i)expected|stored|actual|valid|correct|provided|supplied|submitted|given|candidate|attempt|(?:^|[^a-z])user_?|request|getParameter|getHeader|input`

_prefixish := `(?i)prefix|suffix|scheme|type|kind|marker|delim|quote|sep|char|start|end|bearer|basic|header_name`

_strip(s) := regex.replace(s, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, `""`)

_ext(path) if endswith(path, ".py")

_ext(path) if endswith(path, ".java")

_operand := `[A-Za-z_][\w.]*(?:\([^()]*\))?(?:\[[^\[\]]*\])?`

# The two sides of a prefix/suffix comparison are judged together.
_partial_pair(a, b) if {
	not regex.match(`^\s*["']`, b)
	not regex.match(_prefixish, b)
	regex.match(_secret, a)
	_judged(b)
}

_partial_pair(a, b) if {
	not regex.match(`^\s*["']`, b)
	not regex.match(_prefixish, b)
	regex.match(_secret, b)
	_judged(a)
}

_judged(x) if regex.match(_other, x)

_judged(x) if regex.match(_secret, x)

findings contains _finding(path, i, line, "Secret checked by prefix or suffix only: an empty or truncated guess satisfies startswith/endswith. Compare the full values in constant time (hmac.compare_digest, MessageDigest.isEqual)") if {
	some path, content in input.file_contents
	_ext(path)
	regex.match(`\.(?:startswith|endswith|startsWith|endsWith|regionMatches)\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(?:startswith|endswith|startsWith|endsWith|regionMatches)\s*\(`, line)
	not helpers.is_comment_line(line)
	code := _strip(line)
	some m in regex.find_all_string_submatch_n(concat("", [`(`, _operand, `)\.(?:startswith|endswith|startsWith|endsWith)\s*\(\s*(`, _operand, `|["'][^"']*["']|""|''|\))`]), code, -1)
	_partial_pair(m[1], m[2])
}

findings contains _finding(path, i, line, "Secret checked with regionMatches: only the compared region has to match, so a partial guess passes. Compare the full values in constant time (MessageDigest.isEqual)") if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "regionMatches(")
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`(`, _operand, `)\.regionMatches\s*\(([^;]*)`]), _strip(line), 1)
	count(m) > 0
	regex.match(_secret, concat(" ", [m[0][1], m[0][2]]))
}

findings contains _finding(path, i, line, "Secret compared after truncation: only the first characters have to match. Compare the full values in constant time (hmac.compare_digest)") if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "[:")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "[:")
	not helpers.is_comment_line(line)
	code := _strip(line)
	_py_truncated(code)
}

_py_slice := `[A-Za-z_][\w.]*(?:\([^()]*\))?\[\s*:\s*[\w.+\-* ]+\]`

_py_truncated(code) if {
	some m in regex.find_all_string_submatch_n(concat("", [`(`, _py_slice, `)\s*[!=]=\s*(`, _operand, `)`]), code, -1)
	not regex.match(_prefixish, m[2])
	regex.match(_secret, concat(" ", [m[1], m[2]]))
}

_py_truncated(code) if {
	some m in regex.find_all_string_submatch_n(concat("", [`(`, _operand, `)\s*[!=]=\s*(`, _py_slice, `)`]), code, -1)
	not regex.match(_prefixish, m[1])
	regex.match(_secret, concat(" ", [m[1], m[2]]))
}

_py_truncated(code) if {
	m := regex.find_all_string_submatch_n(`compare_digest\s*\(([^)]*\[\s*:[^\]]+\][^)]*)\)`, code, 1)
	count(m) > 0
	regex.match(_secret, m[0][1])
}

findings contains _finding(path, i, line, "Secret compared after substring truncation: only the first characters have to match. Compare the full values in constant time (MessageDigest.isEqual)") if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, ".substring(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".substring(")
	not helpers.is_comment_line(line)
	code := _strip(line)
	some m in regex.find_all_string_submatch_n(`([A-Za-z_][\w.]*(?:\(\))?)\.substring\(\s*0\s*,[^()]*(?:\([^()]*\))?[^()]*\)\.equals(?:IgnoreCase)?\(\s*([^)]*)\)|([A-Za-z_][\w.]*(?:\(\))?)\.equals(?:IgnoreCase)?\(\s*([A-Za-z_][\w.]*(?:\(\))?)\.substring\(\s*0\s*,`, code, -1)
	regex.match(_secret, concat(" ", [m[1], m[2], m[3], m[4]]))
}
