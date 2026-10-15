# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1254

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1254",
	"name": "Incorrect Comparison Logic Granularity",
	"description": "A secret (a MAC, HMAC, signature, digest, hash, token, key, password, OTP, nonce or session value) is compared one element at a time in a Java loop that returns false at the first mismatch, so the comparison is performed in steps and its running time reveals how many leading bytes or characters of a forged value are correct (the software form of CWE-1254). Reported: inside a for/while loop, if (a[i] != b[i]) or if (a.charAt(i) != b.charAt(i)) followed by return false on the same line or the next code line, when the compared names or the enclosing method's signature name a secret. Not reported: an accumulate-and-test loop (diff |= a[i] ^ b[i]), MessageDigest.isEqual, a loop that returns the index of the first difference, the same loop over values whose names and method do not say they are secret, and comments. Whole-value comparisons with equals/Arrays.equals/== are reported by VNX-CRYPTO-008 and VNX-385.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1254/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1254],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["timing", "comparison", "early-exit", "java", "cwe-1254"],
}

_msg := "Secret compared element by element with an early 'return false': the time taken reveals how much of the guess is right. Use MessageDigest.isEqual() or accumulate the differences (diff |= a[i] ^ b[i]) and test once"

_cmp_res := [
	`\bif\s*\(\s*([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*\]\s*!=\s*([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*\]\s*\)`,
	`\bif\s*\(\s*([A-Za-z_]\w*)\s*\.\s*charAt\s*\(\s*([A-Za-z_]\w*)\s*\)\s*!=\s*([A-Za-z_]\w*)\s*\.\s*charAt\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\)`,
]

# The identifier, split into its camelCase / snake_case words, contains a word
# that names a secret. Whole words, so tokens[] of a lexer, keys[] of a map,
# monkeyIds and authorList are not secrets.
_secret_words := {
	"mac", "hmac", "sig", "signature", "digest", "hash", "token", "secret", "password", "passwd",
	"pwd", "passcode", "passphrase", "pin", "key", "apikey", "otp", "totp", "hotp", "nonce",
	"csrf", "xsrf", "credential", "cookie", "session", "auth", "sid",
}

_secret_name(name) if {
	some w in regex.find_all_string_submatch_n(`[A-Z]?[a-z0-9]+|[A-Z]+`, name, -1)
	lower(w[0]) in _secret_words
}

# String literals blanked, so a sentence quoting the unsafe loop is not code.
_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

# return false right after the condition, or as the next code line (alone or
# after an opening brace, or after a lone brace line).
_early_false(lines, i, line) if regex.match(`\)\s*\{?\s*return\s+false\s*;`, line)

_early_false(lines, i, _) if {
	j := helpers.next_code_index(lines, i, 2)
	regex.match(`^\s*\{?\s*return\s+false\s*;`, lines[j])
}

_early_false(lines, i, _) if {
	j := helpers.next_code_index(lines, i, 2)
	regex.match(`^\s*\{\s*$`, lines[j])
	k := helpers.next_code_index(lines, j, 2)
	regex.match(`^\s*return\s+false\s*;`, lines[k])
}

# ok = false; break; : the loop stops at the first mismatch all the same.
_early_false(lines, i, _) if {
	w := concat("\n", array.slice(lines, i, min([count(lines), i + 4])))
	regex.match(`\b\w+\s*=\s*false\s*;\s*(?:\n\s*)?break\s*;`, w)
}

_in_loop(lines, i) if {
	some j in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`^\s*(\}\s*)?(for|while)\s*\(`, lines[j])
}

# The name of the nearest method declaration above line i.
_method_name(lines, i) := n if {
	ks := [j |
		some j in numbers.range(max([0, i - 25]), i - 1)
		regex.match(`^\s*(?:(?:public|private|protected|static|final|synchronized)\s+)*[\w<>\[\],]+\s+[A-Za-z_]\w*\s*\([^;]*$`, lines[j])
		not regex.match(`^\s*(?:if|for|while|switch|return|new|else|catch)\b`, lines[j])
	]
	count(ks) > 0
	n := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*\(`, lines[max(ks)], 1)[0][1]
}

_secret_context(lines, i, m) if _secret_name(m[1])

_secret_context(lines, i, m) if _secret_name(m[3])

_secret_context(lines, i, _) if _secret_name(_method_name(lines, i))

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "!=")
	regex.match(`return\s+false|break\s*;`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "!=")
	not helpers.is_comment_line(line)
	c := _code(line)
	some re in _cmp_res
	m := regex.find_all_string_submatch_n(re, c, 1)[0]
	m[2] == m[4]
	m[1] != m[3]
	_early_false(lines, i, c)
	_in_loop(lines, i)
	_secret_context(lines, i, m)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
