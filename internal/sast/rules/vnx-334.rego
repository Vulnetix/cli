# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_334

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-334",
	"name": "Small Space of Random Values",
	"description": "A secret is drawn as a random integer from a range of fewer than 2^32 values, so it can be guessed or enumerated however good the generator is. Reported when the same line (or the line above, when the assignment wraps after `=`) names the value as a token, secret, key, password, salt, session id, CSRF, API key, reset or invite value: Python random.randint(a, b)/randrange(..., b) and secrets.randbelow(n) with a literal bound below 2^32 (digits, 1_000_000, 10**k, 2**k), secrets.randbits/getrandbits(k) with k < 32; Java/Kotlin nextInt() and nextInt(n) (32 bits at most, from SecureRandom too); Node.js crypto.randomInt([min,] max) with a literal max below 2^32 and Math.floor([offset +] Math.random() * N); PHP random_int/mt_rand/rand(a, b); Ruby SecureRandom.random_number(n) and rand(n). Not reported: bounds from variables or expressions, ranges of 2^32 and more, random integers with no security name (indexes, delays, ports, colours, dice) or whose name is a count, length, size or index of tokens or keys (tokenCount, key_index), one-time passcodes and PINs (a 6-digit OTP is the norm and is protected by expiry and attempt limits), comments and test files. Use 128 bits from a CSPRNG for tokens (secrets.token_urlsafe(32), crypto.randomBytes(32)). A non-cryptographic generator for a secret is reported by VNX-PY-005 and VNX-JAVA-016 as well.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-334/",
	"languages": ["java", "kotlin", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [334],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["small-random-space", "cwe-334", "crypto"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_secret_re := `(?i)(token|secret|passw|pwd|api_?key|secret_?key|\bkey\b|_key\b|[a-z]Key\b|salt|session_?id|sessid|session_?key|csrf|xsrf|reset|invite|auth_?code|credential|cookie)`

# The generator's own name is not a security name, and neither is a count,
# length, size or index of tokens or keys (tokenCount, key_index).
_scrub(line) := regex.replace(line, `\bsecrets\.|\btoken_(?:bytes|hex|urlsafe)\b|\btokenBytes\b|\b(?i:\w*(?:count|counts|len|length|size|index|idx|num|limit|max|min|offset|pos))\b`, "")

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Secret drawn from fewer than 2^32 possible values; generate at least 128 random bits (secrets.token_urlsafe(32), crypto.randomBytes(32), SecureRandom.nextBytes on 16+ bytes)",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# A literal bound below 2^32.
_small(expr) if {
	e := trim_space(expr)
	regex.match(`^[0-9_]+$`, e)
	to_number(replace(e, "_", "")) < 4294967296
}

_small(expr) if {
	m := regex.find_all_string_submatch_n(`^10\s*\*\*\s*(\d+)$`, trim_space(expr), 1)
	count(m) > 0
	to_number(m[0][1]) <= 9
}

_small(expr) if {
	m := regex.find_all_string_submatch_n(`^2\s*\*\*\s*(\d+)$`, trim_space(expr), 1)
	count(m) > 0
	to_number(m[0][1]) < 32
}

_small(expr) if {
	m := regex.find_all_string_submatch_n(`^[1-9](?:\.\d+)?e(\d+)$`, trim_space(expr), 1)
	count(m) > 0
	to_number(m[0][1]) <= 9
}

_small_bits(expr) if {
	e := trim_space(expr)
	regex.match(`^\d+$`, e)
	to_number(e) < 32
}

# ── call shapes: [extensions, gate, regex, kind]; the bound is the last group ──

_calls := [
	{"exts": {".py"}, "gate": "rand", "re": `\b(?:random\.|SystemRandom\(\)\.|\b)randint\(\s*[^,()]+,\s*([^,()]+)\)`, "bits": false},
	{"exts": {".py"}, "gate": "rand", "re": `\b(?:random\.|SystemRandom\(\)\.)randrange\(\s*(?:[^,()]+,\s*)?([^,()]+?)\s*(?:,\s*[^,()]+)?\)`, "bits": false},
	{"exts": {".py"}, "gate": "randbelow", "re": `\b(?:secrets\.)?randbelow\(\s*([^,()]+)\)`, "bits": false},
	{"exts": {".py"}, "gate": "randbits", "re": `\b(?:secrets\.|random\.)(?:randbits|getrandbits)\(\s*([^,()]+)\)`, "bits": true},
	{"exts": _js_exts, "gate": "randomInt", "re": `\brandomInt\(\s*(?:[^,()]+,\s*)?([^,()]+)\)`, "bits": false},
	{"exts": {".php"}, "gate": "rand", "re": `\b(?:random_int|mt_rand|rand)\(\s*[^,()]+,\s*([^,()]+)\)`, "bits": false},
	{"exts": {".rb"}, "gate": "random_number", "re": `\bSecureRandom\.random_number\(\s*([^,()]+)\)`, "bits": false},
	{"exts": {".rb"}, "gate": "rand(", "re": `(?:^|[^\w.])(?:Kernel\.|Random\.)?rand\(\s*([^,()]+)\)`, "bits": false},
	{"exts": _js_exts, "gate": "Math.random","re": `\bMath\.floor\(\s*(?:\d[\d_]*\s*\+\s*)?Math\.random\(\)\s*\*\s*([^()]+?)\s*\)`, "bits": false},
]

_bound_ok(false, expr) if _small(expr)

_bound_ok(true, expr) if _small_bits(expr)

# The text that names the value: the call line, plus the line above when the
# assignment was wrapped after `=` or an opening parenthesis.
_named(lines, i, line) := concat("\n", [lines[i - 1], line]) if {
	i > 0
	regex.match(`(=|\()\s*$`, lines[i - 1])
	not helpers.is_comment_line(lines[i - 1])
} else := line

# One-time passcodes and PINs are short by design.
_otp(line) if regex.match(`(?i)\botp\b|_otp\b|otp_|passcode|\bpin\b|_pin\b|pin_|verification_?code|captcha`, line)

findings contains finding if {
	some path, content in input.file_contents
	some c in _calls
	some ext in c.exts
	endswith(path, ext)
	contains(content, c.gate)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, c.gate)
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(c.re, line, -1)
	_bound_ok(c.bits, m[1])
	regex.match(_secret_re, _scrub(_named(lines, i, line)))
	not _otp(_named(lines, i, line))
	finding := _finding(path, i, line)
}

# ── Java/Kotlin: nextInt() is 32 bits at most ───────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	some ext in {".java", ".kt"}
	endswith(path, ext)
	contains(content, "nextInt(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "nextInt(")
	not helpers.is_comment_line(line)
	regex.match(`\.nextInt\(\s*(\)|\d[\d_]*\s*\)|\d[\d_]*\s*,\s*\d[\d_]*\s*\))`, line)
	regex.match(_secret_re, _scrub(_named(lines, i, line)))
	not _otp(_named(lines, i, line))
	finding := _finding(path, i, line)
}
