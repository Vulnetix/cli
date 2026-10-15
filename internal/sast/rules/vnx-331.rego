# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_331

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-331",
	"name": "Insufficient Entropy",
	"description": "A secret value is generated with too little randomness to resist guessing: fewer than 16 random bytes (128 bits) from a cryptographic generator, or a time-based or truncated UUID, for a value named as a token, secret, key, password, salt, session id, CSRF, API key, reset or invite value. Reported: Python secrets.token_bytes/token_hex/token_urlsafe(n) and os.urandom(n) with n < 16, uuid.uuid1() (timestamp and MAC address, not random) and uuid4().hex[:n] with n < 32 and str(uuid4())[:n] with n < 36; Node.js crypto.randomBytes(n) with n < 16; PHP random_bytes(n) and openssl_random_pseudo_bytes(n) with n < 16; Ruby SecureRandom.hex/base64/urlsafe_base64/random_bytes(n) with n < 16 (alphanumeric(n) counts characters and is not judged); Java a byte[] and Kotlin a ByteArray of fewer than 16 bytes named as a salt, key, token or secret and filled with nextBytes(). The security name must be on the same line (an assignment, keyword or dict key). Not reported: 16 bytes or more, the secrets defaults (32 bytes), short random values with no security name (file names, colours, trace ids), nonces and IVs (12-byte GCM nonces are correct), uuid4() in full, comments and test files. Weak (non-cryptographic) generators are reported by VNX-PY-005, VNX-JAVA-016 and VNX-338; small numeric ranges by VNX-334.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-331/",
	"languages": ["java", "kotlin", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [331],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["insufficient-entropy", "cwe-331", "crypto"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

# A name that marks a value as a secret. Nonces and IVs are excluded: their
# required size is the cipher's, not 128 bits.
_secret_re := `(?i)(token|secret|passw|pwd|api_?key|secret_?key|\bkey\b|_key\b|[a-z]Key\b|salt|session_?id|sessid|session_?key|csrf|xsrf|reset|invite|auth_?code|credential|cookie)`

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Secret generated with fewer than 128 bits of randomness (or from a time-based/truncated UUID); use at least 16 random bytes, e.g. secrets.token_urlsafe(32) or crypto.randomBytes(32)",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── byte-count calls: [extensions, gate, regex with the byte count in group 1] ──

_count_calls := [
	{"exts": {".py"}, "gate": "secrets", "re": `\b(?:secrets\.)?token_(?:bytes|hex|urlsafe)\(\s*(?:nbytes\s*=\s*)?(\d+)\s*\)`},
	{"exts": {".py"}, "gate": "urandom", "re": `\bos\.urandom\(\s*(\d+)\s*\)`},
	{"exts": _js_exts, "gate": "randomBytes", "re": `\brandomBytes\(\s*(\d+)\s*[,)]`},
	{"exts": {".php"}, "gate": "random", "re": `\b(?:random_bytes|openssl_random_pseudo_bytes)\(\s*(\d+)\s*[,)]`},
	{"exts": {".rb"}, "gate": "SecureRandom", "re": `\bSecureRandom\.(?:hex|base64|urlsafe_base64|random_bytes)\(\s*(\d+)\s*[,)]`},
]

# ── Kotlin: a short ByteArray secret filled by nextBytes() ──────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".kt")
	contains(content, "nextBytes")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ByteArray(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\b(?:val|var)\s+(\w+)\s*(?::\s*ByteArray\s*)?=\s*ByteArray\(\s*(\d+)\s*\)`, line, 1)
	count(m) > 0
	to_number(m[0][2]) < 16
	name := m[0][1]
	regex.match(_secret_re, name)
	regex.match(concat("", [`\.nextBytes\(\s*`, name, `\s*\)`]), content)
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	some c in _count_calls
	some ext in c.exts
	endswith(path, ext)
	contains(content, c.gate)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, c.gate)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(c.re, line, 1)
	count(m) > 0
	to_number(m[0][1]) < 16
	regex.match(_secret_re, _scrub(line))
	finding := _finding(path, i, line)
}

# ── Python: time-based or truncated UUID as a secret ────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "uuid")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "uuid")
	not helpers.is_comment_line(line)
	_weak_uuid(line)
	regex.match(_secret_re, line)
	finding := _finding(path, i, line)
}

_weak_uuid(line) if regex.match(`\buuid1\(\s*\)`, line)

_weak_uuid(line) if {
	m := regex.find_all_string_submatch_n(`\buuid4\(\s*\)\.hex\[\s*(?:0\s*)?:\s*(\d+)\s*\]`, line, 1)
	count(m) > 0
	to_number(m[0][1]) < 32
}

# str(uuid.uuid4())[:N]: the 36-character hyphenated form, truncated
_weak_uuid(line) if {
	m := regex.find_all_string_submatch_n(`\bstr\(\s*(?:uuid\.)?uuid4\(\s*\)\s*\)\[\s*(?:0\s*)?:\s*(\d+)\s*\]`, line, 1)
	count(m) > 0
	to_number(m[0][1]) < 36
}

# ── Java: a short byte[] secret filled by nextBytes() ───────────────────

findings contains finding if {
	some path, content in input.file_contents
	some ext in {".java", ".kt"}
	endswith(path, ext)
	contains(content, "nextBytes")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "new byte[")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\bbyte\[\]\s+(\w+)\s*=\s*new\s+byte\[\s*(\d+)\s*\]`, line, 1)
	count(m) > 0
	to_number(m[0][2]) < 16
	name := m[0][1]
	regex.match(_secret_re, name)
	regex.match(concat("", [`\.nextBytes\(\s*`, name, `\s*\)`]), content)
	finding := _finding(path, i, line)
}

# The generator's own name ("secrets", "token_hex") is not a security name.
_scrub(line) := regex.replace(line, `\bsecrets\.|\btoken_(?:bytes|hex|urlsafe)\b`, "")
