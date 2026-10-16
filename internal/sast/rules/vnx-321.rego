# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_321

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-321",
	"name": "Hard-coded cryptographic key",
	"description": "A cryptographic key is written into the source, so anyone with the code can decrypt or forge what it protects. Reported, in Python, JavaScript/TypeScript, Java and Go: a variable, constant, field or config key named as a cryptographic key (secret_key, private_key, encryption_key, signing_key, hmac_key, aes_key, des_key, master_key, crypto_key, cipher_key, enc_key, jwt_secret) assigned a literal that looks like key material (at least 16 characters, no spaces unless it is an inline PEM private key, not a placeholder or an environment lookup), including config subscripts such as app.config[\"SECRET_KEY\"]; a literal of 8 or more characters assigned to any variable that one of the key APIs below consumes as its key within 15 lines (key = b\"...\" then AES.new(key, ...), byte[] keyBytes = \"...\".getBytes() then new SecretKeySpec(keyBytes, ...)); and a string or byte literal passed straight to a key API, including JWT HMAC secrets (jwt.sign/encode/verify/decode with a literal secret, Algorithm.HMAC256(\"...\")): pycryptodome AES/DES/ARC4 .new(), cryptography Fernet/AESGCM/ChaCha20Poly1305/algorithms.AES, hmac.new, Node crypto.createCipheriv/createDecipheriv/createHmac and CryptoJS AES/DES/TripleDES/Rabbit/RC4/Hmac*, Java new SecretKeySpec(\"...\".getBytes(), ...) and byte-array literals, Go aes.NewCipher/des.NewCipher/hmac.New with []byte(\"...\"). In JavaScript and TypeScript, a literal key given to jwt.sign()/jwt.verify() or crypto.createHmac(alg, '...'), a config property named for a JWT or session secret (jwtSecret, jwt_secret) set to a literal, and a constant holding a literal that one of those calls uses as its key are reported by VNX-NODE-019 instead, so one key is one finding (in examples/ directories, which VNX-NODE-019 skips, they stay here). Not reported: names that merely end in key (map keys, cache keys, loop variables), API keys and passwords (credentials, covered by the secret rules), placeholders (changeme, your-..., example, xxxx, ${...}), environment and config lookups, short non-key strings assigned to key names, test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-321/",
	"languages": ["go", "java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [321],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "hardcoded-key", "cwe-321"],
}

_exts := {".py", ".java", ".js", ".ts", ".go", ".mjs", ".cjs", ".jsx", ".tsx"}

_ext_ok(path) if {
	some e in _exts
	endswith(path, e)
	not endswith(path, ".min.js")
}

# The name says it is a cryptographic key, as a whole identifier segment.
_key_name := `(?i)\b(?:\w*[_\.\-])?(?:secret_?key|private_?key|encryption_?key|signing_?key|sign_?key|hmac_?key|aes_?key|des_?key|master_?key|crypto_?key|cipher_?key|enc_?key|jwt_?secret)\b["']?\]?\s*(?::=|=|:)\s*(?:\[\]byte\(\s*)?(?:b|r|u)?["'\x60]([^"'\x60]*)["'\x60]`

# A literal handed straight to a key API.
_key_api := [
	`\b(?:AES|DES|DES3|ARC4|Blowfish|ChaCha20|Salsa20)\.new\(\s*b?["']([^"']+)["']`,
	`\b(?:Fernet|AESGCM|AESCCM|AESSIV|ChaCha20Poly1305|algorithms\.AES|algorithms\.TripleDES)\(\s*b?["']([^"']+)["']`,
	`\bhmac\.new\(\s*b?["']([^"']+)["']`,
	"\\bcreate(?:Cipheriv|Decipheriv)\\(\\s*['\"`][^'\"`]+['\"`]\\s*,\\s*(?:Buffer\\.from\\(\\s*)?['\"`]([^'\"`]+)['\"`]",
	"\\bcreateHmac\\(\\s*['\"`][^'\"`]+['\"`]\\s*,\\s*['\"`]([^'\"`]+)['\"`]",
	"\\bCryptoJS\\.(?:AES|DES|TripleDES|Rabbit|RC4|RC4Drop)\\.(?:encrypt|decrypt)\\([^,]+,\\s*['\"`]([^'\"`]+)['\"`]",
	"\\bCryptoJS\\.Hmac\\w+\\([^,]+,\\s*['\"`]([^'\"`]+)['\"`]",
	`\bnew\s+SecretKeySpec\(\s*"([^"]+)"\s*\.getBytes`,
	`\bnew\s+SecretKeySpec\(\s*new\s+byte\s*\[\s*\]\s*\{(\s*\(?\s*(?:byte\)\s*)?-?(?:0x)?[0-9A-Fa-f]+[^}]*)\}`,
	"\\b(?:aes|des)\\.New(?:TripleDES)?Cipher\\(\\s*\\[\\]byte\\(\\s*[\"`]([^\"`]+)[\"`]",
	"\\bhmac\\.New\\([^,]+,\\s*\\[\\]byte\\(\\s*[\"`]([^\"`]+)[\"`]",
	"\\bjwt\\.(?:sign|encode|verify|decode)\\(\\s*(?:\\{[^}]*\\}|[^,()]+(?:\\([^()]*\\))?)\\s*,\\s*b?['\"`]([^'\"`]+)['\"`]",
	`\bAlgorithm\.HMAC(?:256|384|512)\(\s*"([^"]+)"`,
]

# The same APIs taking the key from a variable, as a prefix before the name.
_key_sink_prefix := [
	`\bnew\s+SecretKeySpec\(\s*`,
	`\b(?:AES|DES|DES3|ARC4|Blowfish|ChaCha20|Salsa20)\.new\(\s*`,
	`\b(?:Fernet|AESGCM|AESCCM|AESSIV|ChaCha20Poly1305|algorithms\.AES|algorithms\.TripleDES)\(\s*`,
	`\bhmac\.new\(\s*`,
	`\bcreate(?:Cipheriv|Decipheriv)\(\s*[^,]+,\s*(?:Buffer\.from\(\s*)?`,
	`\bcreateHmac\(\s*[^,]+,\s*`,
	`\b(?:aes|des)\.New(?:TripleDES)?Cipher\(\s*`,
	`\bhmac\.New\([^,]+,\s*`,
	`\bCryptoJS\.(?:AES|DES|TripleDES|Rabbit|RC4|RC4Drop)\.(?:encrypt|decrypt)\([^,]+,\s*`,
	`\bjwt\.(?:sign|encode|verify|decode)\(\s*(?:\{[^}]*\}|[^,()]+(?:\([^()]*\))?)\s*,\s*`,
	`\bAlgorithm\.HMAC(?:256|384|512)\(\s*`,
]

# name = "literal" (optionally []byte(...), Buffer.from(...), b"...", .getBytes()).
_lit_assign := "^\\s*(?:[\\w\\[\\]<>.]+\\s+)*?([A-Za-z_]\\w*)\\s*(?::\\s*[\\w\\[\\]]+)?\\s*(?::=|=)\\s*(?:\\[\\]byte\\(\\s*|Buffer\\.from\\(\\s*)?(?:b|r|u)?['\"`]([^'\"`]{8,})['\"`]"

# A literal assigned to a variable that a key API consumes within 15 lines.
findings contains finding if {
	some path, content in input.file_contents
	_ext_ok(path)
	not helpers.is_test_path(path)
	_api_gate(content)
	lines := split(content, "\n")
	some j, line in lines
	regex.match("=\\s*(?:\\[\\]byte\\(\\s*|Buffer\\.from\\(\\s*)?(?:b|r|u)?['\"`][^'\"`]{8,}['\"`]", line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_lit_assign, line, 1)
	count(m) > 0
	v := m[0][1]
	not _placeholder(m[0][2])
	some k in numbers.range(j + 1, min([count(lines) - 1, j + 15]))
	_api_gate(lines[k])
	some p in _key_sink_prefix
	regex.match(concat("", [p, v, `\b`]), lines[k])
	not _handed_over(path, lines, line)
	finding := _finding(path, j, line)
}

# Not key material: placeholders, templates, lookups.
_placeholder(v) if regex.match(`(?i)(changeme|change_me|your[_\-]|example|placeholder|xxxx|todo|dummy|sample|<|>|\$\{|\{\{|%[sdv]|process\.env|os\.environ|getenv)`, v)

# Key material has no spaces, except an inline PEM private key.
_key_shaped(v) if not contains(v, " ")

_key_shaped(v) if regex.match(`^-----BEGIN [A-Z ]*PRIVATE KEY-----`, v)

_api_lits := [".new(", "Fernet(", "AESGCM(", "AESCCM(", "AESSIV(", "Poly1305(", "algorithms.", "Cipheriv(", "createHmac(", "CryptoJS.", "SecretKeySpec(", "NewCipher(", "NewTripleDESCipher(", "hmac.New(", "jwt.sign(", "jwt.encode(", "jwt.verify(", "jwt.decode(", "Algorithm.HMAC"]

_api_gate(s) if {
	some x in _api_lits
	contains(s, x)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Hard-coded cryptographic key: load it from a secrets manager or KMS and rotate the exposed one",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains finding if {
	some path, content in input.file_contents
	_ext_ok(path)
	not helpers.is_test_path(path)
	# Case-sensitive gate: a case-insensitive alternation over every file is
	# what made this rule slow.
	regex.match(`(?:[Kk]ey|KEY|[Ss]ecret|SECRET)["']?\]?\s*(?::=|=|:)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:[Kk]ey|KEY|[Ss]ecret|SECRET)`, line)
	regex.match(`(?i)(secret_?key|private_?key|encryption_?key|sign(ing)?_?key|hmac_?key|aes_?key|des_?key|master_?key|crypto_?key|cipher_?key|enc_?key|jwt_?secret)`, line)
	not helpers.is_comment_line(line)
	some hit in regex.find_all_string_submatch_n(_key_name, line, 3)
	value := hit[1]
	count(value) >= 16
	_key_shaped(value)
	not _placeholder(value)
	not _handed_over(path, lines, line)
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	_ext_ok(path)
	not helpers.is_test_path(path)
	_api_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	_api_gate(line)
	not helpers.is_comment_line(line)
	some re in _key_api
	some hit in regex.find_all_string_submatch_n(re, line, 2)
	value := hit[1]
	trim_space(value) != ""
	not _placeholder(value)
	not regex.match(`^\s*['"\x60]`, value)
	not _handed_over(path, lines, line)
	finding := _finding(path, i, line)
}

# ── Handed over to VNX-NODE-019 ─────────────────────────────────────────
# In JavaScript and TypeScript, VNX-NODE-019 reports a literal JWT, session
# or HMAC signing key: the key argument of jwt.sign()/jwt.verify() and
# crypto.createHmac(alg, '...'), a config property named jwtSecret and the
# like, and a const holding a literal that one of those calls uses as its
# key. Those lines are left to it so one key is one finding. The shapes below
# are VNX-NODE-019's own; it skips examples/ directories, so they stay here.

_n19_path(path) if {
	regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)
	not regex.match(`(^|/)examples?/`, path)
}

# Every non-empty string literal becomes 'x', as VNX-NODE-019 normalises.
_n19_norm(line) := regex.replace(
	regex.replace(line, "''|\"\"|``", "\u0001"),
	"'(?:[^'\\\\]|\\\\.)+'|\"(?:[^\"\\\\]|\\\\.)+\"|`[^`$]+`",
	"'x'",
)

_n19_first := `(?:\{[^{}]*\}|[^,(){}]+(?:\([^()]*\))?)`

_n19_jwt := `\b(?i:jwt|jsonwebtoken)\s*\.\s*(?:sign|verify)\s*\(\s*`

_n19_lit_res := [
	concat("", [_n19_jwt, _n19_first, `\s*,\s*'x'\s*[,)]`]),
	`\bcreateHmac\s*\(\s*[^,()]+,\s*'x'\s*\)`,
	concat("", [
		`(?i)(?:^|[\s{,(])['"]?((?:jwt|session|cookie|token|auth|signing|access[_-]?token|refresh[_-]?token)[_-]?secret(?:[_-]?key)?|jwt[_-]?(?:signing[_-]?)?key)['"]?\s*(?::|=)\s*`,
		`'x'\s*[,;}]?\s*$`,
	]),
]

_n19_ident_res := [
	concat("", [_n19_jwt, _n19_first, `\s*,\s*([A-Za-z_$][\w$]*)\s*[,)]`]),
	`\bcreateHmac\s*\(\s*[^,()]+,\s*([A-Za-z_$][\w$]*)\s*\)`,
]

_handed_over(path, _, line) if {
	_n19_path(path)
	n := _n19_norm(line)
	some re in _n19_lit_res
	regex.match(re, n)
}

# const NAME = '...' where a jwt.sign/verify or createHmac call uses NAME.
_handed_over(path, lines, line) if {
	_n19_path(path)
	regex.match(`^\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*(?::\s*\w+\s*)?=\s*'x'\s*;?\s*$`, _n19_norm(line))
	m := regex.find_all_string_submatch_n(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)`, line, 1)
	name := m[0][1]
	some k, l in lines
	regex.match(`\.\s*(?:sign|verify)\s*\(|createHmac`, l)
	not helpers.is_comment_line(l)
	w := _n19_norm(helpers.code_window(lines, k, 0, 3))
	some re in _n19_ident_res
	some hit in regex.find_all_string_submatch_n(re, w, -1)
	hit[1] == name
}
