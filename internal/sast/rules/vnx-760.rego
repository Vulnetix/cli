# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_760

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-760",
	"name": "Password hash or KDF uses a constant or predictable salt",
	"description": "A password hash or key derivation is salted with a value an attacker already knows, so one precomputed table covers every account. Reported: (1) a string, byte-string, template, []byte(\"...\"), \"...\".getBytes(), Buffer.from('...') or literal byte-array constant written in the salt position of hashlib.pbkdf2_hmac, hashlib.scrypt(salt=...), PBKDF2HMAC(salt=...) (also with salt=b\"...\" on its own line inside a call opened up to six lines above), Java new PBEKeySpec(pw, <salt>, ...)/PBEParameterSpec, Go pbkdf2.Key/scrypt.Key/argon2.Key/argon2.IDKey, Node crypto.pbkdf2/pbkdf2Sync/scrypt/scryptSync, and a literal \"$2...\" bcrypt salt given to bcrypt.hashpw/BCrypt.hashpw/bcrypt.hash; (2) a variable whose name says salt, assigned such a constant, that is then used on a line calling a password hash, KDF or digest (anywhere in the file for a top-level or static constant, within the next 30 lines and before any reassignment for a local); (3) the user's own username, email or id used as the pbkdf2_hmac salt. Not reported: salts from os.urandom, secrets, SecureRandom, crypto/rand, crypto.randomBytes or gensalt(), a stored hash passed back to hashpw to verify, salt constants used for something else (itsdangerous/signing namespaces, column names, lengths, a key in dict.update({SALT_FIELD: ...})), comments and test files. Constant IVs and nonces are VNX-CRYPTO-010.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-760/",
	"languages": ["go", "java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [760],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["password-hash", "predictable-salt", "cwe-760"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "js" if regex.match(`\.(?:js|mjs|cjs|ts|jsx|tsx)$`, path)

_gate := `(?i)salt|pbkdf2|scrypt|argon2|PBEKeySpec|PBEParameterSpec|hashpw|bcrypt\.hash`

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	_constant_salt(lang, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Password hash or KDF salted with a constant or predictable value: one precomputed table covers every account. Generate a random salt per password (os.urandom, SecureRandom, crypto/rand, randomBytes, gensalt) and store it with the hash",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── (1) a constant written in the salt position ──────────────────────────
_lit := `(?:b?"[^"]*"|b?'[^']*'|\x60[^\x60$]*\x60)`

_inline_salt("py") := [
	concat("", [`\bpbkdf2_hmac\(\s*[^,]+,\s*[^,]+,\s*`, _lit]),
	concat("", [`\b(?:hashlib\.scrypt|PBKDF2HMAC|Scrypt)\([^)]*\bsalt\s*=\s*`, _lit]),
	`\bbcrypt\.hashpw\([^,]+,\s*b?["']\$2`,
	`\bpbkdf2_hmac\(\s*[^,]+,\s*[^,]+,\s*[\w.]*(?i:username|email|user_?id|login)\b`,
]

_inline_salt("java") := [
	`\bnew\s+PBEKeySpec\([^,]+,\s*(?:"[^"]*"|new\s+byte\s*\[\]\s*\{)`,
	`\bnew\s+PBEParameterSpec\(\s*(?:"[^"]*"|new\s+byte\s*\[\]\s*\{)`,
	`\bBCrypt\.hashpw\([^,]+,\s*"\$2`,
]

_inline_salt("go") := [`\b(?:pbkdf2\.Key|scrypt\.Key|argon2\.I?D?Key)\([^,]+,\s*\[\]byte\(\s*"`]

_inline_salt("js") := [
	concat("", [`\b(?:pbkdf2|pbkdf2Sync|scrypt|scryptSync)\(\s*[^,]+,\s*`, _lit]),
	`\bbcrypt(?:js)?\.hash(?:Sync)?\([^,]+,\s*['"\x60]\$2`,
]

_constant_salt(lang, _, _, line) if {
	some re in _inline_salt(lang)
	regex.match(re, line)
}

# PBKDF2HMAC(\n    algorithm=...,\n    salt=b"constant",\n ...): the keyword
# argument on its own line, inside a KDF call opened a few lines above.
_constant_salt("py", lines, i, line) if {
	regex.match(concat("", [`^\s*salt\s*=\s*`, _lit, `\s*,?\s*(?:#.*)?$`]), line)
	some j in numbers.range(max([0, i - 6]), i - 1)
	j >= max([0, i - 6])
	j <= i - 1
	regex.match(`\b(?:PBKDF2HMAC|Scrypt|hashlib\.scrypt|Argon2id|hash_secret_raw|hash_secret)\(\s*$|\b(?:PBKDF2HMAC|Scrypt|hashlib\.scrypt)\([^)]*,\s*$`, lines[j])
}

# ── (2) a salt-named constant that reaches a hash or KDF call ─────────────
_const_value := `(?:b?"[^"]*"|b?'[^']*'|\x60[^\x60$]*\x60|\[\]byte\(\s*"[^"]*"\s*\)|"[^"]*"\.getBytes\([^)]*\)|\{\s*-?\d[\d,\s-]*\}|new\s+byte\s*\[\]\s*\{[^}]*\}|Buffer\.from\(\s*['"][^'"]*['"]\s*\))`

_decl_re := concat("", [
	`^(\s*)(?:(?:private|public|protected|static|final|const|var|let|readonly|export)\s+)*`,
	`(?:(?:byte\s*\[\]|String|char\s*\[\])\s+)?`,
	`([A-Za-z_]\w*)\s*(?::\s*[\w\[\]]+\s*)?(?::=|=)\s*`,
	_const_value,
	`\s*;?\s*$`,
])

_use_re := `(?i)pbkdf2|scrypt|argon2|bcrypt|PBEKeySpec|PBEParameterSpec|hashlib\.|MessageDigest|\.digest\(|createHash|sha\d+\.(?:Sum|New)|hash_?password|\bcrypt\(`

# The constant reaches a hash or KDF on line l: a call named above, or a digest
# fed the constant directly (md.update(SALT), h.update(SALT.getBytes())). A
# dict.update({SALT_FIELD: ...}) mentions the name without hashing it.
_hash_use(l, name) if {
	regex.match(_use_re, l)
	regex.match(concat("", [`\b`, name, `\b`]), l)
}

_hash_use(l, name) if {
	regex.match(concat("", [`\.update\([^{=]*\b`, name, `\b`]), l)
	not regex.match(`\.update\(\s*(?:\{|\*\*|\w+\s*=[^=])`, l)
}

_constant_salt(_, lines, i, line) if {
	m := regex.find_all_string_submatch_n(_decl_re, line, 1)
	count(m) > 0
	name := m[0][2]
	regex.match(`(?i)salt`, name)
	_used_in_hash(lines, i, name, _file_wide(m[0][1], line))
}

_file_wide(indent, line) := true if {
	_top_or_static(indent, line)
} else := false

_top_or_static(indent, _) if indent == ""

_top_or_static(_, line) if regex.match(`\bstatic\b`, line)

_used_in_hash(lines, i, name, true) if {
	some j, l in lines
	j != i
	contains(l, name)
	_hash_use(l, name)
	not helpers.is_comment_line(l)
}

_used_in_hash(lines, i, name, false) if {
	reassign := concat("", [`\b`, name, `\s*(?::=|=)[^=]`])
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 30]))
	j >= i + 1
	l := lines[j]
	contains(l, name)
	_hash_use(l, name)
	not helpers.is_comment_line(l)
	not _reassigned_between(lines, i, j, reassign)
}

_reassigned_between(lines, i, j, reassign) if {
	some k in numbers.range(i + 1, j)
	k >= i + 1
	k <= j
	regex.match(reassign, lines[k])
}
