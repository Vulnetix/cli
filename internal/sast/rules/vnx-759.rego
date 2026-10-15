# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_759

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-759",
	"name": "Password hashed with a one-way hash and no salt",
	"description": "A password is passed straight into a fast general-purpose digest with no salt, so equal passwords get equal hashes and a precomputed table recovers them. Reported, when the hashed argument names a password (password, passwd, passphrase, pwd, pw, $pass, $pass_new, getPassword(), a subscript or .get() keyed by a password field such as form[\"new_password\"] or request.json.get(\"password\")) or a variable assigned from one a few lines above: Python hashlib.md5/sha1/sha224/sha256/sha384/sha512/sha3_*/blake2*/new(...) (also from-imported) and <hashlib object>.update(password); Java MessageDigest <md>.digest(password...)/<md>.update(password...) and MessageDigest.getInstance(...).digest(password...), commons-codec DigestUtils.md5Hex/sha1Hex/sha256Hex/... and Guava Hashing.md5()/sha1()/sha256()/sha512().hashString/hashBytes; PHP md5()/sha1()/crc32()/hash('<alg>', ...); Node crypto.createHash(...).update(password) on one line, as a chained call split over lines, or through a variable (const h = crypto.createHash(...); h.update(password)). A call argument split onto the next line is followed. Not reported: an argument or a neighbouring update() that mixes in a salt or pepper, password KDFs (pbkdf2_hmac, scrypt, bcrypt, argon2, PBEKeySpec, password_hash, scryptSync), HMAC, digests of tokens, nonces, password-reset values, file contents or other non-password data, string literals and comments. Weak iteration counts and broken algorithms are other rules (VNX-CRYPTO-007, VNX-327).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-759/",
	"languages": ["java", "python", "php", "node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [759],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["password-hash", "unsalted", "cwe-759"],
}

# A call's argument list, one level of nested parentheses deep.
_args := `\(([^()]*(?:\([^()]*\)[^()]*)*)\)`

_pw_re := `(?i)(?:passw(?:or)?d|passwd|passphrase|\bpwd\b|\bpw\b|\$pass\w*|\bpass\b)`

_salted_re := `(?i)salt|pepper|token|nonce|reset`

_strip_strings(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "js" if regex.match(`\.(?:js|mjs|cjs|ts|jsx|tsx)$`, path)

_gate("py") := `hashlib`

_gate("java") := `MessageDigest|DigestUtils|Hashing\.`

_gate("php") := `(?i)\b(?:md5|sha1|crc32|hash)\s*\(`

_gate("js") := `createHash\(`

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate(lang), content)
	regex.match(_pw_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_pw_re, line)
	not helpers.is_comment_line(line)
	some k in numbers.range(1, 13)
	k >= 1
	k <= 13
	some args in _hashed_args(k, lang, lines, i, _src(lang, line), content)
	_is_password(lines, i, args)
	not regex.match(_salted_re, args)
	not _salt_mixed_nearby(lang, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Password hashed with an unsalted fast digest: equal passwords give equal hashes. Use bcrypt, scrypt, Argon2 or PBKDF2 with a random per-password salt",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_is_password(_, _, args) if regex.match(_pw_re, _strip_strings(args))

# PHP superglobal keyed by a password field: $_POST['password'].
_is_password(_, _, args) if regex.match(`\$_(?:POST|GET|REQUEST)\[\s*['"]\w*(?i:pass|pwd)\w*['"]`, args)

# pw = request.form["password"]; hashlib.md5(pw.encode())
_is_password(lines, i, args) if {
	some v in helpers.tainted_names(lines, i, 8, _pw_re)
	regex.match(concat("", [`\b`, v, `\b`]), _strip_strings(args))
}

# ── Python ────────────────────────────────────────────────────────────────
_py_hash := `\bhashlib\.(?:md5|sha1|sha224|sha256|sha384|sha512|sha3_\d+|blake2[bs]|new)\s*`

_hashed_args(1, "py", _, _, line, _) := {a |
	some m in regex.find_all_string_submatch_n(concat("", [_py_hash, _args]), line, -1)
	a := m[1]
}

_hashed_args(2, "py", _, _, line, content) := {a |
	regex.match(`from\s+hashlib\s+import`, content)
	some m in regex.find_all_string_submatch_n(concat("", [`(?:^|[^.\w])(?:md5|sha1|sha224|sha256|sha384|sha512)\s*`, _args]), line, -1)
	a := m[1]
}

# h = hashlib.sha256(); h.update(password)
_hashed_args(3, "py", _, _, line, content) := {a |
	some m in regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\.update\s*`, _args]), line, -1)
	regex.match(concat("", [`\b`, m[1], `\s*=\s*hashlib\.`]), content)
	a := m[2]
}

# hashlib.sha256(\n    password.encode()\n)
_hashed_args(4, "py", lines, i, line, _) := {trim_space(line) |
	i > 0
	regex.match(concat("", [_py_hash, `\(\s*$`]), lines[i - 1])
}

# ── Java ──────────────────────────────────────────────────────────────────
_hashed_args(5, "java", _, _, line, content) := {a |
	some m in regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\.(?:digest|update)\s*`, _args]), line, -1)
	_is_message_digest(m[1], content)
	a := m[2]
}

_hashed_args(6, "java", _, _, line, _) := {a |
	some m in regex.find_all_string_submatch_n(concat("", [`MessageDigest\.getInstance\([^)]*\)\s*\.digest\s*`, _args]), line, -1)
	a := m[1]
}

_hashed_args(7, "java", _, _, line, _) := {a |
	some m in regex.find_all_string_submatch_n(concat("", [`\bDigestUtils\.(?:md2|md5|sha|sha1|sha224|sha256|sha384|sha512|sha3_\d+)(?:Hex)?\s*`, _args]), line, -1)
	a := m[1]
}

_hashed_args(8, "java", _, _, line, _) := {a |
	some m in regex.find_all_string_submatch_n(concat("", [`\bHashing\.(?:md5|sha1|sha256|sha384|sha512)\(\)\s*\.hash(?:String|Bytes|UnencodedChars)\s*`, _args]), line, -1)
	a := m[1]
}

_is_message_digest(name, content) if regex.match(concat("", [`MessageDigest\s+`, name, `\b`]), content)

_is_message_digest(name, content) if regex.match(concat("", [`\b`, name, `\s*=\s*MessageDigest\.getInstance`]), content)

# ── PHP ───────────────────────────────────────────────────────────────────
_hashed_args(9, "php", _, _, line, _) := {a |
	some m in regex.find_all_string_submatch_n(concat("", [`(?i)(?:^|[^\w>:$])(?:md5|sha1|crc32)\s*`, _args]), line, -1)
	a := m[1]
}

_hashed_args(10, "php", _, _, line, _) := {a |
	some m in regex.find_all_string_submatch_n(`(?i)(?:^|[^\w>:$])hash\s*\(\s*['"][\w/-]+['"]\s*,\s*([^()]*(?:\([^()]*\)[^()]*)*)\)`, line, -1)
	a := m[1]
}

# ── Node ──────────────────────────────────────────────────────────────────
_hashed_args(11, "js", _, _, line, _) := {a |
	some m in regex.find_all_string_submatch_n(concat("", [`createHash\([^)]*\)\s*\.update\s*`, _args]), line, -1)
	a := m[1]
}

# const h = crypto.createHash('sha256'); h.update(password)
_hashed_args(13, "js", _, _, line, content) := {a |
	some m in regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_$][\w$]*)\.update\s*`, _args]), line, -1)
	regex.match(concat("", [`\b`, m[1], `\s*=\s*(?:[\w.]+\.)?createHash\(`]), content)
	a := m[2]
}

_hashed_args(12, "js", lines, i, line, _) := {a |
	i > 0
	regex.match(`^\s*\.update\s*\(`, line)
	some j in numbers.range(max([0, i - 2]), i - 1)
	j >= max([0, i - 2])
	j <= i - 1
	contains(lines[j], "createHash(")
	some m in regex.find_all_string_submatch_n(concat("", [`\.update\s*`, _args]), line, 1)
	a := m[1]
}

# A salt fed to the same digest just before or after the password.
_salt_mixed_nearby(lang, lines, i, _) if {
	lang in {"py", "java", "js"}
	some j in numbers.range(max([0, i - 5]), min([count(lines) - 1, i + 3]))
	j >= max([0, i - 5])
	j != i
	regex.match(`\.update\s*\(`, lines[j])
	regex.match(`(?i)salt|pepper`, lines[j])
}

# String literals are blanked outside PHP, so a call written inside a message
# is not a call. PHP keeps them: $_POST['password'] names the field.
_src("php", line) := line

_src(lang, line) := _strip_strings(_keep_pw_keys(line)) if lang != "php"

# A subscript or .get() keyed by a password field names the password even
# though it is a string: form["new_password"], request.json.get("password").
_keep_pw_keys(line) := regex.replace(line, `(\[\s*|\.get\(\s*)["'](\w*(?i:passw(?:or)?d|passwd|passphrase|pwd)\w*)["']`, "${1}${2}")
