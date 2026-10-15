# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_780

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-780",
	"name": "Use of RSA Algorithm without OAEP",
	"description": "RSA encryption or decryption is performed with PKCS#1 v1.5 padding or with no padding, which leaves decryption open to Bleichenbacher-style padding-oracle attacks (and raw RSA is deterministic and malleable). Reported: Java and Kotlin Cipher.getInstance with \"RSA\" (the provider default is RSA/ECB/PKCS1Padding), RSA/<mode>/PKCS1Padding or RSA/<mode>/NoPadding in any case, inline, on the next line or through a constant assigned in the file, and BouncyCastle new PKCS1Encoding(); Python cryptography padding.PKCS1v15() passed to encrypt()/decrypt() (also across lines), PyCryptodome PKCS1_v1_5 imported from Crypto.Cipher and its .new(), and python-rsa rsa.encrypt()/rsa.decrypt(); Node.js publicEncrypt/privateDecrypt with padding RSA_PKCS1_PADDING or RSA_NO_PADDING, node-rsa encryptionScheme 'pkcs1', and new JSEncrypt() (PKCS#1 v1.5 only); Go rsa.EncryptPKCS1v15, rsa.DecryptPKCS1v15 and DecryptPKCS1v15SessionKey; PHP openssl_public_encrypt/openssl_private_decrypt with no padding argument (the default is OPENSSL_PKCS1_PADDING) or with OPENSSL_PKCS1_PADDING/OPENSSL_NO_PADDING, and phpseclib ENCRYPTION_PKCS1/ENCRYPTION_NONE modes; Ruby OpenSSL public_encrypt/private_decrypt with no padding argument or PKCS1_PADDING/NO_PADDING; C# Encrypt/Decrypt(data, false) on an RSA provider, RSAEncryptionPadding.Pkcs1 and BouncyCastle new Pkcs1Encoding(). Not reported: OAEP everywhere, PKCS#1 v1.5 signatures (sign/verify, SignPKCS1v15, RSASignaturePadding.Pkcs1, Crypto.Signature), Node publicEncrypt with a bare key (its default is OAEP), a transformation passed in as a parameter, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-780/",
	"languages": ["java", "kotlin", "python", "node", "go", "php", "ruby", "csharp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [780],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["crypto", "rsa-no-padding", "cwe-780"],
}

_msg := "RSA encryption uses PKCS#1 v1.5 or no padding, which is open to padding-oracle attacks; use OAEP (with SHA-256)"

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# String literals blanked, so a call quoted in a message is not code.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_ext(path) := regex.replace(path, `^.*\.`, "")

# ── Java / Kotlin ────────────────────────────────────────────────────────

_jvm_ext := {"java", "kt", "kts"}

_weak_literal := `^(?i:"RSA(/[^/"]*/(PKCS1Padding|NoPadding))?")$`

_weak_names(lines) := {m[1] |
	some l in lines
	contains(lower(l), "\"rsa")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*(?::\s*String\s*)?=\s*(?i:"RSA(?:/[^/"]*/(?:PKCS1Padding|NoPadding))?")\s*;?\s*$`, l, -1)
}

_first_arg(lines, i) := a if {
	end := min([count(lines) - 1, i + 2])
	txt := concat(" ", [regex.replace(lines[k], `//.*$`, "") | some k in numbers.range(i, end)])
	m := regex.find_all_string_submatch_n(`Cipher\s*\.\s*getInstance\s*\(\s*([^),]*)`, txt, 1)
	count(m) > 0
	a := trim_space(m[0][1])
}

_jvm_weak(_, arg) if regex.match(_weak_literal, arg)

_jvm_weak(lines, arg) if arg in _weak_names(lines)

findings contains f if {
	some path, content in input.file_contents
	_ext(path) in _jvm_ext
	contains(content, "getInstance")
	regex.match(`(?i)"RSA`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "getInstance")
	not helpers.is_comment_line(line)
	regex.match(`Cipher\s*\.\s*getInstance\s*\(`, _code(line))
	_jvm_weak(lines, _first_arg(lines, i))
	f := _finding(path, i, line)
}

findings contains f if {
	some path, content in input.file_contents
	_ext(path) in {"java", "kt", "kts", "cs"}
	regex.match(`(?i)new\s+PKCS1Encoding\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(`\bnew\s+(?:PKCS1Encoding|Pkcs1Encoding)\s*\(`, _code(line))
	f := _finding(path, i, line)
}

# ── Python ───────────────────────────────────────────────────────────────

# padding.PKCS1v15() whose nearest enclosing call (this line or up to four
# above) is encrypt/decrypt rather than sign/verify.
_py_enc_ctx(lines, i) if {
	opens := [k |
		some k in numbers.range(max([0, i - 4]), i)
		not helpers.is_comment_line(lines[k])
		regex.match(`\.(?:encrypt|decrypt|sign|verify|recover_data_from_signature)\s*\(`, _code(lines[k]))
	]
	count(opens) > 0
	last := lines[max(opens)]
	ms := regex.find_all_string_submatch_n(`\.(encrypt|decrypt|sign|verify|recover_data_from_signature)\s*\(`, _code(last), -1)
	ms[count(ms) - 1][1] in {"encrypt", "decrypt"}
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "PKCS1v15()")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "PKCS1v15")
	not helpers.is_comment_line(line)
	regex.match(`\bPKCS1v15\s*\(\s*\)`, _code(line))
	_py_enc_ctx(lines, i)
	f := _finding(path, i, line)
}

_py_cipher_names(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+(?:Crypto|Cryptodome)\.Cipher\s+import\s+([^\n#]+)`, content, -1)
	some part in split(trim(m[1], "()"), ",")
	pm := regex.find_all_string_submatch_n(`^\s*PKCS1_v1_5(?:\s+as\s+(\w+))?\s*$`, part, 1)
	count(pm) > 0
	n := _alias_or(pm[0][1], "PKCS1_v1_5")
}

_alias_or(a, d) := a if a != ""

_alias_or(a, d) := d if a == ""

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "PKCS1_v1_5")
	names := _py_cipher_names(content)
	count(names) > 0
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	some n in names
	contains(line, n)
	regex.match(concat("", [`(?:^|[^\w.])`, n, `\.new\s*\(`]), _code(line))
	f := _finding(path, i, line)
}

# python-rsa only implements PKCS#1 v1.5 encryption.
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)^\s*import\s+rsa\s*$`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "rsa.")
	not helpers.is_comment_line(line)
	regex.match(`(?:^|[^\w.])rsa\.(?:encrypt|decrypt)\s*\(`, _code(line))
	f := _finding(path, i, line)
}

# ── JavaScript / TypeScript ──────────────────────────────────────────────

_js_ext := {"js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts"}

findings contains f if {
	some path, content in input.file_contents
	_ext(path) in _js_ext
	regex.match(`RSA_(?:PKCS1|NO)_PADDING`, content)
	regex.match(`(?:publicEncrypt|privateDecrypt)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "_PADDING")
	not helpers.is_comment_line(line)
	regex.match(`\bpadding\s*:\s*(?:\w+\.)*RSA_(?:PKCS1|NO)_PADDING\b`, _code(line))
	window := helpers.code_window(lines, i, 5, 0)
	ms := regex.find_all_string_submatch_n(`\b(publicEncrypt|privateDecrypt|privateEncrypt|publicDecrypt|sign|verify|createSign|createVerify)\s*\(`, window, -1)
	count(ms) > 0
	ms[count(ms) - 1][1] in {"publicEncrypt", "privateDecrypt"}
	f := _finding(path, i, line)
}

findings contains f if {
	some path, content in input.file_contents
	_ext(path) in _js_ext
	contains(content, "encryptionScheme")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "encryptionScheme")
	not helpers.is_comment_line(line)
	regex.match(`\bencryptionScheme\s*:\s*["']pkcs1["']`, line)
	regex.match(`\bencryptionScheme\s*:`, _code(line))
	f := _finding(path, i, line)
}

findings contains f if {
	some path, content in input.file_contents
	_ext(path) in _js_ext
	contains(content, "JSEncrypt")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "JSEncrypt")
	not helpers.is_comment_line(line)
	regex.match(`\bnew\s+(?:\w+\.)?JSEncrypt\s*\(`, _code(line))
	f := _finding(path, i, line)
}

# ── Go ───────────────────────────────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`rsa\.(?:Encrypt|Decrypt)PKCS1v15`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "PKCS1v15")
	not helpers.is_comment_line(line)
	regex.match(`\brsa\.(?:EncryptPKCS1v15|DecryptPKCS1v15|DecryptPKCS1v15SessionKey)\s*\(`, _code(line))
	f := _finding(path, i, line)
}

# ── PHP ──────────────────────────────────────────────────────────────────

_top_args(s) := split(regex.replace(regex.replace(s, `\([^()]*\)`, "()"), `\([^()]*\)`, "()"), ",")

_php_weak_args(args) if count(args) == 3

_php_weak_args(args) if {
	count(args) >= 4
	regex.match(`\bOPENSSL_(?:PKCS1|NO)_PADDING\b`, args[3])
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`openssl_(?:public_encrypt|private_decrypt)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "openssl_")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(`\bopenssl_(?:public_encrypt|private_decrypt)\s*\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`, _code(line), -1)
	_php_weak_args(_top_args(m[1]))
	f := _finding(path, i, line)
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`ENCRYPTION_(?:PKCS1|NONE)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ENCRYPTION_")
	not helpers.is_comment_line(line)
	regex.match(`(?:setEncryptionMode|withPadding)\s*\(\s*(?:[\\\w]*::)?(?:CRYPT_RSA_)?ENCRYPTION_(?:PKCS1|NONE)\b`, _code(line))
	f := _finding(path, i, line)
}

# ── Ruby ─────────────────────────────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".rb")
	regex.match(`\.(?:public_encrypt|private_decrypt)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	c := _code(line)
	some m in regex.find_all_string_submatch_n(`\.(?:public_encrypt|private_decrypt)(?:\s*\(((?:[^()]|\([^()]*\))*)\)|\s+([^\n#]+))`, c, -1)
	_rb_weak_args(_top_args(concat("", [m[1], m[2]])))
	f := _finding(path, i, line)
}

_rb_weak_args(args) if {
	count(args) == 1
	trim_space(args[0]) != ""
}

_rb_weak_args(args) if {
	count(args) >= 2
	regex.match(`\b(?:PKCS1_PADDING|NO_PADDING)\b`, args[1])
}

# ── C# ───────────────────────────────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	contains(content, "RSA")
	regex.match(`RSAEncryptionPadding\.Pkcs1\b|\.(?:Encrypt|Decrypt)\s*\([^;]*,\s*false\s*\)`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	c := _code(line)
	_cs_weak(lines, i, c)
	f := _finding(path, i, line)
}

_cs_weak(_, _, c) if regex.match(`\bRSAEncryptionPadding\.Pkcs1\b`, c)

# fOAEP = false on RSACryptoServiceProvider.Encrypt/Decrypt
_cs_weak(lines, i, c) if {
	regex.match(`\.(?:Encrypt|Decrypt)\s*\([^,;()]+(?:\([^()]*\))?\s*,\s*false\s*\)`, c)
	regex.match(`RSA`, helpers.code_window(lines, i, 20, 0))
}
