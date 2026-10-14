package vulnetix.rules.vnx_crypto_010

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-010",
	"name": "Hardcoded IV, nonce, or salt in cryptographic operation",
	"description": "A constant is passed as the IV, nonce or salt argument of a cipher, AEAD or password KDF call: a string or byte literal, a literal byte array, or a zero-filled buffer (bytes(16), Buffer.alloc(16), new Uint8Array(12), make([]byte, n), new byte[16], [0u8; 12], {0}), either written in the call or held in a variable whose nearest assignment above is that constant and which is not filled between the assignment and the call. Sinks: Python pycryptodome AES/DES/Blowfish .new(), cryptography modes.CBC/CTR/GCM/CFB/OFB/XTS, AESGCM/AESCCM/ChaCha20Poly1305 encrypt/decrypt, iv=/nonce=/salt= keywords, hashlib.pbkdf2_hmac, PBKDF2/scrypt/PBKDF2HMAC/Scrypt/argon2 hash_secret, bcrypt.hashpw; JavaScript/TypeScript createCipheriv/createDecipheriv, pbkdf2(Sync)/scrypt(Sync), WebCrypto and CryptoJS iv:/salt: parameters, CryptoJS.PBKDF2; Go cipher.NewCBCEncrypter/NewCBCDecrypter/NewCTR/NewOFB/NewCFB*, AEAD Seal/Open, secretbox/box Seal/Open, pbkdf2/scrypt/argon2 Key; Java/Kotlin IvParameterSpec, GCMParameterSpec, PBEKeySpec, PBEParameterSpec, ChaCha20ParameterSpec, BCrypt.hashpw; C/C++/Objective-C EVP_EncryptInit/DecryptInit/CipherInit(_ex), AES_cbc/cfb/ofb_encrypt, PKCS5_PBKDF2_HMAC, mbedtls_aes_crypt_cbc, mbedtls_gcm_crypt_and_tag, crypto_secretbox_easy, CCCrypt/CCCryptorCreate; Rust Nonce::from_slice, Nonce::assume_unique_for_key, CBC/CTR/CFB/OFB ::new and new_from_slices, pbkdf2/pbkdf2_hmac, ring pbkdf2::derive, Argon2 hash_password_into. A direct constant is reported on the call line (or on the iv:/nonce:/salt: line); a constant held in a variable is reported on its assignment. Not reported: IVs and salts from a CSPRNG, read from the ciphertext, or filled in place (rand.Read, io.ReadFull, randomFillSync, getRandomValues, nextBytes, RAND_bytes, fill_bytes) before use; values from configuration or other objects (config.iv), function parameters with no constant assignment in the file, HKDF salts (a constant HKDF salt is permitted by RFC 5869), NULL IVs, calls inside comments or string literals, and test files (known-answer test vectors use fixed IVs by design). Flows through more than one variable, through helper functions, or across files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-010/",
	"languages": ["python", "javascript", "typescript", "go", "java", "kotlin", "c", "cpp", "rust"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [329, 330, 760],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "iv", "nonce", "salt", "hardcoded"],
}

# ── Languages ────────────────────────────────────────────────────────────

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if regex.match(`\.(?:js|mjs|cjs|jsx|ts|tsx|mts|cts)$`, path)

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "jvm" if regex.match(`\.(?:java|kt|kts)$`, path)

_lang(path) := "c" if regex.match(`\.(?:c|h|cc|cpp|cxx|hh|hpp|hxx|m|mm)$`, path)

_lang(path) := "rs" if endswith(path, ".rs")

# ── Argument grammar ─────────────────────────────────────────────────────
# One call argument: string literals, plain characters and one level of
# nested brackets.
_arg := `(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^,()\[\]{}"']|\((?:"[^"]*"|'[^']*'|[^()])*\)|\[[^\[\]]*\]|\{[^{}]*\})+`

_sub(re) := replace(re, "@A", _arg)

# ── Sinks ────────────────────────────────────────────────────────────────
# file: any of these substrings gates the file; lsub: any of these gates the
# line; line: the call head on the line with strings blanked; re: the call on
# the joined lines from here, capture 1 being the IV / nonce / salt argument.

_sinks := {
	"py": [
		{"file": [".new("], "lsub": [".new("], "line": `\b(?:AES|DES3?|Blowfish|CAST|ARC2)\.new\(`, "re": _sub(`\b(?:AES|DES3?|Blowfish|CAST|ARC2)\.new\(\s*@A,\s*@A,\s*(@A)`)},
		{"file": ["modes."], "lsub": ["modes."], "line": `\bmodes\.(?:CBC|CTR|GCM|CFB8?|OFB|XTS)\(`, "re": _sub(`\bmodes\.(?:CBC|CTR|GCM|CFB8?|OFB|XTS)\(\s*(@A)`)},
		{"file": ["AESGCM", "AESCCM", "AESOCB3", "ChaCha20Poly1305"], "lsub": ["crypt("], "line": `(?i:gcm|ccm|ocb|chacha|aead)\w*(?:\([^()]*\))?\.(?:en|de)crypt\(`, "re": _sub(`(?i:gcm|ccm|ocb|chacha|aead)\w*(?:\([^()]*\))?\.(?:en|de)crypt\(\s*(@A)\s*,`)},
		{"file": ["pbkdf2_hmac"], "lsub": ["pbkdf2_hmac("], "line": `\bpbkdf2_hmac\(`, "re": _sub(`\bpbkdf2_hmac\(\s*@A,\s*@A,\s*(@A)`)},
		{"file": ["PBKDF2(", "scrypt("], "lsub": ["PBKDF2(", "scrypt("], "line": `(?:^|[^\w.])(?:PBKDF2|scrypt)\(`, "re": _sub(`(?:^|[^\w.])(?:PBKDF2|scrypt)\(\s*@A,\s*(@A)`)},
		{"file": ["hash_secret"], "lsub": ["hash_secret"], "line": `\bhash_secret(?:_raw)?\(`, "re": _sub(`\bhash_secret(?:_raw)?\(\s*@A,\s*(@A)`)},
		{"file": ["hashpw"], "lsub": ["hashpw("], "line": `\bbcrypt\.hashpw\(`, "re": _sub(`\bbcrypt\.hashpw\(\s*@A,\s*(@A)`)},
	],
	"js": [
		{"file": ["ipheriv"], "lsub": ["ipheriv("], "line": `\bcreate(?:De)?[cC]ipheriv\(`, "re": _sub(`\bcreate(?:De)?[cC]ipheriv\(\s*@A,\s*@A,\s*(@A)`)},
		{"file": ["pbkdf2", "scrypt"], "lsub": ["pbkdf2", "scrypt"], "line": `(?:^|[^\w])(?:pbkdf2Sync|pbkdf2|scryptSync|scrypt)\(`, "re": _sub(`(?:^|[^\w])(?:pbkdf2Sync|pbkdf2|scryptSync|scrypt)\(\s*@A,\s*(@A)`)},
		{"file": ["CryptoJS"], "lsub": ["CryptoJS."], "line": `\bCryptoJS\.(?:PBKDF2|EvpKDF)\(`, "re": _sub(`\bCryptoJS\.(?:PBKDF2|EvpKDF)\(\s*@A,\s*(@A)`)},
	],
	"go": [
		{"file": ["cipher.New"], "lsub": ["cipher.New"], "line": `\bcipher\.New(?:CBCEncrypter|CBCDecrypter|CTR|OFB|CFBEncrypter|CFBDecrypter)\(`, "re": _sub(`\bcipher\.New(?:CBCEncrypter|CBCDecrypter|CTR|OFB|CFBEncrypter|CFBDecrypter)\(\s*@A,\s*(@A)`)},
		{"file": ["crypto/cipher", "chacha20poly1305", "siv"], "lsub": [".Seal(", ".Open("], "line": `\w\.(?:Seal|Open)\(`, "not": `\b(?:secretbox|box)\.(?:Seal|Open)\(`, "re": _sub(`\w\.(?:Seal|Open)\(\s*@A,\s*(@A)\s*,`)},
		{"file": ["box."], "lsub": ["box.Seal(", "box.Open("], "line": `\b(?:secretbox|box)\.(?:Seal|Open)\(`, "re": _sub(`\b(?:secretbox|box)\.(?:Seal|Open)\(\s*@A,\s*@A,\s*(@A)`)},
		{"file": ["Key("], "lsub": ["Key("], "line": `\b(?:pbkdf2|scrypt|argon2)\.(?:ID)?Key\(`, "re": _sub(`\b(?:pbkdf2|scrypt|argon2)\.(?:ID)?Key\(\s*@A,\s*(@A)`)},
	],
	"jvm": [
		{"file": ["IvParameterSpec"], "lsub": ["IvParameterSpec("], "line": `\bIvParameterSpec\(`, "re": _sub(`\bIvParameterSpec\(\s*(@A)`)},
		{"file": ["GCMParameterSpec"], "lsub": ["GCMParameterSpec("], "line": `\bGCMParameterSpec\(`, "re": _sub(`\bGCMParameterSpec\(\s*@A,\s*(@A)`)},
		{"file": ["PBEKeySpec"], "lsub": ["PBEKeySpec("], "line": `\bPBEKeySpec\(`, "re": _sub(`\bPBEKeySpec\(\s*@A,\s*(@A)\s*,`)},
		{"file": ["PBEParameterSpec", "ChaCha20ParameterSpec"], "lsub": ["ParameterSpec("], "line": `\b(?:PBE|ChaCha20)ParameterSpec\(`, "re": _sub(`\b(?:PBE|ChaCha20)ParameterSpec\(\s*(@A)`)},
		{"file": ["BCrypt"], "lsub": ["BCrypt.hashpw("], "line": `\bBCrypt\.hashpw\(`, "re": _sub(`\bBCrypt\.hashpw\(\s*@A,\s*(@A)`)},
	],
	"c": [
		{"file": ["EVP_"], "lsub": ["Init_ex("], "line": `\bEVP_(?:Encrypt|Decrypt|Cipher)Init_ex\(`, "re": _sub(`\bEVP_(?:Encrypt|Decrypt|Cipher)Init_ex\(\s*@A,\s*@A,\s*@A,\s*@A,\s*(@A)`)},
		{"file": ["EVP_"], "lsub": ["Init(", "Init_ex2("], "line": `\bEVP_(?:Encrypt|Decrypt|Cipher)Init(?:_ex2)?\(`, "re": _sub(`\bEVP_(?:Encrypt|Decrypt|Cipher)Init(?:_ex2)?\(\s*@A,\s*@A,\s*@A,\s*(@A)`)},
		{"file": ["AES_"], "lsub": ["_encrypt("], "line": `\bAES_(?:cbc|cfb128|cfb8|cfb1|ofb128)_encrypt\(`, "re": _sub(`\bAES_(?:cbc|cfb128|cfb8|cfb1|ofb128)_encrypt\(\s*@A,\s*@A,\s*@A,\s*@A,\s*(@A)`)},
		{"file": ["PKCS5_PBKDF2_HMAC"], "lsub": ["PKCS5_PBKDF2_HMAC"], "line": `\bPKCS5_PBKDF2_HMAC(?:_SHA1)?\(`, "re": _sub(`\bPKCS5_PBKDF2_HMAC(?:_SHA1)?\(\s*@A,\s*@A,\s*(@A)`)},
		{"file": ["mbedtls_"], "lsub": ["mbedtls_"], "line": `\bmbedtls_(?:aes_crypt_cbc|gcm_crypt_and_tag)\(`, "re": _sub(`\bmbedtls_(?:aes_crypt_cbc|gcm_crypt_and_tag)\(\s*@A,\s*@A,\s*@A,\s*(@A)`)},
		{"file": ["crypto_secretbox"], "lsub": ["crypto_secretbox"], "line": `\bcrypto_secretbox_(?:open_)?easy\(`, "re": _sub(`\bcrypto_secretbox_(?:open_)?easy\(\s*@A,\s*@A,\s*@A,\s*(@A)`)},
		{"file": ["CCCrypt"], "lsub": ["CCCrypt"], "line": `\bCCCrypt(?:orCreate)?\(`, "re": _sub(`\bCCCrypt(?:orCreate)?\(\s*@A,\s*@A,\s*@A,\s*@A,\s*@A,\s*(@A)`)},
	],
	"rs": [
		{"file": ["Nonce"], "lsub": ["from_slice("], "line": `\bX?Nonce(?:::<[^()]*?>)?::from_slice\(`, "re": _sub(`\bX?Nonce(?:::<[^()]*?>)?::from_slice\(\s*(@A)\s*\)`)},
		{"file": ["assume_unique_for_key"], "lsub": ["assume_unique_for_key("], "line": `\bNonce::assume_unique_for_key\(`, "re": _sub(`\bNonce::assume_unique_for_key\(\s*(@A)\s*\)`)},
		{"file": ["new_from_slices"], "lsub": ["new_from_slices("], "line": `::new_from_slices\(`, "re": _sub(`::new_from_slices\(\s*@A,\s*(@A)\s*\)`)},
		{"file": ["::new("], "lsub": ["::new("], "line": `(?:\b(?:cbc|cfb_mode|cfb8|ofb|ctr)::\w+|\b\w*(?:Cbc|Ctr|Cfb|Ofb)\w*)(?:::<[^()]*?>|<[^()]*?>)?::new\(`, "re": _sub(`(?:\b(?:cbc|cfb_mode|cfb8|ofb|ctr)::\w+|\b\w*(?:Cbc|Ctr|Cfb|Ofb)\w*)(?:::<[^()]*?>|<[^()]*?>)?::new\(\s*@A,\s*(@A)\s*\)`)},
		{"file": ["pbkdf2"], "lsub": ["pbkdf2"], "line": `\bpbkdf2(?:_hmac)?(?:::<[^()]*?>)?\(`, "re": _sub(`\bpbkdf2(?:_hmac)?(?:::<[^()]*?>)?\(\s*@A,\s*(@A)`)},
		{"file": ["pbkdf2::derive"], "lsub": ["pbkdf2::derive("], "line": `\bpbkdf2::derive\(`, "re": _sub(`\bpbkdf2::derive\(\s*@A,\s*@A,\s*(@A)`)},
		{"file": ["hash_password_into"], "lsub": ["hash_password_into("], "line": `\.hash_password_into\(`, "re": _sub(`\.hash_password_into\(\s*@A,\s*(@A)`)},
	],
}

# Keyword / object-member parameters: `nonce=b"..."` (Python),
# `{ iv: ..., salt: ... }` (WebCrypto, CryptoJS, forge), checked against a
# crypto call within six lines.
_kw := {
	"py": {
		"lsub": ["iv=", "IV=", "nonce=", "salt=", "iv =", "nonce =", "salt ="],
		"re": _sub(`(?:[(,]\s*|^\s*)(?:iv|IV|nonce|salt)\s*=\s*(@A)`),
		"ctx": `\b(?:AES|DES3?|Blowfish|CAST|ARC2|ChaCha20|ChaCha20_Poly1305|Salsa20|XChaCha20)\.new\(|\bPBKDF2HMAC\(|\bScrypt\(|\bhashlib\.scrypt\(|(?:^|[^\w.])(?:PBKDF2|scrypt)\(|\bArgon2id\(|\bhash_secret(?:_raw)?\(`,
	},
	"js": {
		"lsub": ["iv", "salt", "nonce"],
		"re": _sub(`(?:^|[{,])\s*(?:iv|salt|nonce)\s*:\s*(@A)`),
		"ctx": `\bsubtle\.(?:encrypt|decrypt|deriveKey|deriveBits|wrapKey|unwrapKey)\(|\bCryptoJS\.\w+\.(?:encrypt|decrypt)\(|\bCryptoJS\.(?:PBKDF2|EvpKDF)\(|\.start\(\s*\{|\bforge\.pkcs5\.pbkdf2\(`,
	},
}

_kw_short := `(?:^|[{,])\s*(iv|salt|nonce)\s*(?:[,}]|$)`

# ── Code text ────────────────────────────────────────────────────────────

_blank(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`)

_code(line, "py") := regex.replace(line, `\s#[^"']*$`, "")

_code(line, lang) := c if {
	lang != "py"
	a := regex.replace(line, `/\*.*?\*/`, " ")
	c := regex.replace(a, concat("", [`\s//[^"'`, "`", `]*$`]), "")
}

_joined(lines, i, lang) := concat(" ", [_code(l, lang) |
	some k in numbers.range(i, min([count(lines) - 1, i + 6]))
	l := lines[k]
	not helpers.is_comment_line(l)
])

# ── Constants ────────────────────────────────────────────────────────────

_str := concat("", [`(?:[bBuU]|[rR][bB]|[bB][rR])?(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`, "`[^`$]*`", `)`])

_hard_res := [
	concat("", [`^`, _str, `(?:\s*\*\s*\d+)?$`]),
	concat("", [`^`, _str, `\s*\.\s*(?:getBytes|encode|toByteArray|as_bytes|to_vec|c_str|data)\s*\([^()]*\)$`]),
	`^\{[^{}]*\d[^{}]*\}$`,
	`^new\s+byte\s*\[\s*\]\s*\{[^{}]*\}$`,
	`^byteArrayOf\([^;]*\)$`,
	`^\[\]byte\{[^{}]*\d[^{}]*\}$`,
	`^(?:new\s+)?Uint8Array(?:\.from)?\(\s*\[[^\]]*\d[^\]]*\]\s*\)$`,
	`^(?:bytes|bytearray)\(\s*\[[^\]]*\d[^\]]*\]\s*\)$`,
	`^\[[\s\dxXa-fA-Fu8_,]*\d[\s\dxXa-fA-Fu8_,]*\]$`,
]

_zero_res := [
	`^(?:bytes|bytearray)\(\s*\d+\s*\)$`,
	`^(?:bytes|bytearray)\(\s*\[\s*0\s*\]\s*\*\s*\d+\s*\)$`,
	`^\[\s*0\s*\]\s*\*\s*\d+$`,
	`^Buffer\.alloc\(\s*[\w.]+\s*(?:,\s*[^()]*)?\)$`,
	`^new\s+Uint8Array\(\s*[\w.]+\s*\)$`,
	`^make\(\s*\[\]byte\s*,\s*(?:[^()]|\([^()]*\))*\)$`,
	`^new\s+byte\s*\[\s*[\w.]+\s*\]$`,
	`^ByteArray\(\s*[\w.]+\s*\)$`,
	`^(?:vec!)?\[\s*0(?:u8)?\s*;\s*[\w.]+\s*\]$`,
	`^\{\s*0?\s*\}$`,
]

# Strip borrows, casts and conversions that do not change the value.
_norm(a) := n if {
	s1 := regex.replace(trim_space(a), `^(?:&\s*(?:mut\s+)?|\*\s*)`, "")
	s2 := regex.replace(s1, `^\(\s*(?:const\s+)?(?:unsigned\s+char|uint8_t|u_char|unsigned char|char|byte|BYTE|void|guchar)\s*\*\s*\)\s*`, "")
	s3 := regex.replace(s2, `(?:\s*\.\s*(?:into|as_ref|as_slice|to_vec|clone)\s*\(\s*\))+$`, "")
	n := trim_space(regex.replace(s3, `\[\s*:\s*\]$`, ""))
}

# One wrapper that turns a literal into bytes.
_wrap := `^(?:Buffer\.from|\[\]byte|bytes\.fromhex|bytearray\.fromhex|(?:binascii\.)?unhexlify|base64\.b64decode|Hex\.decode(?:Hex)?|DatatypeConverter\.parseHexBinary|Base64\.getDecoder\(\)\.decode|Base64\.decode|CryptoJS\.enc\.\w+\.parse|(?:new\s+)?TextEncoder\(\)\.encode|GenericArray::from_slice|X?Nonce::from_slice|Uint8Array\.from|forge\.util\.(?:hexToBytes|decode64)|bytes)\(\s*&?\s*((?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^,'"])+?)\s*(?:,\s*[^,()]*)?\)$`

_peel(n) := _norm(m[0][1]) if {
	m := regex.find_all_string_submatch_n(_wrap, n, 1)
	count(m) > 0
}

_hard(n) if {
	some re in _hard_res
	regex.match(re, n)
	not regex.match(`^\{\s*0?\s*\}$`, n)
}

_zero(n) if {
	some re in _zero_res
	regex.match(re, n)
}

_const(n) if _hard(n)

_const(n) if _zero(n)

_const(n) if _hard(_peel(n))

_ident_re := `^(?:(?:self|this|cls)\s*\.\s*)?([A-Za-z_]\w*)(?:\s*\.\s*(?:getBytes|encode|toByteArray|as_bytes|c_str|data|buffer)\s*\([^()]*\))?$`

_not_ident := {"None", "null", "NULL", "nil", "undefined", "true", "false", "nullptr", "self", "this"}

_ident(n) := v if {
	m := regex.find_all_string_submatch_n(_ident_re, n, 1)
	count(m) > 0
	v := m[0][1]
	not _not_ident[v]
} else := v if {
	p := _peel(n)
	m := regex.find_all_string_submatch_n(_ident_re, p, 1)
	count(m) > 0
	v := m[0][1]
	not _not_ident[v]
}

# ── The nearest assignment of a variable above the call ──────────────────

_assign_re(v) := concat("", [`(?:^|[^\w.])(?:(?:self|this|cls)\s*\.\s*)?`, v, `(?:\s*\[[^\]]*\])*\s*(?::[^=]+?)?\s*(?::=|=)\s*([^=\s].*?)\s*;?\s*$`])

_var_zero_re(v) := concat("", [`^\s*var\s+`, v, `\s+\[[\w.]+\]byte\s*(?://.*)?$`])

_memset_re(v) := concat("", [`\bmemset\(\s*&?\s*`, v, `\s*,\s*0\s*,`])

_is_assign(l, v) if regex.match(_assign_re(v), l)

_is_assign(l, v) if regex.match(_var_zero_re(v), l)

_is_assign(l, v) if regex.match(_memset_re(v), l)

_assign_line(lines, i, v) := max(ks) if {
	i > 0
	ks := [k |
		some k in numbers.range(max([0, i - 400]), i - 1)
		l := lines[k]
		contains(l, v)
		not helpers.is_comment_line(l)
		_is_assign(l, v)
	]
	count(ks) > 0
}

_rhs(lines, k, v) := "{0}" if regex.match(_var_zero_re(v), lines[k])

else := "{0}" if regex.match(_memset_re(v), lines[k])

else := r if {
	m := regex.find_all_string_submatch_n(_assign_re(v), lines[k], 1)
	r0 := trim_space(m[0][1])
	r := _complete(lines, k, r0)
}

# An initialiser that opens on this line and closes on a later one.
_complete(lines, k, r0) := r if {
	_open(r0) > 0
	rest := [trim_space(lines[j]) | some j in numbers.range(k + 1, min([count(lines) - 1, k + 6]))]
	joined := concat(" ", array.concat([r0], rest))
	m := regex.find_all_string_submatch_n(`^((?:new\s+byte\s*\[\s*\]\s*)?\{[^{}]*\}|[\w.!]*\(\s*\[[^\]]*\]\s*\)|\[[^\]]*\]|[\w.]+\([^()]*\))`, joined, 1)
	count(m) > 0
	r := m[0][1]
} else := r0

_open(s) := (strings.count(s, "{") + strings.count(s, "[")) + strings.count(s, "(") - ((strings.count(s, "}") + strings.count(s, "]")) + strings.count(s, ")"))

# Filled in place (rand.Read(iv), randomFillSync(iv), RAND_bytes(iv, ...)):
# any code line between the assignment and the call that names the variable.
_mentioned_between(lines, k, i, v) if {
	k + 1 <= i - 1
	some j in numbers.range(k + 1, i - 1)
	l := lines[j]
	contains(l, v)
	not helpers.is_comment_line(l)
	regex.match(concat("", [`(?:^|[^\w])`, v, `(?:[^\w]|$)`]), l)
}

_flow_const(lines, i, v) := k if {
	k := _assign_line(lines, i, v)
	r := _norm(_rhs(lines, k, v))
	_hard_or_peeled(r)
}

else := k if {
	k := _assign_line(lines, i, v)
	r := _norm(_rhs(lines, k, v))
	_zero(r)
	not _mentioned_between(lines, k, i, v)
}

_hard_or_peeled(r) if _hard(r)

_hard_or_peeled(r) if _hard(_peel(r))

# ── Verdict on one argument ──────────────────────────────────────────────

_verdict(arg, lines, i) := {"line": i, "direct": true} if {
	_const(_norm(arg))
} else := {"line": k, "direct": false} if {
	v := _ident(_norm(arg))
	k := _flow_const(lines, i, v)
}

_msg(true) := "A constant IV, nonce or salt is passed to this cipher, AEAD or KDF call; generate a fresh value per operation from a CSPRNG (os.urandom, crypto.randomBytes, crypto/rand, SecureRandom, RAND_bytes, OsRng) and store it beside the ciphertext or hash"

_msg(false) := "This constant is used as the IV, nonce or salt of a cipher, AEAD or KDF call below; generate a fresh value per operation from a CSPRNG (os.urandom, crypto.randomBytes, crypto/rand, SecureRandom, RAND_bytes, OsRng) and store it beside the ciphertext or hash"

_finding(path, lines, r) := {
	"rule_id": metadata.id,
	"message": _msg(r.direct),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": r.line + 1,
	"snippet": lines[r.line],
}

# ── Positional sinks ─────────────────────────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	some s in _sinks[lang]
	some fs in s.file
	contains(content, fs)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	some ls in s.lsub
	contains(line, ls)
	not helpers.is_comment_line(line)
	regex.match(s.line, _blank(line))
	not _excluded(s, line)
	t := _joined(lines, i, lang)
	m := regex.find_all_string_submatch_n(s.re, t, 1)
	count(m) > 0
	indexof(t, m[0][0]) < count(_code(line, lang))
	not _in_docstring(lines, i, lang)
	r := _verdict(m[0][1], lines, i)
	finding := _finding(path, lines, r)
}

_excluded(s, line) if regex.match(s.not, line)

# ── Keyword / object-member parameters ───────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	k := _kw[lang]
	_has_ctx_word(content, lang)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	some ls in k.lsub
	contains(line, ls)
	not helpers.is_comment_line(line)
	code := _code(line, lang)
	not _py_statement(lang, code)
	arg := _kw_arg(k, code)
	_kw_context(lines, i, k.ctx)
	not _in_docstring(lines, i, lang)
	r := _verdict(arg, lines, i)
	finding := _finding(path, lines, r)
}

_has_ctx_word(content, "py") if regex.match(`\.new\(|PBKDF2|[Ss]crypt\(|Argon2id|hash_secret`, content)

_has_ctx_word(content, "js") if regex.match(`subtle\.|CryptoJS\.|\.start\(|forge\.pkcs5`, content)

# `iv = b"..."` on its own line is an assignment, handled by the flow above.
_py_statement("py", code) if regex.match(`^\s*(?:iv|IV|nonce|salt)\s+=`, code)

_kw_arg(k, code) := m[0][1] if {
	m := regex.find_all_string_submatch_n(k.re, code, 1)
	count(m) > 0
} else := m[0][1] if {
	m := regex.find_all_string_submatch_n(_kw_short, code, 1)
	count(m) > 0
}

_kw_context(lines, i, ctx) if regex.match(ctx, _blank(lines[i]))

# A call opened on one of the six lines above and still open here.
_kw_context(lines, i, ctx) if {
	i > 0
	some j in numbers.range(max([0, i - 6]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(ctx, _blank(l))
	text := concat(" ", [_blank(lines[k]) | some k in numbers.range(j, i - 1)])
	strings.count(text, "(") > strings.count(text, ")")
}

# Inside a Python triple-quoted string (a docstring).
_in_docstring(lines, i, "py") if {
	before := concat("\n", array.slice(lines, 0, i))
	n := strings.count(before, `"""`) + strings.count(before, `'''`)
	n % 2 == 1
}
