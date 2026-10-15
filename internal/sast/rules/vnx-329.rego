# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_329

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-329",
	"name": "Predictable IV derived from the key or a non-cryptographic generator",
	"description": "A block-cipher IV or nonce is predictable: it is the encryption key (or a slice of it), or it is drawn from a non-cryptographic generator or the clock. An IV equal to the key lets an attacker who controls a chosen-ciphertext decryption recover the key, and a predictable CBC IV enables chosen-plaintext attacks (BEAST). Reported: Python AES.new(k, mode, k|k[:16]|iv=k), cryptography modes.CBC/CTR/CFB/OFB(k[:16]), iv = key[:16], iv = hashlib.md5|sha*(key).digest() (an IV fixed per key), and iv from random.randbytes/randint/getrandbits/choice or time.time()/datetime.now(); Java/Kotlin new IvParameterSpec(keyBytes|key.getEncoded()), an IV assigned from Arrays.copyOf(key, ...) or key.getEncoded(), and nextBytes(iv) on a java.util.Random (not SecureRandom); Kotlin kotlin.random.Random.nextBytes(n) assigned to an IV or nonce, or Random(.Default).nextBytes(iv); Go cipher.NewCBCEncrypter/NewCBCDecrypter/NewCTR/NewCFB*/NewOFB(block, key[:n]), iv := key[:n], and rand.Read(iv) from math/rand; Node.js createCipheriv(alg, key, key.slice(...)), an IV sliced from the key, and an IV (not a nonce, which in JavaScript is usually a CSP or JSONP value) built from Math.random() or Date.now(). Not reported: IVs from os.urandom, secrets, get_random_bytes, SecureRandom, crypto/rand, randomBytes or getRandomValues; IVs read from the ciphertext; constant IVs (VNX-CRYPTO-010 and VNX-JAVA-020 report those); names that only contain the letters (keys, keyword, keystore, monkey); comments, string literals and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-329/",
	"languages": ["go", "java", "kotlin", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [329],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "iv-reuse", "predictable-iv", "cwe-329"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Predictable IV/nonce (derived from the key, a non-cryptographic PRNG or the clock); generate a fresh random IV per message with a CSPRNG and send it with the ciphertext",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_strip(line) := regex.replace(line, `"[^"]*"|'[^']*'`, `""`)

# A name that holds the key.
_keyish(name) if {
	regex.match(`(?i)key`, name)
	not regex.match(`(?i)keys$|keyword|keystore|keychain|keyboard|keypress|keydown|keyup|monkey|donkey|turkey|hockey|jockey|key_?id$|keyname|key_?len|key_?size|^iv|^nonce`, name)
}

# A name that holds the IV or nonce.
_iv_re := `^(iv|IV|nonce|Nonce|NONCE|ivBytes|ivSpec|ivParams?|iv_bytes|iv_value|\w+_iv|\w+Iv|\w+IV|initVector|initialization_?vector)$`

_ivish(name) if regex.match(_iv_re, name)

# ── the IV argument of a cipher call is the key ─────────────────────────

_js_sink := {"gate": "ipheriv", "re": `\bcreate(?:De)?[Cc]ipheriv\(\s*[^,]+,\s*[^,]+,\s*(?:Buffer\.from\(\s*)?(?:this\.)?(\w+)\b`}

_key_arg_sinks := {
	".py": [
		{"gate": "AES.new", "re": `\bAES\.new\(\s*[^,()]+,\s*[^,()]+,\s*(?:iv\s*=\s*)?(?:(?:self|this|cls)\.)?(\w+)\s*(?:\[[^\]]*\])?\s*[,)]`},
		{"gate": "AES.new", "re": `\bAES\.new\([^)]*\biv\s*=\s*(?:(?:self|this|cls)\.)?(\w+)`},
		{"gate": "modes.", "re": `\bmodes\.(?:CBC|CTR|CFB8?|OFB)\(\s*(\w+)`},
	],
	".java": [{"gate": "IvParameterSpec", "re": `\bnew\s+IvParameterSpec\(\s*(\w+)\s*(?:\.getEncoded\(\))?\s*[,)]`}],
	".kt": [{"gate": "IvParameterSpec", "re": `\bIvParameterSpec\(\s*(\w+)\s*(?:\.encoded|\.getEncoded\(\))?\s*[,)]`}],
	".go": [{"gate": "cipher.New", "re": `\bcipher\.New(?:CBCEncrypter|CBCDecrypter|CTR|CFBEncrypter|CFBDecrypter|OFB)\(\s*\w+\s*,\s*(\w+)\s*[\[)]`}],
	".js": [_js_sink],
	".ts": [_js_sink],
	".mjs": [_js_sink],
	".cjs": [_js_sink],
}

findings contains finding if {
	some path, content in input.file_contents
	some ext, sinks in _key_arg_sinks
	endswith(path, ext)
	some s in sinks
	contains(content, s.gate)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, s.gate)
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(s.re, _strip(line), -1)
	_keyish(m[1])
	finding := _finding(path, i, line)
}

# ── an IV variable assigned from the key ────────────────────────────────

_assign_re := `^\s*(?:(?:final\s+|const\s+|let\s+|var\s+|val\s+)?(?:byte\[\]\s+|IvParameterSpec\s+)?)(\w+)\s*(?::\s*[\w\[\]<>]+\s*)?(?::=|=)\s*(.+)$`

# A cheap pre-test: an IV-like name assigned from something mentioning a key.
_iv_from_key_hint := `(?:\b(?:iv|IV|nonce|Nonce|NONCE)|_iv|Iv|IV)\w*\s*(?::\s*[\w\[\]<>]+\s*)?:?=\s*[^=\n]*(?i:key)`

# RHS shapes that take the key's bytes.
_from_key_re := `^(?:new\s+IvParameterSpec\(\s*)?(?:Arrays\.copyOf(?:Range)?\(\s*|Buffer\.from\(\s*|bytes\(\s*|bytearray\(\s*|\[\]byte\(\s*|hashlib\.(?:md5|sha1|sha224|sha256|sha384|sha512)\(\s*)?(?:(?:self|this|cls)\.)?(\w+)\s*\)?\s*(?:\[[^\]]*\]|\.getEncoded\(\)|\.encoded|\.slice\(|\.subarray\(|\.copyOf|\)|,|;|$)`

findings contains finding if {
	some path, content in input.file_contents
	some ext in {".py", ".java", ".kt", ".go", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
	endswith(path, ext)
	regex.match(concat("", ["(?m)", _iv_from_key_hint]), content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_iv_from_key_hint, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_assign_re, _strip(line), 1)
	count(m) > 0
	_ivish(m[0][1])
	rhs := trim_space(m[0][2])
	k := regex.find_all_string_submatch_n(_from_key_re, rhs, 1)
	count(k) > 0
	_keyish(k[0][1])
	finding := _finding(path, i, line)
}

# ── an IV variable drawn from a non-cryptographic source ────────────────

_py_weak := `\brandom\.(randbytes|randint|randrange|getrandbits|choice|choices|random)\(|\btime\.time(_ns)?\(\)|\bdatetime\.(now|utcnow)\(`

_weak_src := {
	".py": _py_weak,
	".js": _js_weak,
	".ts": _js_weak,
	".mjs": _js_weak,
	".cjs": _js_weak,
	".kt": _kt_weak,
}

_js_weak := `\bMath\.random\(\)|\bDate\.now\(\)|\bnew Date\(\)\.getTime\(\)`

# kotlin.random.Random (the default object) is not a CSPRNG.
_kt_weak := `(^|[^\w.])Random(\.Default)?\.nextBytes\(`

# In JavaScript a "nonce" is usually a CSP or JSONP cache-buster, not a cipher input.
_weak_name(ext, name) if {
	not ext in {".js", ".ts", ".mjs", ".cjs"}
	_ivish(name)
}

_weak_name(ext, name) if {
	ext in {".js", ".ts", ".mjs", ".cjs"}
	_ivish(name)
	not regex.match(`(?i)nonce`, name)
}

# Kotlin: Random.nextBytes(iv) / Random.Default.nextBytes(nonce) fills the IV in place.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".kt")
	regex.match(_kt_weak, content)
	contains(content, "kotlin.random")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "nextBytes(")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.])Random(?:\.Default)?\.nextBytes\(\s*(\w+)\s*\)`, line, -1)
	_ivish(m[1])
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext, src in _weak_src
	endswith(path, ext)
	regex.match(src, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(src, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_assign_re, _strip(line), 1)
	count(m) > 0
	_weak_name(ext, m[0][1])
	regex.match(src, m[0][2])
	not regex.match(`SystemRandom|secrets\.`, line)
	finding := _finding(path, i, line)
}

# ── Java/Kotlin: java.util.Random fills the IV ──────────────────────────

_jrandom_vars(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`(\w+)\s*(?::\s*Random\s*)?=\s*(?:new\s+)?(?:java\.util\.)?Random\(`, content, -1)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in {".java", ".kt"}
	endswith(path, ext)
	contains(content, "Random(")
	contains(content, "nextBytes")
	not helpers.is_test_path(path)
	vars := _jrandom_vars(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "nextBytes")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(`(?:\b(\w+)|\bRandom\((?:[^()]|\([^()]*\))*\))\.nextBytes\(\s*(\w+)\s*\)`, line, -1)
	_java_weak_receiver(m, vars)
	_ivish(m[2])
	finding := _finding(path, i, line)
}

_java_weak_receiver(m, vars) if m[1] in vars

_java_weak_receiver(m, _) if {
	m[1] == ""
	regex.match(`\bRandom\(`, m[0])
	not regex.match(`SecureRandom\(`, m[0])
}

# ── Go: math/rand fills the IV ──────────────────────────────────────────

_go_mrand(content) := a if {
	m := regex.find_all_string_submatch_n(`(?m)^\s*(?:import\s+)?(\w+)\s+"math/rand(?:/v2)?"`, content, 1)
	count(m) > 0
	a := m[0][1]
}

_go_mrand(content) := "rand" if {
	not regex.match(`(?m)^\s*(?:import\s+)?\w+\s+"math/rand(?:/v2)?"`, content)
	regex.match(`(?m)^\s*(?:import\s+)?"math/rand(?:/v2)?"`, content)
	not regex.match(`(?m)^\s*(?:import\s+)?"crypto/rand"`, content)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "math/rand")
	not helpers.is_test_path(path)
	alias := _go_mrand(content)
	re := concat("", [`\b`, alias, `\.Read\(\s*(\w+)\s*\)`])
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".Read(")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(re, line, -1)
	_ivish(m[1])
	finding := _finding(path, i, line)
}
