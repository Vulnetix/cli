# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_327

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-327",
	"name": "Broken hash algorithm (MD5, SHA-1) protecting a password, token or signature",
	"description": "MD5 or SHA-1 is computed through a hash API on a security value: the call line, the three code lines above it or the next one (the next three for a Java/Kotlin MessageDigest, which is fed afterwards), never looking past a line that closes a block name a password, secret, token, session id, cookie, signature, salt, nonce, CSRF value, API key, credential or reset value. Both algorithms are broken for collision resistance and are fast to brute-force, so they must not hash passwords or derive tokens and signatures; use SHA-256 or stronger, HMAC-SHA256 for tokens and signatures, and argon2id/bcrypt/scrypt for passwords. Calls recognised: Python hashlib.md5()/sha1()/new('md5'|'sha1') and bare md5()/sha1() after from hashlib import, Node.js createHash('md5'|'sha1') and CryptoJS.MD5/SHA1, Java/Kotlin MessageDigest.getInstance(\"MD5\"|\"SHA-1\"), commons-codec/Spring DigestUtils.md5Hex/sha1Hex/md5DigestAsHex and Guava Hashing.md5()/sha1(), PHP md5()/sha1()/md5_file()/sha1_file(), Ruby Digest::MD5/SHA1, OpenSSL::Digest::MD5/SHA1 and OpenSSL::Digest.new('MD5'|'SHA1'). Not reported: digests with no security name nearby (cache keys, ETags, checksums, content addresses), digests of a constant (static::class, __CLASS__, a string literal), Python calls marked usedforsecurity=False, HMAC-SHA1, names, fields, enums and comments that only mention the algorithms, and test files. Every MD5 and SHA-1 call regardless of purpose is reported by VNX-CRYPTO-001 and VNX-CRYPTO-002; Go is covered there.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-327/",
	"languages": ["java", "kotlin", "node", "php", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "weak-algorithm", "cwe-327"],
}

_js_call := `\bcreateHash\(\s*['"\x60](md5|sha-?1)['"\x60]|\bCryptoJS\.(MD5|SHA1)\(`

# MessageDigest, Apache commons-codec / Spring DigestUtils, Guava Hashing.
_jvm_call := `\bMessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"|\bDigestUtils\.(md5|sha1|sha)(Hex|DigestAsHex|Digest)?\s*\(|\bHashing\.(md5|sha1)\(\s*\)`

_py_call := `\bhashlib\.(md5|sha1)\s*\(|\bhashlib\.new\(\s*['"](md5|sha1)['"]`

_py_from_import := `(?m)^\s*from\s+hashlib\s+import\s+[^\n]*\b(md5|sha1)\b`

# extension → the call shape that computes the digest; `from hashlib import
# md5` makes a bare md5( call the same thing.
_call(path, content) := _py_call if {
	endswith(path, ".py")
	not regex.match(_py_from_import, content)
}

_call(path, content) := concat("|", [_py_call, `(^|[^\w.])(md5|sha1)\s*\(`]) if {
	endswith(path, ".py")
	regex.match(_py_from_import, content)
}

_call(path, _) := _js_call if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_call(path, _) := _jvm_call if {
	some ext in {".java", ".kt"}
	endswith(path, ext)
}

_call(path, _) := `(^|[^\w>:$\\])(md5|sha1)(_file)?\s*\(` if endswith(path, ".php")

_call(path, _) := `\b(OpenSSL::)?Digest::(MD5|SHA1)\b|\bOpenSSL::Digest\.new\(\s*['"](?i:md5|sha1)['"]` if endswith(path, ".rb")

# The look-behind stops at the end of the previous block (a line that is only
# a closing brace or Ruby `end`), so the function above does not lend its name.
_closer(l) if regex.match(`^\s*(\}[\s;),]*|end)\s*$`, l)

_before_start(lines, i) := s if {
	lo := max([0, i - 3])
	ks := [k | some k in numbers.range(lo, i - 1); _closer(lines[k])]
	count(ks) > 0
	s := max(ks) + 1
} else := max([0, i - 3])

# The look-ahead likewise stops before the next closing line.
_after_n(lines, i, after) := n if {
	hi := min([count(lines) - 1, i + after])
	hi > i
	ks := [k | some k in numbers.range(i + 1, hi); _closer(lines[k])]
	count(ks) > 0
	n := (min(ks) - i) - 1
} else := after

_window(lines, i, after) := helpers.code_window(lines, i, i - _before_start(lines, i), _after_n(lines, i, after)) if i > 0

_window(lines, 0, after) := helpers.code_window(lines, 0, 0, _after_n(lines, 0, after))

# A name that says the value is a credential, a secret or an authenticator.
_security_re := `(?i)(passw|passwd|pwd|\bpw\b|\$pass|\bpass_|_pass\b|\bpass\b|secret|token|session_?id|sessid|cookie|signature|\bsig\b|\bsign\b|\botp\b|nonce|csrf|xsrf|api_?key|credential|\bsalt|reset|auth_?code)`

# Lines after the call that can still be part of it: a JVM MessageDigest is
# fed by the statements that follow; elsewhere the input is on the call line.
_after(_, line) := 3 if contains(line, "MessageDigest")

_after(_, line) := 1 if not contains(line, "MessageDigest")

# HMAC over SHA-1 is not the collision-resistance use this rule is about.
_hmac(line) if regex.match(`(?i)hmac`, line)

# Explicitly not a security use.
_non_security(line) if regex.match(`usedforsecurity\s*=\s*False`, line)

# The digest of a constant identifies something; it protects nothing.
_non_security(line) if regex.match(`\b(md5|sha1)\(\s*(static::class|self::class|__CLASS__|'[^']*'|"[^"$]*")\s*\)`, line)

# Python: hashlib.new( wrapped, the algorithm name on the next line.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "hashlib.new(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\bhashlib\.new\(\s*$`, line)
	not helpers.is_comment_line(line)
	i + 1 < count(lines)
	regex.match(`^\s*['"](md5|sha1)['"]`, lines[i + 1])
	not _non_security(concat("\n", array.slice(lines, i, i + 4)))
	regex.match(_security_re, _window(lines, i, 4))
	finding := {
		"rule_id": metadata.id,
		"message": "MD5/SHA-1 used on a password, token, secret or signature; use HMAC-SHA256 or SHA-256 for tokens and signatures and argon2id/bcrypt/scrypt for passwords",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	re := _call(path, content)
	regex.match(re, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(re, line)
	count(line) < 400
	not helpers.is_comment_line(line)
	not _hmac(line)
	not _non_security(line)
	regex.match(_security_re, _window(lines, i, _after(path, line)))
	not _c7_owns(path, content, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "MD5/SHA-1 used on a password, token, secret or signature; use HMAC-SHA256 or SHA-256 for tokens and signatures and argon2id/bcrypt/scrypt for passwords",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── lines VNX-CRYPTO-007 reports ────────────────────────────────────────
# A fast digest whose argument names a password is VNX-CRYPTO-007's finding
# (a password hashed with a fast hash). This is that rule's own test, kept
# in step with it, so a line is only handed over when it reports the line.
_c7_lang(path) := "python" if endswith(path, ".py")

_c7_lang(path) := "node" if {
	regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)
	not endswith(path, ".min.js")
}

_c7_lang(path) := "java" if endswith(path, ".java")

_c7_lang(path) := "php" if endswith(path, ".php")

_c7_lang(path) := "ruby" if endswith(path, ".rb")

_c7_lang(path) := "go" if endswith(path, ".go")

_c7_strings := {
	"python": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"node": "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`]*`",
	"java": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"php": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"ruby": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"go": "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`",
}

_c7_tail := {
	"python": `#.*$`,
	"node": `//.*$`,
	"java": `//.*$`,
	"php": `(?://|#).*$`,
	"ruby": `#.*$`,
	"go": `//.*$`,
}

_c7_code(lang, line) := c if {
	s1 := regex.replace(line, `['"](?i:md5|sha-?(?:1|224|256|384|512)|sha3-\d+|sha)['"]`, "__FAST__")
	s3 := regex.replace(s1, `\[\s*['"](\w+)['"]\s*\]`, "[__k_${1}]")
	s4 := regex.replace(s3, `\.(?:FormValue|PostFormValue|getParameter|get|param|fetch|input|post|query|Get)\s*\(\s*['"](\w+)['"]\s*\)`, ".__k_${1}")
	t := regex.replace(s4, _c7_strings[lang], `""`)
	c := regex.replace(t, _c7_tail[lang], "")
}

_c7_fast := {
	"python": [
		`\bhashlib\.(?:md5|sha1|sha224|sha256|sha384|sha512|sha3_\d+|blake2[bs])\s*\((.*)$`,
		`\bhashlib\.new\s*\(\s*__FAST__\s*,(.*)$`,
	],
	"node": [
		`\bcreateHash\s*\(\s*__FAST__\s*\)\s*\.update\s*\((.*)$`,
		`\bCryptoJS\.(?:MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3)\s*\((.*)$`,
	],
	"java": [
		`\bMessageDigest\.getInstance\s*\([^)]*\)\s*\.(?:digest|update)\s*\((.*)$`,
		`\bDigestUtils\.(?:md5|sha1|sha256|sha384|sha512|sha|md2)(?:Hex)?\s*\((.*)$`,
		`\bHashing\.(?:md5|sha1|sha256|sha384|sha512)\s*\(\s*\)\s*\.hash\w*\s*\((.*)$`,
	],
	"php": [
		`(?i)(?:^|[^\w>:$\\])(?:md5|sha1)\s*\((.*)$`,
		`(?i)\bhash\s*\(\s*__FAST__\s*,(.*)$`,
	],
	"go": [
		`\b(?:md5|sha1)\.Sum\s*\((.*)$`,
		`\bsha256\.Sum(?:256|224)\s*\((.*)$`,
		`\bsha512\.Sum(?:512|384|512_256)\s*\((.*)$`,
	],
	"ruby": [`\b(?:OpenSSL::)?Digest::(?:MD5|SHA1|SHA256|SHA384|SHA512|SHA2|RMD160)\.(?:hexdigest|digest|base64digest)\s*\(?(.*)$`],
}

_c7_py_imported(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+hashlib\s+import\s+([^\n#]+)`, content, -1)
	some part in split(regex.replace(m[1], `[()]`, ""), ",")
	t := regex.split(`\s+as\s+`, trim_space(part))
	t[0] in {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}
	n := t[count(t) - 1]
}

_c7_pw_ident(id) if {
	regex.match(`(?i)passw(?:or)?d|passphrase`, id)
	not _c7_not_pw(id)
}

_c7_pw_ident(id) if {
	regex.match(`(?i)^\$?(?:pass|pwd|pw)(?:_[a-z]\w*)?$|_(?:pass|pwd)$|[a-z](?:Pass|Pwd)$`, id)
	not _c7_not_pw(id)
}

_c7_not_pw(id) if regex.match(`(?i)token|reset|hash|digest|length|len$|policy|field|label|url|hint|count|attempt|expir|strength|regex|rule|error|msg|message|salt|key|through|port`, id)

_c7_names_password(rest) if {
	some id in regex.find_n(`[A-Za-z_$][\w$]*`, rest, -1)
	_c7_pw_ident(id)
}

_c7_rest(lang, code, _) if {
	some p in _c7_fast[lang]
	m := regex.find_all_string_submatch_n(p, code, 1)
	count(m) > 0
	_c7_names_password(m[0][count(m[0]) - 1])
}

_c7_rest("python", code, content) if {
	some n in _c7_py_imported(content)
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, n, `\s*\((.*)$`]), code, 1)
	count(m) > 0
	_c7_names_password(m[0][1])
}

_c7_api := ["hashlib", "createHash", "CryptoJS.", "MessageDigest", "DigestUtils", "Hashing.", "Digest::", "md5(", "md5 (", "MD5(", "sha1(", "sha1 (", "SHA1(", "hash(", "hash (", "Md5", "Sha1", "Sha256", "SHA256", "Sha512", "Sum256", "Sum512", "md5.Sum", "sha1.Sum"]

_c7_pw := ["pass", "Pass", "PASS", "pwd", "Pwd", "PWD", "pw"]

_c7_any(content, toks) if {
	some t in toks
	contains(content, t)
}

_c7_owns(path, content, lines, i) if {
	lang := _c7_lang(path)
	_c7_any(content, _c7_api)
	_c7_any(content, _c7_pw)
	not helpers.is_test_path(path)
	line := lines[i]
	count(line) < 1000
	regex.match(`pass|Pass|PASS|pwd|Pwd|PWD|pw\b|PW\b`, line)
	regex.match(`md5|MD5|Md5|Sum|sha|SHA|Sha|igest|update|blake|hash\s*\(`, line)
	code := _c7_code(lang, line)
	_c7_rest(lang, code, content)
	not regex.match(`(?i)hmac`, code)
	not regex.match(`(?i)pwned|/range/|\[:5\]|substr\s*\([^)]*,\s*0\s*,\s*5\s*\)`, helpers.code_window(lines, i, 4, 4))
}
