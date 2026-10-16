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
	not _c7_owns(path, content, lines, i)
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
