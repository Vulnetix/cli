package vulnetix.rules.vnx_py_017

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-017",
	"name": "MD5 or SHA1 used as password hash",
	"description": "A password is hashed with MD5 or SHA-1 in a .py file. Reported: hashlib.md5()/hashlib.sha1() (also through `import hashlib as h` and `from hashlib import md5, sha1 as x`), hashlib.new('md5'|'sha1', ...) and PyCryptodome MD5.new()/SHA1.new()/SHA.new() whose argument names a password (password, passwd, passphrase, pwd, pw, a request field keyed 'pass'/'password'), whose argument is a variable assigned from such a value in the 8 lines above, or an .update(password) on a hasher created by one of those calls in the 10 lines above; a call broken across lines is read on its next line. Both algorithms are fast and broken, so a dumped hash is cracked offline in hours; use argon2id, bcrypt, scrypt or PBKDF2 with a high iteration count. Not reported: MD5/SHA-1 of data that is not a password (cache keys, ETags, file checksums), a call with usedforsecurity=False (HTTP digest auth), hashing a password reset token, SHA-256 and the password KDFs, and the calls in comments or string literals. VNX-CRYPTO-007 covers the same weakness across more algorithms and languages.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-017/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-49"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["cryptography", "password", "hash", "python"],
}

# String contents blanked (quotes kept) and trailing comments removed, so a
# call named inside a string or a comment is not a call.
_code(line) := regex.replace(
	regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`),
	`#.*$`, "",
)

# hashlib and its `import hashlib as x` aliases.
_modules(content) := {"hashlib"} | {m[1] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+hashlib\s+as\s+(\w+)`, content, -1)
}

# md5/sha1 from-imported from hashlib, under the name they are bound to.
_from_names(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+hashlib\s+import\s+([^\n#]+)`, content, -1)
	some part in split(regex.replace(m[1], `[()\\]`, ""), ",")
	words := regex.split(`\s+`, trim_space(part))
	words[0] in {"md5", "sha1"}
	n := words[count(words) - 1]
}

_pycrypto(content) if regex.match(`(?m)^\s*from\s+(?:Crypto|Cryptodome)\.Hash\s+import\b`, content)

# _weak_rest returns the code after the opening parenthesis of a weak-hash
# constructor on this line.
_weak_rest(code, _, ctx) := m[0][1] if {
	some mod in ctx.modules
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, mod, `\.(?:md5|sha1)\s*\((.*)$`]), code, 1)
	count(m) > 0
}

_weak_rest(code, raw, ctx) := m[0][1] if {
	some mod in ctx.modules
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, mod, `\.new\s*\(\s*(?:""|'')(.*)$`]), code, 1)
	count(m) > 0
	regex.match(concat("", [mod, `\.new\s*\(\s*["'](?i:md5|sha-?1)["']`]), raw)
}

_weak_rest(code, _, ctx) := m[0][1] if {
	some n in ctx.from_names
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, n, `\s*\((.*)$`]), code, 1)
	count(m) > 0
}

_weak_rest(code, _, ctx) := m[0][1] if {
	ctx.pycrypto
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.])(?:MD5|SHA1?)\.new\s*\((.*)$`, code, 1)
	count(m) > 0
}

# The argument text, extended onto the next code line when the call is
# broken right after its opening parenthesis.
_arg(_, _, rest) := rest if trim_space(rest) != ""

_arg(lines, i, rest) := concat(" ", [lines[j], lines[k]]) if {
	trim_space(rest) == ""
	j := helpers.next_code_index(lines, i, 3)
	k := min([j + 1, count(lines) - 1])
}

_pw_re := `(?i)(?:passw(?:or)?d|passphrase|\bpwd|\bpw\b|_pw\b|\bpw_|\bpass\b|\bpass_|_pass\b)`

# A request field keyed by a password name: form["password"], .get('pass').
_pw_key_re := `(?i)(?:\[|\.get\()\s*["'](?:[\w-]*_)?(?:pass(?:word|wd|phrase)?|pwd|pw)(?:_?\d)?["']`

_names_password(arg, _) if regex.match(_pw_re, _code(arg))

_names_password(_, raw) if regex.match(_pw_key_re, raw)

# An f-string interpolating a password: f"{salt}{password}".
_names_password(_, raw) if {
	some m in regex.find_all_string_submatch_n(`\b[fF][rR]?(?:"[^"]*"|'[^']*')`, raw, -1)
	some b in regex.find_all_string_submatch_n(`\{([^{}]*)\}`, m[0], -1)
	regex.match(_pw_re, b[1])
}

_not_password(arg) if regex.match(`(?i)reset|token|usedforsecurity\s*=\s*False`, arg)

# A value assigned from a password expression in the lines above.
_source_re := `(?i)[^=!<>]=[^=].*(?:passw(?:or)?d|passphrase|\bpwd\b|["']pass["'])`

# The right-hand side must itself name a password in code, a request key or
# an f-string: `k != "password"` in a comprehension is a comparison, not a
# password value.
_tainted(lines, i, arg) if {
	i > 0
	some j in numbers.range(max([0, i - 8]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(_source_re, prev)
	v := helpers.assigned_first(prev)
	regex.match(concat("", [`\b`, v, `\b`]), _code(arg))
	m := regex.find_all_string_submatch_n(`[^=!<>]=([^=].*)$`, prev, 1)
	count(m) > 0
	_names_password(m[0][1], m[0][1])
}

_password_arg(_, _, arg, raw) if _names_password(arg, raw)

_password_arg(lines, i, arg, _) if _tainted(lines, i, arg)

_ctx(content) := {
	"modules": _modules(content),
	"from_names": _from_names(content),
	"pycrypto": _has_pycrypto(content),
}

_has_pycrypto(content) := true if _pycrypto(content)

_has_pycrypto(content) := false if not _pycrypto(content)

_findings_in(path, content) := {[i, line] |
	ctx := _ctx(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)md5|sha`, line)
	not helpers.is_comment_line(line)
	rest := _weak_rest(_code(line), line, ctx)
	arg := _arg(lines, i, rest)
	_password_arg(lines, i, arg, line)
	not _not_password(line)
	not _not_password(arg)
}

# h = hashlib.md5(); ... h.update(password)
_update_findings(content) := {[i, line] |
	ctx := _ctx(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".update(")
	m := regex.find_all_string_submatch_n(`^\s*(\w+)\.update\s*\((.*)$`, line, 1)
	count(m) > 0
	h := m[0][1]
	arg := m[0][2]
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := lines[j]
	regex.match(concat("", [`^\s*`, h, `\s*=`]), prev)
	_weak_rest(_code(prev), prev, ctx)
	_password_arg(lines, i, arg, line)
	not _not_password(line)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?i)md5|sha1|\bSHA\.new`, content)
	some hit in _findings_in(path, content) | _update_findings(content)
	not _c7_owns(path, content, split(content, "\n"), hit[0])
	finding := {
		"rule_id": metadata.id,
		"message": "A password is hashed with MD5 or SHA-1, which are fast and broken; use argon2id, bcrypt, scrypt or PBKDF2 with a high iteration count",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": hit[0] + 1,
		"snippet": hit[1],
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
