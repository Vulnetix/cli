package vulnetix.rules.vnx_php_016

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-016",
	"name": "PHP weak hash function (md5/sha1)",
	"description": "A password is hashed with MD5 or SHA-1, fast unsalted digests that GPUs and rainbow tables reverse in bulk. Reported: md5(), sha1(), hash('md5'|'sha1'|'md4'|'md2', ...) and MD5-crypt (crypt() with a '$1$' salt) when an argument names a password (a variable, property or array key such as $pass, $pass_new, $password, $userPassword, $pwd, $_POST['password'], $input['passwd']) or when the result is assigned to one ($user->password = md5(...), $hashedPassword = sha1(...), 'password' => md5(...)). Not reported: password_hash()/password_verify(), md5/sha1 of non-credential data (cache keys, ETags, checksums, md5_file(), the SHA-1 prefix sent to the Have I Been Pwned range API), hash('sha256', ...) (a fast hash for passwords is still weak but outside this rule), a digest of nothing but a random generator stored under a password name (substr(md5(rand()), 0, 8) generating a temporary password), password-reset tokens, lookalike names such as $bypass, and the call inside a comment or a string literal. Any MD5/SHA-1 use regardless of purpose is reported by VNX-327, VNX-CRYPTO-001 and VNX-CRYPTO-002.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-016/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [328],
	"capec": ["CAPEC-55"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["weak-crypto", "hashing", "php"],
}

_lit_re := `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`

_code(line) := regex.replace(line, _lit_re, `''`)

_args_re := `((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`

_call_re := `(?i)(?:^|[^\w>:$\\])(?:md5|sha1)\s*\(|\bhash\s*\(|\bcrypt\s*\(`

# The argument lists of every weak-hash call on the line.
_weak_args(line) := {a |
	some m in regex.find_all_string_submatch_n(concat("", [`(?i)(?:^|[^\w>:$\\])(?:md5|sha1)\s*\(`, _args_re]), line, -1)
	a := m[1]
} | {a |
	some m in regex.find_all_string_submatch_n(concat("", [`(?i)\bhash\s*\(\s*['"](?:md5|sha1|md4|md2)['"]\s*,`, _args_re]), line, -1)
	a := m[1]
} | {a |
	some m in regex.find_all_string_submatch_n(concat("", [`(?i)\bcrypt\s*\(`, _args_re]), line, -1)
	regex.match(`,\s*['"]\$1\$`, m[1])
	a := m[1]
}

_pw_name_re := `(?i)^(pass|pw|pwd|passwd|password|passphrase)$|passw(or)?d|passwd|passphrase|pwd|^pass_|_pass$|^(new|old|cur|curr|current|confirm|user|plain|admin|login)_?pass`

_names(text) := {n |
	some m in regex.find_all_string_submatch_n(`\$(\w+)|->(\w+)|\[\s*['"](\w+)['"]\s*\]`, text, -1)
	n := concat("", [m[1], m[2], m[3]])
}

# Names that mention a password but hold something else: a form field id,
# a label, a reset token, a policy or length setting.
_not_credential_re := `(?i)(reset|forgot|recover|policy|rule|regex|pattern|field|label|placeholder|selector|input_?id|_?id|ids|name|url|link|len|length|count|attempts|expir\w*|min|max|hint|key|token|class|type)$|reset`

_pw_name(n) if {
	regex.match(_pw_name_re, n)
	not regex.match(_not_credential_re, n)
}

_password(text) if {
	some n in _names(text)
	_pw_name(n)
}

# The name the result is stored under: $var = , $obj->prop = , $arr['key'] = ,
# or 'key' => in an array literal.
_lhs_name(line) := n if {
	m := regex.find_all_string_submatch_n(`^\s*['"](\w+)['"]\s*=>`, line, 1)
	n := m[0][1]
}

_lhs_name(line) := n if {
	not regex.match(`^\s*['"]\w+['"]\s*=>`, line)
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)((?:->\w+|\[\s*['"]?\w+['"]?\s*\])*)\s*\.?=[^=>]`, line, 1)
	n := _last(m[0][1], m[0][2])
}

_last(base, "") := base

_last(_, chain) := n if {
	chain != ""
	ms := regex.find_all_string_submatch_n(`(\w+)['"]?\s*\]?\s*$`, chain, 1)
	n := ms[0][1]
}

_weak_for_password(line) if {
	some a in _weak_args(line)
	_password(a)
}

# A digest of nothing but a random generator is a generated value (a
# temporary password built as substr(md5(rand()), 0, 8)), not a stored
# password hash.
_random_only(a) if {
	not contains(a, "$")
	regex.match(`(?i)^\s*(rand|mt_rand|uniqid|random_bytes|random_int|microtime|time|openssl_random_pseudo_bytes|lcg_value|str_shuffle)\s*\(`, a)
}

_weak_for_password(line) if {
	some a in _weak_args(line)
	not _random_only(a)
	_pw_name(_lhs_name(line))
}


findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`(?i)\b(md5|sha1|hash|crypt)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)(md5|sha1|hash|crypt)\s*\(`, line)
	not helpers.is_comment_line(line)
	regex.match(_call_re, _code(line))
	_weak_for_password(line)
	not _c7_owns(path, content, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Password hashed with MD5/SHA-1, which is fast and unsalted; use password_hash($password, PASSWORD_ARGON2ID or PASSWORD_BCRYPT) and password_verify()",
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
