# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_crypto_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-001",
	"name": "MD5 usage detected",
	"description": "MD5 is computed through a hash or signature API: Python hashlib.md5()/hashlib.new('md5') (module and from-import aliases resolved), PyCryptodome MD5.new() and cryptography hashes.MD5(); Node.js crypto.createHash('md5')/createSign('RSA-MD5'), CryptoJS.MD5() and the md5/blueimp-md5/js-md5/spark-md5 packages under the name they are imported as; Go crypto/md5 md5.New/md5.Sum (aliased import resolved) and x509.MD5WithRSA; Java MessageDigest/Signature.getInstance(\"MD5\"/\"MD5withRSA\") with the name given literally, through a variable, field or constant (also one declared on another class) that holds it, directly, in a ternary, or from a getProperty/@Value lookup that resolves to the value the project's .properties or YAML files give the key, else the lookup default, commons-codec DigestUtils.md5*, Guava Hashing.md5() and BouncyCastle MD5Digest; Ruby Digest::MD5 and OpenSSL::Digest.new('MD5'); PHP md5(), md5_file(), hash('md5') and openssl_digest(..., 'md5'). MD5 collisions are cheap to produce, so it must not protect integrity, signatures, tokens or passwords; use SHA-256 or stronger (argon2/bcrypt/scrypt for passwords). Not reported: HMAC-MD5 (hmac.new(k, m, hashlib.md5), createHmac('md5'), hmac.New(md5.New, k), HmacMD5, hash_hmac('md5')), PBKDF2 or HKDF over MD5, Python calls declaring usedforsecurity=False, a field, header or method merely named md5, the import alone and constants such as md5.Size, the algorithm named inside a string literal (an SQL md5() call) or a comment, documentation, and test files. An MD5 digest that protects a security value is reported by a more precise rule instead, so the line is reported once: a password passed straight into it by VNX-CRYPTO-007 (a password hashed with a fast hash), and one with a password, secret, token, session id, cookie, signature, salt, nonce, CSRF value or API key named around the call by VNX-327 (a broken hash protecting a security value).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-001/",
	"languages": ["python", "node", "go", "java", "ruby", "php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [327, 328],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["weak-crypto", "md5", "hash"],
}

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "node" if {
	regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)
	not endswith(path, ".min.js")
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "ruby" if endswith(path, ".rb")

_lang(path) := "php" if endswith(path, ".php")

# An algorithm-name literal ('md5', "MD5", `md5`, 'RSA-MD5', "MD5withRSA")
# becomes a sentinel before string literals are blanked, so the call that
# names it is still recognisable while the same text inside a longer string
# (an SQL md5() call, a warning message) is not.
_md5_lit := "['\"`](?i:(?:rsa-)?md5(?:with\\w*)?)['\"`]"

_strings := {
	"python": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"node": "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`]*`",
	"go": "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`",
	"java": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"ruby": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"php": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
}

_tail_comment := {
	"python": `#.*$`,
	"node": `//.*$`,
	"go": `//.*$`,
	"java": `//.*$`,
	"ruby": `#.*$`,
	"php": `(?://|#).*$`,
}

_code(lang, line) := c if {
	s := regex.replace(line, _md5_lit, "__MD5__")
	t := regex.replace(s, _strings[lang], `""`)
	c := regex.replace(t, _tail_comment[lang], "")
}

# ── call shapes that need no import resolution ──────────────────────────
_static := {
	"python": [
		`\bhashes\.MD5\s*\(`,
		`\bCrypto(?:dome)?\.Hash\.MD5\.new\s*\(`,
	],
	"node": [
		`\bcreate(?:Hash|Sign|Verify)\s*\(\s*__MD5__`,
		`\bCryptoJS\.MD5\s*\(`,
		`\bforge\.md\.md5\.create\s*\(`,
	],
	"go": [`\bx509\.MD5WithRSA\b`],
	"java": [
		`\b(?:MessageDigest|Signature)\.getInstance\s*\(\s*__MD5__`,
		`\bDigestUtils\.(?:md5\w*|getMd5Digest)\s*\(`,
		`\bHashing\.md5\s*\(`,
		`\bnew\s+MD5Digest\s*\(`,
		`\bMessageDigestAlgorithms\.MD5\b`,
	],
	"ruby": [
		`\bDigest::MD5\.(?:hexdigest|digest|base64digest|new|file|hexencode)\b`,
		`\bOpenSSL::Digest\.(?:new|digest|hexdigest|base64digest)\s*\(\s*__MD5__`,
	],
	"php": [
		`(?i)(?:^|[^\w>:$\\])\\?md5(?:_file)?\s*\(`,
		`(?i)\bhash(?:_file|_init)?\s*\(\s*__MD5__`,
		`(?i)\bopenssl_digest\s*\([^;]*__MD5__`,
		`\bOPENSSL_ALGO_MD5\b`,
	],
}

# A call whose algorithm argument starts on the next line.
_open_call := {
	"python": `\bhashlib\.new\s*\(\s*$`,
	"node": `\bcreate(?:Hash|Sign|Verify)\s*\(\s*$`,
	"java": `\b(?:MessageDigest|Signature)\.getInstance\s*\(\s*$`,
	"ruby": `\bOpenSSL::Digest\.new\s*\(\s*$`,
	"php": `(?i)\bhash(?:_file)?\s*\(\s*$`,
}

# ── names bound by imports or assignments in this file ──────────────────

# import-list entries "md5" / "md5 as x" -> local name
_import_names(list, want) := {n |
	some part in split(regex.replace(list, `[()]`, ""), ",")
	m := regex.find_all_string_submatch_n(concat("", [`^\s*`, want, `(?:\s+as\s+(\w+))?\s*$`]), part, 1)
	count(m) > 0
	n := _alias_or(m[0][1], want)
}

_alias_or(alias, want) := want if alias == ""

_alias_or(alias, _) := alias if alias != ""

_bound("python", content) := pats if {
	mods := {"hashlib"} | {m[1] | some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+hashlib\s+as\s+(\w+)`, content, -1)}
	funcs := {n |
		some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+hashlib\s+import\s+([^\n#]+)`, content, -1)
		some n in _import_names(m[1], "md5")
	}
	pyc := {n |
		some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+Crypto(?:dome)?\.Hash\s+import\s+([^\n#]+)`, content, -1)
		some n in _import_names(m[1], "MD5")
	}
	pats := (({concat("", [`(?:^|[^\w.])`, m, `\.md5\s*\(`]) | some m in mods} | {concat("", [`(?:^|[^\w.])`, m, `\.new\s*\(\s*__MD5__`]) | some m in mods}) | {concat("", [`(?:^|[^\w.])`, f, `\s*\(`]) | some f in funcs}) | {concat("", [`(?:^|[^\w.])`, c, `\.new\s*\(`]) | some c in pyc}
}

_md5_pkgs := `(?:md5|blueimp-md5|js-md5|crypto-js/md5|md5\.js|spark-md5|md5-hex)`

_bound("node", content) := pats if {
	req := {m[1] | some m in regex.find_all_string_submatch_n(concat("", [`\b(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]`, _md5_pkgs, `['"]\s*\)`]), content, -1)}
	imp := {m[1] | some m in regex.find_all_string_submatch_n(concat("", [`(?m)^\s*import\s+(?:\*\s+as\s+)?(\w+)\s+from\s+['"]`, _md5_pkgs, `['"]`]), content, -1)}
	names := req | imp
	pats := ({concat("", [`(?:^|[^\w.])`, n, `(?:\.(?:hash|hex|create|update|base64|array|arrayBuffer|digest))?\s*\(`]) | some n in names} | {concat("", [`\bnew\s+`, n, `\s*\(`]) | some n in names})
}

_bound("go", content) := {concat("", [`(?:^|[^\w.])`, n, `\.(?:New|Sum)\b`]) | some n in _go_names(content)}

_bound("java", content) := {concat("", [`\b(?:MessageDigest|Signature)\.getInstance\s*\(\s*(?:[\w.]+\.)?`, v, `\s*[,)]`]) | some v in helpers.java_global_consts(_weak_alg)}

_bound("ruby", _) := set()

_bound("php", _) := set()

_go_names(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*(?:import\s+)?(?:(\w+)\s+)?"crypto/md5"`, content, -1)
	not m[1] in {"_", "."}
	n := _alias_or(m[1], "md5")
}

# Java: a variable, field or constant that holds the algorithm name: assigned
# the literal, a ternary of literals, a properties lookup (the value the
# project's own configuration gives the key, else the default) or a Spring
# @Value placeholder.
_weak_alg := `^(?i:(?:rsa-)?md5(?:with\w*)?)$`

_java_vars(content) := helpers.java_alg_vars(content, _weak_alg)

# Cheap substrings (compared case-insensitively) for skipping lines that
# cannot match.
_tokens("java", content) := {"md5", "getinstance"} | {lower(v) | some v in _java_vars(content)}

_tokens("go", content) := {"md5"} | {lower(n) | some n in _go_names(content)}

_tokens("python", content) := {"md5"} | {lower(m[1]) |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*(?:from\s+hashlib\s+import\s+[^\n#]*\bmd5\s+as\s+|import\s+hashlib\s+as\s+)(\w+)`, content, -1)
}

_tokens("node", content) := {"md5"} | {lower(m[1]) |
	some m in regex.find_all_string_submatch_n(concat("", [`\b(?:const|let|var|import)\s+(?:\*\s+as\s+)?(\w+)\s*(?:=\s*require\s*\(|from)\s*['"]`, _md5_pkgs, `['"]`]), content, -1)
}

_tokens("ruby", _) := {"md5"}

_tokens("php", _) := {"md5"}

_may(line, toks) if {
	l := lower(line)
	some t in toks
	contains(l, t)
}

_may(line, _) if endswith(trim_right(line, " \t\r"), "(")

_hit(_, _, _, code, pats) if {
	some p in pats
	regex.match(p, code)
}

# an inline lookup or ternary as the algorithm argument
_hit("java", lines, i, _, _) if helpers.java_inline_alg(lines[i], _weak_alg)

# getInstance(name): the assignments to name in the enclosing method decide; a
# name with none there (a field, a constant) falls back to the file's.
_hit("java", lines, i, code, _) if {
	m := regex.find_all_string_submatch_n(`\b(?:MessageDigest|Signature)\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*[,)]`, code, 1)
	count(m) > 0
	v := m[0][1]
	vals := _local_alg_values(lines, i, v)
	count(vals) > 0
	some x in vals
	regex.match(_weak_alg, x)
}

_hit("java", lines, i, code, _) if {
	m := regex.find_all_string_submatch_n(`\b(?:MessageDigest|Signature)\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*[,)]`, code, 1)
	count(m) > 0
	v := m[0][1]
	count(_local_assigns(lines, i, v)) == 0
	not _declared_here(lines, i, v)
	v in _java_vars(concat("\n", lines))
}

_local_assigns(lines, i, v) := [{"k": k, "rhs": m[1]} |
	some k in helpers.span(helpers.flow_method_start(lines, i), i - 1)
	not helpers.is_comment_line(lines[k])
	some m in regex.find_all_string_submatch_n(concat("", [`(?:^|[^=!<>\w.])`, v, `\s*=\s*([^;=][^;]*);`]), lines[k], -1)
]

_indent(l) := count(l) - count(trim_left(l, " \t"))

# An assignment at the call's own block level (or shallower) replaces every one
# above it; those in branches after it, and all of them when none is at that
# level (a switch, an if/else), can each be the value that runs.
_dom_floor(lines, i, all) := max(doms) if {
	doms := [a.k | some a in all; _indent(lines[a.k]) <= _indent(lines[i])]
	count(doms) > 0
} else := 0

_scoped_assigns(lines, i, v) := [a |
	all := _local_assigns(lines, i, v)
	b := _dom_floor(lines, i, all)
	some a in all
	a.k >= b
]

_local_alg_values(lines, i, v) := {x |
	some a in _scoped_assigns(lines, i, v)
	some x in helpers.java_rhs_values(a.rhs)
}

# v is a parameter or a local of the enclosing method, so a field or constant of
# the same name elsewhere in the file is not what it holds
_declared_here(lines, i, v) if {
	s := helpers.flow_method_start(lines, i)
	some k in helpers.span(max([0, s - 3]), i - 1)
	regex.match(concat("", [`\b(?:String|var)\s+`, v, `\b`]), lines[k])
}

_hit(lang, lines, i, code, _) if {
	regex.match(_open_call[lang], code)
	j := helpers.next_code_index(lines, i, 2)
	regex.match(`^\s*__MD5__`, _code(lang, lines[j]))
}

# HMAC over MD5 does not rely on collision resistance.
_excluded(_, _, _, code) if regex.match(`(?i)hmac|pbkdf2|hkdf`, code)

# Python 3.9+: the call itself declares a non-security use.
_excluded("python", lines, i, _) if {
	end := min([count(lines) - 1, i + 3])
	some k in numbers.range(i, end)
	regex.match(`\busedforsecurity\s*=\s*False\b`, lines[k])
}

# The digest is the variable part of a name: concatenated straight after a
# literal ending in a separator ('login_'.md5(...), "cache:" + md5(...)) or
# straight before one (md5(...).':'.$key, md5(...) + ".json").
_excluded(_, lines, i, _) if {
	regex.match("['\"`][^'\"`]*[_\\-/:.]['\"`]\\s*[.+]\\s*\\\\?[\\w.]*(?i:md5)\\w*\\s*\\(", lines[i])
}

_excluded(_, lines, i, _) if {
	regex.match("(?i:md5)\\w*\\s*\\([^;]*\\)\\s*[.+]\\s*['\"`][_\\-/:.]", lines[i])
}

# a definition named md5, not a call
_excluded("python", _, _, code) if regex.match(`^\s*(?:async\s+)?def\s`, code)

_excluded("php", _, _, code) if regex.match(`(?i)\bfunction\s+&?\s*md5`, code)

# the algorithm name is in the text, or a Java getInstance is handed something
# other than a literal (a variable, a lookup) that configuration may resolve
_gate(content) if regex.match(`(?i)md5`, content)

_gate(content) if regex.match(`\b(?:MessageDigest|Signature)\.getInstance\s*\(\s*[^")\s]`, content)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(content)
	not helpers.is_test_path(path)
	pats := {p | some p in _static[lang]} | _bound(lang, content)
	toks := _tokens(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	_may(line, toks)
	count(line) < 1000 # a minified or bundled line is not the project's code
	not helpers.is_comment_line(line)
	code := _code(lang, line)
	_hit(lang, lines, i, code, pats)
	not _excluded(lang, lines, i, code)
	not _handed_over(path, content, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "MD5 is computed here; MD5 collisions are cheap, so it cannot protect integrity, signatures, tokens or passwords. Use SHA-256 or stronger (argon2, bcrypt or scrypt for passwords)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── lines VNX-327 reports ───────────────────────────────────────────────
# An MD5/SHA-1 digest with a password, secret, token, session id, cookie,
# signature, salt, nonce, CSRF value or API key named around the call is
# VNX-327's finding (a broken hash protecting a security value); a password
# hashed directly is VNX-CRYPTO-007's. This is VNX-327's own test, kept in step
# with it, so a line is only handed over when that rule reports it.
_r327_py_call := `\bhashlib\.(md5|sha1)\s*\(|\bhashlib\.new\(\s*['"](md5|sha1)['"]`

_r327_call(path, content) := _r327_py_call if {
	endswith(path, ".py")
	not regex.match(`(?m)^\s*from\s+hashlib\s+import\s+[^\n]*\b(md5|sha1)\b`, content)
}

_r327_call(path, content) := concat("|", [_r327_py_call, `(^|[^\w.])(md5|sha1)\s*\(`]) if {
	endswith(path, ".py")
	regex.match(`(?m)^\s*from\s+hashlib\s+import\s+[^\n]*\b(md5|sha1)\b`, content)
}

_r327_call(path, _) := `\bcreateHash\(\s*['"\x60](md5|sha-?1)['"\x60]|\bCryptoJS\.(MD5|SHA1)\(` if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_r327_call(path, _) := `\bMessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"|\bDigestUtils\.(md5|sha1|sha)(Hex|DigestAsHex|Digest)?\s*\(|\bHashing\.(md5|sha1)\(\s*\)` if endswith(path, ".java")

_r327_call(path, _) := `(^|[^\w>:$\\])(md5|sha1)(_file)?\s*\(` if endswith(path, ".php")

_r327_call(path, _) := `\b(OpenSSL::)?Digest::(MD5|SHA1)\b|\bOpenSSL::Digest\.new\(\s*['"](?i:md5|sha1)['"]` if endswith(path, ".rb")

_r327_closer(l) if regex.match(`^\s*(\}[\s;),]*|end)\s*$`, l)

_r327_before_start(lines, i) := s if {
	lo := max([0, i - 3])
	ks := [k | some k in numbers.range(lo, i - 1); _r327_closer(lines[k])]
	count(ks) > 0
	s := max(ks) + 1
} else := max([0, i - 3])

_r327_after_n(lines, i, after) := n if {
	hi := min([count(lines) - 1, i + after])
	hi > i
	ks := [k | some k in numbers.range(i + 1, hi); _r327_closer(lines[k])]
	count(ks) > 0
	n := (min(ks) - i) - 1
} else := after

_r327_window(lines, i, after) := helpers.code_window(lines, i, i - _r327_before_start(lines, i), _r327_after_n(lines, i, after)) if i > 0

_r327_window(lines, 0, after) := helpers.code_window(lines, 0, 0, _r327_after_n(lines, 0, after))

_r327_security_re := `(?i)(passw|passwd|pwd|\bpw\b|\$pass|\bpass_|_pass\b|\bpass\b|secret|token|session_?id|sessid|cookie|signature|\bsig\b|\bsign\b|\botp\b|nonce|csrf|xsrf|api_?key|credential|\bsalt|reset|auth_?code)`

_r327_after(line) := 3 if contains(line, "MessageDigest")

_r327_after(line) := 1 if not contains(line, "MessageDigest")

_r327_non_security(line) if regex.match(`usedforsecurity\s*=\s*False`, line)

_r327_non_security(line) if regex.match(`\b(md5|sha1)\(\s*(static::class|self::class|__CLASS__|'[^']*'|"[^"$]*")\s*\)`, line)

_r327_owns(path, content, lines, i) if {
	re := _r327_call(path, content)
	not helpers.is_test_path(path)
	line := lines[i]
	regex.match(re, line)
	count(line) < 400
	not regex.match(`(?i)hmac`, line)
	not _r327_non_security(line)
	regex.match(_r327_security_re, _r327_window(lines, i, _r327_after(line)))
}

# Python hashlib.new( with the algorithm on the next line.
_r327_owns(path, _, lines, i) if {
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(`\bhashlib\.new\(\s*$`, lines[i])
	i + 1 < count(lines)
	regex.match(`^\s*['"](md5|sha1)['"]`, lines[i + 1])
	not _r327_non_security(concat("\n", array.slice(lines, i, i + 4)))
	regex.match(_r327_security_re, _r327_window(lines, i, 4))
}

# VNX-327 hands a password hashed directly to VNX-CRYPTO-007, so a line is
# either one's or the other's.
_handed_over(path, content, lines, i) if _r327_owns(path, content, lines, i)

_handed_over(path, content, lines, i) if _c7_owns(path, content, lines, i)

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
