# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_crypto_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-001",
	"name": "MD5 usage detected",
	"description": "MD5 is computed through a hash or signature API: Python hashlib.md5()/hashlib.new('md5') (module and from-import aliases resolved), PyCryptodome MD5.new() and cryptography hashes.MD5(); Node.js crypto.createHash('md5')/createSign('RSA-MD5'), CryptoJS.MD5() and the md5/blueimp-md5/js-md5/spark-md5 packages under the name they are imported as; Go crypto/md5 md5.New/md5.Sum (aliased import resolved) and x509.MD5WithRSA; Java MessageDigest/Signature.getInstance(\"MD5\"/\"MD5withRSA\") with the name given literally, through a variable or constant assigned \"MD5\" or as a getProperty default, commons-codec DigestUtils.md5*, Guava Hashing.md5() and BouncyCastle MD5Digest; Ruby Digest::MD5 and OpenSSL::Digest.new('MD5'); PHP md5(), md5_file(), hash('md5') and openssl_digest(..., 'md5'). MD5 collisions are cheap to produce, so it must not protect integrity, signatures, tokens or passwords; use SHA-256 or stronger (argon2/bcrypt/scrypt for passwords). Not reported: HMAC-MD5 (hmac.new(k, m, hashlib.md5), createHmac('md5'), hmac.New(md5.New, k), HmacMD5, hash_hmac('md5')), PBKDF2 or HKDF over MD5, Python calls declaring usedforsecurity=False, a field, header or method merely named md5, the import alone and constants such as md5.Size, the algorithm named inside a string literal (an SQL md5() call) or a comment, documentation, and test files.",
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

_bound("java", content) := {concat("", [`\b(?:MessageDigest|Signature)\.getInstance\s*\(\s*`, v, `\s*[,)]`]) | some v in _java_vars(content)}

_bound("ruby", _) := set()

_bound("php", _) := set()

_go_names(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*(?:import\s+)?(?:(\w+)\s+)?"crypto/md5"`, content, -1)
	not m[1] in {"_", "."}
	n := _alias_or(m[1], "md5")
}

# Java: a variable or constant assigned the "MD5" literal, directly or as the
# default of a properties lookup.
_java_vars(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b(\w+)\s*=\s*(?:"(?i:md5)"|[\w.]*getProperty\s*\(\s*"[^"]*"\s*,\s*"(?i:md5)"\s*\))\s*[;,)]`, content, -1)
}

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

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(`(?i)md5`, content)
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
