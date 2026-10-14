package vulnetix.rules.vnx_crypto_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-002",
	"name": "SHA-1 usage detected",
	"description": "SHA-1 is computed through a hash or signature API: Python hashlib.sha1()/hashlib.new('sha1') (module and from-import aliases resolved), PyCryptodome SHA1.new()/SHA.new() and cryptography hashes.SHA1(); Node.js crypto.createHash('sha1')/createSign('RSA-SHA1'), CryptoJS.SHA1() and the sha1/js-sha1/simple-sha1 packages under the name they are imported as; Go crypto/sha1 sha1.New/sha1.Sum (aliased import resolved), x509.SHA1WithRSA/ECDSAWithSHA1/DSAWithSHA1 and rsa.Sign*/Verify* with crypto.SHA1; Java MessageDigest/Signature.getInstance(\"SHA-1\"/\"SHA1\"/\"SHA\"/\"SHA1withRSA\") with the name given literally, through a variable or constant assigned it or as a getProperty default, commons-codec DigestUtils.sha1*/sha*, Guava Hashing.sha1() and BouncyCastle SHA1Digest; Ruby Digest::SHA1 and OpenSSL::Digest.new('SHA1'); PHP sha1(), sha1_file(), hash('sha1'), openssl_digest(..., 'sha1') and OPENSSL_ALGO_SHA1. Chosen-prefix SHA-1 collisions are practical (SHAttered, Shambles), so it must not protect integrity, signatures, tokens or passwords; use SHA-256 or stronger. Not reported: HMAC-SHA1 and PBKDF2-HMAC-SHA1 (hmac.new(k, m, hashlib.sha1), createHmac('sha1'), hmac.New(sha1.New, k), HmacSHA1, hash_hmac/hash_pbkdf2('sha1'), OpenSSL::HMAC), the RFC 6455 WebSocket accept key, the Have I Been Pwned range lookup (a SHA-1 cut to its five-character prefix), Python calls declaring usedforsecurity=False, a field, column or method merely named sha1, a hash constructor passed by reference (digestmod=hashlib.sha1, encryptor: Digest::SHA1), the import alone and constants such as sha1.Size, the algorithm named inside a string literal or a comment, documentation, and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-002/",
	"languages": ["python", "node", "go", "java", "ruby", "php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [328],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["weak-crypto", "sha1", "hash"],
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

# An algorithm-name literal ('sha1', "SHA-1", "SHA", `sha1`, 'RSA-SHA1',
# "SHA1withRSA") becomes a sentinel before string literals are blanked, so
# the call that names it is still recognisable while the same text inside a
# longer string (an SQL sha1() call, a warning message) is not.
_sha1_lit := "['\"`](?i:(?:rsa-|ecdsa-with-)?sha-?1(?:with\\w*)?|sha)['\"`]"

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
	s := regex.replace(line, _sha1_lit, "__SHA1__")
	t := regex.replace(s, _strings[lang], `""`)
	c := regex.replace(t, _tail_comment[lang], "")
}

# ── call shapes that need no import resolution ──────────────────────────
_static := {
	"python": [
		`\bhashes\.SHA1\s*\(`,
		`\bCrypto(?:dome)?\.Hash\.SHA1?\.new\s*\(`,
	],
	"node": [
		`\bcreate(?:Hash|Sign|Verify)\s*\(\s*__SHA1__`,
		`\bCryptoJS\.SHA1\s*\(`,
		`\bforge\.md\.sha1\.create\s*\(`,
	],
	"go": [
		`\bx509\.(?:SHA1WithRSA|ECDSAWithSHA1|DSAWithSHA1)\b`,
		`\brsa\.(?:Sign|Verify)\w*\s*\([^)]*\bcrypto\.SHA1\b`,
	],
	"java": [
		`\b(?:MessageDigest|Signature)\.getInstance\s*\(\s*__SHA1__`,
		`\bDigestUtils\.(?:sha1\w*|sha|shaHex|getSha1Digest|getShaDigest)\s*\(`,
		`\bHashing\.sha1\s*\(`,
		`\bnew\s+SHA1Digest\s*\(`,
		`\bMessageDigestAlgorithms\.SHA_1\b`,
	],
	"ruby": [
		`\bDigest::SHA1\.(?:hexdigest|digest|base64digest|new|file|hexencode)\b`,
		`\bOpenSSL::Digest\.(?:new|digest|hexdigest|base64digest)\s*\(\s*__SHA1__`,
	],
	"php": [
		`(?i)(?:^|[^\w>:$\\])\\?sha1(?:_file)?\s*\(`,
		`(?i)\bhash(?:_file|_init)?\s*\(\s*__SHA1__`,
		`(?i)\bopenssl_digest\s*\([^;]*__SHA1__`,
		`\bOPENSSL_ALGO_SHA1\b`,
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

# import-list entries "sha1" / "sha1 as x" -> local name
_import_names(list, want) := {n |
	some part in split(regex.replace(list, `[()]`, ""), ",")
	m := regex.find_all_string_submatch_n(concat("", [`^\s*`, want, `(?:\s+as\s+(\w+))?\s*$`]), part, 1)
	count(m) > 0
	n := _alias_or(m[0][1], want)
}

_alias_or(alias, want) := want if alias == ""

_alias_or(alias, _) := alias if alias != ""

_py_mods(content) := {"hashlib"} | {m[1] | some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+hashlib\s+as\s+(\w+)`, content, -1)}

_py_funcs(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+hashlib\s+import\s+([^\n#]+)`, content, -1)
	some n in _import_names(m[1], "sha1")
}

_py_crypto(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+Crypto(?:dome)?\.Hash\s+import\s+([^\n#]+)`, content, -1)
	some want in ["SHA1", "SHA"]
	some n in _import_names(m[1], want)
}

_bound("python", content) := pats if {
	mods := _py_mods(content)
	a := {concat("", [`(?:^|[^\w.])`, m, `\.sha1\s*\(`]) | some m in mods}
	b := {concat("", [`(?:^|[^\w.])`, m, `\.new\s*\(\s*__SHA1__`]) | some m in mods}
	c := {concat("", [`(?:^|[^\w.])`, f, `\s*\(`]) | some f in _py_funcs(content)}
	d := {concat("", [`(?:^|[^\w.])`, n, `\.new\s*\(`]) | some n in _py_crypto(content)}
	pats := ((a | b) | c) | d
}

_sha1_pkgs := `(?:sha1|js-sha1|crypto-js/sha1|simple-sha1)`

_node_names(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(concat("", [`\b(?:const|let|var|import)\s+(?:\*\s+as\s+)?(\w+)\s*(?:=\s*require\s*\(|from)\s*['"]`, _sha1_pkgs, `['"]`]), content, -1)
}

_bound("node", content) := pats if {
	names := _node_names(content)
	a := {concat("", [`(?:^|[^\w.])`, n, `(?:\.(?:hash|hex|create|update|digest|array|arrayBuffer))?\s*\(`]) | some n in names}
	b := {concat("", [`\bnew\s+`, n, `\s*\(`]) | some n in names}
	pats := a | b
}

_bound("go", content) := {concat("", [`(?:^|[^\w.])`, n, `\.(?:New|Sum)\b`]) | some n in _go_names(content)}

_bound("java", content) := {concat("", [`\b(?:MessageDigest|Signature)\.getInstance\s*\(\s*`, v, `\s*[,)]`]) | some v in _java_vars(content)}

_bound("ruby", _) := set()

_bound("php", _) := set()

_go_names(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*(?:import\s+)?(?:(\w+)\s+)?"crypto/sha1"`, content, -1)
	not m[1] in {"_", "."}
	n := _alias_or(m[1], "sha1")
}

# Java: a variable or constant assigned a SHA-1 name, directly or as the
# default of a properties lookup.
_java_vars(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b(\w+)\s*=\s*(?:"(?i:sha-?1|sha)"|[\w.]*getProperty\s*\(\s*"[^"]*"\s*,\s*"(?i:sha-?1|sha)"\s*\))\s*[;,)]`, content, -1)
}

# Cheap substrings (compared case-insensitively) for skipping lines that
# cannot match.
_tokens("java", content) := {"sha1", "sha-1", "getinstance", "digestutils"} | {lower(v) | some v in _java_vars(content)}

_tokens("go", content) := {"sha1"} | {lower(n) | some n in _go_names(content)}

_tokens("python", content) := (({"sha1"} | {lower(n) | some n in _py_mods(content)}) | {lower(n) | some n in _py_funcs(content)}) | {lower(n) | some n in _py_crypto(content)}

_tokens("node", content) := {"sha1", "sha-1"} | {lower(n) | some n in _node_names(content)}

_tokens("ruby", _) := {"sha1"}

_tokens("php", _) := {"sha1"}

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
	regex.match(`^\s*__SHA1__`, _code(lang, lines[j]))
}

# HMAC-SHA1 and PBKDF2-HMAC-SHA1 do not rely on collision resistance.
_excluded(_, _, _, code) if regex.match(`(?i)hmac`, code)

# Python 3.9+: the call itself declares a non-security use.
_excluded("python", lines, i, _) if {
	end := min([count(lines) - 1, i + 3])
	some k in numbers.range(i, end)
	regex.match(`\busedforsecurity\s*=\s*False\b`, lines[k])
}

# RFC 6455 fixes SHA-1 for the WebSocket opening handshake.
_ws_guid := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

_excluded(_, lines, i, _) if {
	contains(concat("\n", array.slice(lines, i, i + 4)), _ws_guid)
}

_excluded(_, lines, i, _) if {
	some name in _ws_names(lines)
	regex.match(concat("", [`\b`, name, `\b`]), concat("\n", array.slice(lines, i, i + 4)))
}

# The digest is the variable part of a name: concatenated straight after a
# literal ending in a separator ('login_'.sha1(...), "cache:" + sha1(...)) or
# straight before one (sha1(...).':'.$key, sha1(...) + ".json").
_excluded(_, lines, i, _) if {
	regex.match("['\"`][^'\"`]*[_\\-/:.]['\"`]\\s*[.+]\\s*\\\\?[\\w.]*(?i:sha-?1)\\w*\\s*\\(", lines[i])
}

_excluded(_, lines, i, _) if {
	regex.match("(?i:sha-?1)\\w*\\s*\\([^;]*\\)\\s*[.+]\\s*['\"`][_\\-/:.]", lines[i])
}

# a definition named sha1, not a call
_excluded("python", _, _, code) if regex.match(`^\s*(?:async\s+)?def\s`, code)

_excluded("php", _, _, code) if regex.match(`(?i)\bfunction\s+&?\s*sha1`, code)

# Have I Been Pwned k-anonymity lookup: the API is keyed by the first five
# hex characters of the SHA-1, so SHA-1 is mandated by the protocol.
_excluded(_, lines, i, _) if {
	w := helpers.code_window(lines, i, 4, 4)
	regex.match(`(?i)pwned|/range/|\[\s*:\s*5\s*\]|(?:substr|substring|slice)\s*\([^)]*\b0\s*,\s*5\s*\)`, w)
}

_ws_names(lines) := {m[1] |
	some l in lines
	contains(l, _ws_guid)
	some m in regex.find_all_string_submatch_n(`\b(\w+)\s*[:=]\s*['"]258EAFA5-E914-47DA-95CA-C5AB0DC85B11['"]`, l, 1)
}

_gate(content) if regex.match(`(?i)sha-?1|['"]sha['"]`, content)

_gate(content) if regex.match(`\bSHA\.new\b`, content)

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
	finding := {
		"rule_id": metadata.id,
		"message": "SHA-1 is computed here; chosen-prefix SHA-1 collisions are practical, so it cannot protect integrity, signatures, tokens or passwords. Use SHA-256 or stronger (argon2, bcrypt or scrypt for passwords)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
