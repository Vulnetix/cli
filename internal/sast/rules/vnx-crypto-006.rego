package vulnetix.rules.vnx_crypto_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-006",
	"name": "Weak RSA key size",
	"description": "An RSA key pair is generated with a modulus below 2048 bits, given literally or through a constant assigned in the same file. Reported: Python cryptography rsa.generate_private_key(key_size=N) (one line or wrapped, keyword or positional, also through an import alias whose name contains rsa), PyCryptodome RSA.generate(N), python-rsa newkeys(N) and pyOpenSSL generate_key(TYPE_RSA, N); Go rsa.GenerateKey(rand, N) and rsa.GenerateMultiPrimeKey(rand, k, N); Java initialize(N) on a KeyPairGenerator obtained with getInstance(\"RSA\") and new RSAKeyGenParameterSpec(N, ...) (also wrapped); Node.js generateKeyPair/generateKeyPairSync('rsa'|'rsa-pss', { modulusLength: N }), WebCrypto crypto.subtle.generateKey({ name: 'RSA-OAEP'|'RSASSA-PKCS1-v1_5'|'RSA-PSS', modulusLength: N }) (one line or wrapped), node-forge rsa.generateKeyPair({ bits: N }) and node-rsa new NodeRSA({ b: N }). Keys under 2048 bits are within reach of factoring and are disallowed by NIST SP 800-131A; use 3072 bits or more, or an elliptic-curve key. Not reported: sizes of 2048 and above, a size taken from a parameter or configuration, EC, DSA, DH and symmetric key sizes, initialize() on anything other than an RSA KeyPairGenerator, the call inside a string literal or a comment, and test files (small keys there are a speed choice).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-006/",
	"languages": ["python", "go", "java", "node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [326],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["weak-crypto", "rsa", "key-size"],
}

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "node" if {
	regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)
	not endswith(path, ".min.js")
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_gate := {
	"python": `generate_private_key|RSA\.generate|newkeys|TYPE_RSA`,
	"node": `modulusLength|generateKeyPair|NodeRSA`,
	"go": `rsa\.Generate`,
	"java": `KeyPairGenerator|RSAKeyGenParameterSpec`,
}

_strings := {
	"python": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"node": "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`]*`",
	"go": "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`",
	"java": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
}

_tail_comment := {
	"python": `#.*$`,
	"node": `//.*$`,
	"go": `//.*$`,
	"java": `//.*$`,
}

# 'rsa' / "RSA" / 'rsa-pss' survive string blanking as a sentinel.
_code(lang, line) := c if {
	s := regex.replace(line, `['"](?i:rsa(?:-pss)?)['"]`, "__RSA__")
	t := regex.replace(s, _strings[lang], `""`)
	c := regex.replace(t, _tail_comment[lang], "")
}

# Patterns whose first capture group is the key size token (a number or a
# constant name).
_pats := {
	"python": [
		`\b\w*(?i:rsa)\.generate_private_key\s*\([^)]*\bkey_size\s*=\s*(\w+)`,
		`\b\w*(?i:rsa)\.generate_private_key\s*\(\s*\w+\s*,\s*(\w+)\s*[,)]`,
		`\bRSA\.generate\s*\(\s*(?:bits\s*=\s*)?(\w+)`,
		`\bnewkeys\s*\(\s*(?:nbits\s*=\s*)?(\w+)`,
		`\bgenerate_key\s*\(\s*(?:[\w.]*\.)?TYPE_RSA\s*,\s*(\w+)`,
	],
	"node": [
		`\bgenerateKeyPair(?:Sync)?\s*\(\s*__RSA__\s*,\s*\{[^}]*\bmodulusLength\s*:\s*(\w+)`,
		`\brsa\.generateKeyPair\s*\(\s*(?:\{[^}]*\bbits\s*:\s*)?(\w+)`,
		`\bnew\s+NodeRSA\s*\(\s*\{[^}]*\bb\s*:\s*(\w+)`,
		`\bsubtle\.generateKey\s*\(.*\bmodulusLength\s*:\s*(\w+)`,
	],
	"go": [
		`\brsa\.GenerateKey\s*\(\s*[^,()]+(?:\([^)]*\))?\s*,\s*(\w+)\s*\)`,
		`\brsa\.GenerateMultiPrimeKey\s*\(\s*[^,()]+(?:\([^)]*\))?\s*,\s*\w+\s*,\s*(\w+)\s*\)`,
	],
	"java": [`\bnew\s+RSAKeyGenParameterSpec\s*\(\s*(\w+)`],
}

# name = 1024 / const bits = 1024 / static final int KEY_SIZE = 1024;
_consts(content) := {[m[1], to_number(m[2])] |
	some m in regex.find_all_string_submatch_n(`(?m)\b([A-Za-z_]\w*)\s*:?=\s*(\d{3,5})\s*;?\s*(?:(?://|#).*)?$`, content, -1)
}

_weak(tok, _) if {
	regex.match(`^\d{3,5}$`, tok)
	n := to_number(tok)
	n < 2048
	n >= 256
}

_weak(tok, consts) if {
	not regex.match(`^\d`, tok)
	some c in consts
	c[0] == tok
	n := c[1]
	n < 2048
	n >= 256
}

_hit(lang, _, _, code, _, consts) if {
	some p in _pats[lang]
	m := regex.find_all_string_submatch_n(p, code, 1)
	count(m) > 0
	_weak(m[0][1], consts)
}

# Python: key_size=N on its own line inside a wrapped rsa.generate_private_key(
_hit("python", lines, i, code, _, consts) if {
	m := regex.find_all_string_submatch_n(`^\s*key_size\s*=\s*(\w+)\s*[,)]?\s*$`, code, 1)
	count(m) > 0
	_opened_above(lines, i, `\b\w*(?i:rsa)\.generate_private_key\s*\(`)
	_weak(m[0][1], consts)
}

# Node: modulusLength: N inside a wrapped generateKeyPair('rsa', {
_hit("node", lines, i, code, _, consts) if {
	m := regex.find_all_string_submatch_n(`^\s*modulusLength\s*:\s*(\w+)\s*,?\s*$`, code, 1)
	count(m) > 0
	_opened_above(lines, i, `\bgenerateKeyPair(?:Sync)?\s*\(\s*__RSA__`)
	_weak(m[0][1], consts)
}

# WebCrypto: only the RSA algorithms take a modulusLength
_hit("node", lines, i, code, _, consts) if {
	m := regex.find_all_string_submatch_n(`^\s*modulusLength\s*:\s*(\w+)\s*,?\s*$`, code, 1)
	count(m) > 0
	_opened_above(lines, i, `\bsubtle\.generateKey\s*\(`)
	_weak(m[0][1], consts)
}

# Java: new RSAKeyGenParameterSpec( with the size on the next line
_hit("java", lines, i, code, _, consts) if {
	regex.match(`\bnew\s+RSAKeyGenParameterSpec\s*\(\s*$`, code)
	j := helpers.next_code_index(lines, i, 2)
	m := regex.find_all_string_submatch_n(`^\s*(\w+)`, lines[j], 1)
	count(m) > 0
	_weak(m[0][1], consts)
}

# Java: gen.initialize(N ...) where gen came from KeyPairGenerator.getInstance("RSA")
_hit("java", lines, i, code, gens, consts) if {
	m := regex.find_all_string_submatch_n(`\b(\w+)\.initialize\s*\(\s*(\w+)\s*[,)]`, code, 1)
	count(m) > 0
	m[0][1] in gens
	_nearest_is_rsa(lines, i, m[0][1])
	_weak(m[0][2], consts)
}

# The nearest assignment above of the generator variable is an RSA one (the
# same name may be reused for a DSA generator elsewhere in the file).
_nearest_is_rsa(lines, i, v) if {
	ks := [k |
		some k in numbers.range(max([0, i - 60]), i)
		regex.match(concat("", [`\b`, v, `\s*=\s*KeyPairGenerator\s*\.\s*getInstance\s*\(`]), lines[k])
	]
	count(ks) > 0
	regex.match(`getInstance\s*\(\s*"(?i:rsa)"`, lines[max(ks)])
}

_opened_above(lines, i, re) if {
	some k in numbers.range(max([0, i - 4]), i - 1)
	k < i
	regex.match(re, regex.replace(lines[k], `['"](?i:rsa(?:-pss)?)['"]`, "__RSA__"))
}

_rsa_gens("java", content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b(\w+)\s*=\s*KeyPairGenerator\s*\.\s*getInstance\s*\(\s*"(?i:rsa)"`, content, -1)
}

_rsa_gens(lang, _) := set() if lang != "java"

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	not helpers.is_test_path(path)
	consts := _consts(content)
	gens := _rsa_gens(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 1000
	not helpers.is_comment_line(line)
	code := _code(lang, line)
	_hit(lang, lines, i, code, gens, consts)
	finding := {
		"rule_id": metadata.id,
		"message": "RSA key generated with a modulus below 2048 bits; such keys are within reach of factoring. Use 3072 bits or more, or an elliptic-curve key",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
