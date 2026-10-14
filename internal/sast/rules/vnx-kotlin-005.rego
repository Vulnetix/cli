package vulnetix.rules.vnx_kotlin_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-KOTLIN-005",
	"name": "Kotlin MD5 or SHA-1 used as cryptographic hash",
	"description": "A broken hash (MD5, SHA-1, or the older MD2/MD4) is computed through a hash API. MD5 and SHA-1 have practical collision attacks and, being fast, are trivially brute-forced when they protect passwords; use SHA-256/SHA-3 for integrity and signatures and bcrypt/scrypt/Argon2 for passwords. Reported in Kotlin (.kt, .kts): MessageDigest.getInstance(\"MD5\"/\"SHA-1\"/\"SHA1\"/\"SHA\"/\"MD2\"/\"MD4\", any case, with or without a provider, wrapped or not), the same through a constant the file assigns once or a commons-codec MessageDigestAlgorithms.MD5/SHA_1/MD2 constant; Signature.getInstance(\"SHA1withRSA\"/\"MD5withRSA\"/...); Apache Commons Codec DigestUtils.md5/md5Hex/sha1/sha1Hex/sha/shaHex/md2/md2Hex/getMd5Digest/getSha1Digest, new DigestUtils(MD5/SHA_1) and statically imported md5Hex()/sha1Hex(); Guava Hashing.md5()/sha1(); and Okio ByteString/Buffer .md5()/.sha1() or HashingSink/HashingSource md5/sha1 when the hashed value is named as a password, secret, token, credential or PIN. Not reported: SHA-256 and stronger, HMAC constructions (HmacSHA1, HmacUtils, Hashing.hmacMd5, Okio hmacSha1), SHA1PRNG, OAEP padding names, Okio digests used as cache keys, file names or certificate fingerprints, the SHA-1 that RFC 6455 mandates for Sec-WebSocket-Accept, an algorithm variable whose value is not fixed in the file, enum entries and string lists of algorithm names, test code, and the calls in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-kotlin-005/",
	"languages": ["kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [328],
	"capec": ["CAPEC-461"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["crypto", "hash", "weak-hash", "kotlin"],
}

_message := "MD5/SHA-1 (or MD2/MD4) used as a cryptographic hash; use SHA-256 or SHA-3 for integrity and signatures, and bcrypt, scrypt or Argon2 for passwords"

_is_kotlin(path) if endswith(path, ".kt")

_is_kotlin(path) if endswith(path, ".kts")

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)src/[A-Za-z]*[Tt]est[A-Za-z]*/`, path)

_is_test(path) if regex.match(`(Test|Tests|Spec|IT)\.kts?$`, path)

_is_test(path) if regex.match(`(^|/)([\w.]+[-_])?test(s|ing)?([-_][\w.-]+)?/`, path)

# String-literal contents blanked, trailing comment cut.
_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

_joined(lines, i) := concat(" ", [l | some l in array.slice(lines, i, i + 3); not helpers.is_comment_line(l)])

_weak_name(s) if regex.match(`^(?i:MD2|MD4|MD5|SHA|SHA-?1)$`, s)

# The value of an identifier the file assigns exactly once.
_single_value(content, id) := v if {
	re := concat("", [`\b`, id, `\s*(?::\s*[\w.?]+)?\s*=\s*([^=\n][^\n]*)`])
	ms := regex.find_all_string_submatch_n(re, content, -1)
	count(ms) == 1
	v := ms[0][1]
}

_weak_arg(arg, _) if {
	m := regex.find_all_string_submatch_n(`^"([^"]*)"$`, arg, 1)
	count(m) > 0
	_weak_name(m[0][1])
}

_weak_arg(arg, _) if regex.match(`^(?:org\.apache\.commons\.codec\.digest\.)?MessageDigestAlgorithms\.(MD2|MD5|SHA_1)$`, arg)

_weak_arg(arg, content) if {
	regex.match(`^[A-Za-z_]\w*$`, arg)
	m := regex.find_all_string_submatch_n(`^\s*"([^"]*)"`, _single_value(content, arg), 1)
	count(m) > 0
	_weak_name(m[0][1])
}

# RFC 6455 fixes SHA-1 for the WebSocket accept key; it is not a choice.
_websocket(lines, i) if {
	w := concat("\n", array.slice(lines, max([0, i - 8]), i + 9))
	regex.match(`258EAFA5-E914-47DA-95CA-C5AB0DC85B11|(?i:sec-?websocket-?accept)`, w)
}

# The fingerprint of the app's own signing certificate (the "key hash" that
# identity-provider consoles ask for) is an identifier, not a protection.
_app_signature(lines, i) if {
	w := concat("\n", array.slice(lines, max([0, i - 8]), i + 5))
	regex.match(`signingInfo|GET_SIGNATURES|GET_SIGNING_CERTIFICATES|apkContentsSigners|signingCertificateHistory|\.signatures\b`, w)
}

# Gradle build logic: repositories still require .md5/.sha1 sidecar checksums.
_build_script(path) if endswith(path, ".gradle.kts")

_build_script(path) if regex.match(`(^|/)(buildSrc|build-logic)/`, path)

_credential(txt) if regex.match(`(?i)(passw|secret|token|credential|\bpin|\botp\b|\bssn\b)`, txt)

# MessageDigest.getInstance("MD5") and friends
_weak(lines, i, code, content) if {
	regex.match(`\bMessageDigest\s*\.\s*getInstance\s*\(`, code)
	m := regex.find_all_string_submatch_n(`\bMessageDigest\s*\.\s*getInstance\s*\(\s*("[^"]*"|[\w.]+)\s*[,)]`, _joined(lines, i), 1)
	count(m) > 0
	_weak_arg(m[0][1], content)
	not _websocket(lines, i)
	not _app_signature(lines, i)
}

# Signature.getInstance("SHA1withRSA") used to sign. Verifying a signature
# someone else produced (store receipts, legacy partners) is not a choice of
# algorithm and is not reported.
_weak(lines, i, code, content) if {
	regex.match(`\bSignature\s*\.\s*getInstance\s*\(`, code)
	m := regex.find_all_string_submatch_n(`\bSignature\s*\.\s*getInstance\s*\(\s*("[^"]*"|[\w.]+)\s*[,)]`, _joined(lines, i), 1)
	count(m) > 0
	_weak_sig(m[0][1], content)
	not _verify_only(lines, i)
}

_weak_sig_re := `^\s*"(?i:MD2|MD5|SHA1?|SHA-1)with\w+"`

_weak_sig(arg, _) if regex.match(_weak_sig_re, arg)

_weak_sig(arg, content) if {
	regex.match(`^[A-Za-z_]\w*$`, arg)
	regex.match(_weak_sig_re, _single_value(content, arg))
}

_verify_only(lines, i) if {
	w := concat("\n", array.slice(lines, i, i + 8))
	contains(w, "initVerify")
	not contains(w, "initSign")
}

# Commons Codec and Spring DigestUtils
_weak(_, _, code, _) if regex.match(`\bDigestUtils\s*\.\s*(md2|md2Hex|md5|md5Hex|sha|shaHex|sha1|sha1Hex|getMd2Digest|getMd5Digest|getShaDigest|getSha1Digest|md5Digest|md5DigestAsHex|appendMd5DigestAsHex)\s*\(`, code)

# Bouncy Castle lightweight digests, except as the PRF of an HMAC, PBKDF2,
# HKDF or OAEP/MGF1 construction
_weak(_, _, code, _) if {
	regex.match(`(?:^|[^\w.])(?:org\.bouncycastle\.crypto\.digests\.)?(MD2|MD4|MD5|SHA1)Digest\s*\(`, code)
	not regex.match(`(?i:hmac)|ParametersGenerator|HKDF|OAEP|MGF1`, code)
}

_weak(_, _, code, _) if regex.match(`\bDigestFactory\s*\.\s*create(MD5|SHA1)\s*\(`, code)

_weak(_, _, code, _) if regex.match(`\bDigestUtils\s*\(\s*(?:org\.apache\.commons\.codec\.digest\.)?MessageDigestAlgorithms\.(MD2|MD5|SHA_1)\s*\)`, code)

_weak(lines, i, code, _) if {
	regex.match(`\bDigestUtils\s*\(\s*""`, code)
	regex.match(`\bDigestUtils\s*\(\s*"(?i:MD2|MD4|MD5|SHA|SHA-?1)"`, lines[i])
}

# md5Hex(x) after `import org.apache.commons.codec.digest.DigestUtils.md5Hex`
_weak(_, _, code, content) if {
	some name in _imported(content)
	regex.match(concat("", [`(?:^|[^\w.])`, name, `\s*\(`]), code)
	not regex.match(concat("", [`\bfun\s+(?:[\w.<>]+\.)?`, name, `\b`]), code)
}

# Guava Hashing.md5() / sha1()
_weak(_, _, code, _) if regex.match(`\bHashing\s*\.\s*(md5|sha1)\s*\(\s*\)`, code)

# Okio .md5() / .sha1() / HashingSink.md5(...) over a credential
_weak(lines, i, code, _) if {
	regex.match(`(\.(md5|sha1)\s*\(\s*\)|\bHashing(Sink|Source)\s*\.\s*(md5|sha1)\s*\()`, code)
	not regex.match(`\bHashing\s*\.\s*(md5|sha1)\s*\(`, code)
	ctx := concat("\n", [_code(l) | some l in array.slice(lines, max([0, i - 2]), i + 1); not helpers.is_comment_line(l)])
	_credential(ctx)
	not _websocket(lines, i)
}

_imported(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`import\s+org\.apache\.commons\.codec\.digest\.DigestUtils\.(md2Hex|md5Hex|sha1Hex|shaHex)\b`, content, -1)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_kotlin(path)
	regex.match(`(?i)md[245]|sha[-_]?1|"sha"`, content)
	not _is_test(path)
	not _build_script(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)md[245]|sha|digest|getInstance`, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	_weak(lines, i, code, content)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
