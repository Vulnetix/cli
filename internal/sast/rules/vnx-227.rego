# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_227

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-227",
	"name": "Improper Fulfillment of API Contract: security verification result ignored",
	"description": "A security API whose return value is the verdict is called as a bare statement, so the verdict is thrown away and the code carries on as if the check passed: a password check, a MAC or constant-time comparison, a signature verification, or an OpenSSL certificate/RNG call. Reported as a statement on its own (also with Go's `_ =` and C's `(void)`, because discarding a verdict verifies nothing): Go hmac.Equal, subtle.ConstantTimeCompare, bcrypt.CompareHashAndPassword, rsa.VerifyPKCS1v15/VerifyPSS, ecdsa.Verify/VerifyASN1, ed25519.Verify; Python hmac/secrets.compare_digest, bcrypt.checkpw, check_password_hash, check_password, passlib verify; Node.js crypto.timingSafeEqual, crypto.verify, bcrypt.compare/compareSync, argon2.verify and verify() on a crypto.createVerify() object; PHP password_verify, hash_equals, openssl_verify, sodium verify functions, plus openssl_verify used directly as an if condition (its -1 error result is truthy); Ruby secure_compare and fixed_length_secure_compare, has_secure_password authenticate; Java MessageDigest.isEqual, BCrypt.checkpw, a PasswordEncoder's matches() and verify() on a java.security.Signature; C/C++ SSL_get_verify_result, X509_verify_cert, RAND_bytes, RAND_priv_bytes, EVP_DigestVerify(Final), EVP_VerifyFinal, RSA/ECDSA/DSA_verify, CRYPTO_memcmp. Not reported: a result that is assigned, returned, tested or part of an expression (also across line breaks), the last expression of a Ruby method or block (its return value), a call that hands the verdict to a callback, APIs that raise on failure (jwt.verify, a JWTVerifier, cryptography's and argon2-cffi's verify), comments, string literals and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-227/",
	"languages": ["c", "cpp", "go", "java", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [227],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["api-contract", "unchecked-return", "authentication", "signature-verification", "cwe-227"],
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "rb" if endswith(path, ".rb")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx)$`, path)

_lang(path) := "c" if regex.match(`\.(?:c|h|cc|cpp|cxx|hpp|hh)$`, path)

# Literal substrings one of which every reportable file contains (a substring
# test is far cheaper than a regular expression over the whole file).
_gate := {
	"go": ["hmac.Equal", "ConstantTimeCompare", "CompareHashAndPassword", "rsa.Verify", "ecdsa.Verify", "ed25519.Verify"],
	"py": ["compare_digest", "checkpw", "check_password", ".verify("],
	"php": ["password_verify", "hash_equals", "openssl_verify", "sodium_"],
	"rb": ["secure_compare", ".authenticate("],
	"java": ["MessageDigest.isEqual", "BCrypt.checkpw", "ncoder.matches", "Signature ", "Signature.getInstance"],
	"js": ["timingSafeEqual", "crypto.verify", "bcrypt", "argon2.verify", "createVerify"],
	"c": ["SSL_get_verify_result", "X509_verify_cert", "RAND_bytes", "RAND_priv_bytes", "VerifyFinal", "DigestVerify", "_verify(", "CRYPTO_memcmp"],
}

_gated(lang, content) if {
	some s in _gate[lang]
	contains(content, s)
}

_apis := {
	"go": `hmac\.Equal|subtle\.ConstantTimeCompare|bcrypt\.CompareHashAndPassword|rsa\.VerifyPKCS1v15|rsa\.VerifyPSS|ecdsa\.VerifyASN1|ecdsa\.Verify|ed25519\.VerifyWithOptions|ed25519\.Verify`,
	"py": `(?:hmac\.|secrets\.)?compare_digest|bcrypt\.checkpw|check_password_hash|(?:[\w\.]+\.)?check_password|pwd_context\.verify|(?:pbkdf2_sha256|sha256_crypt|sha512_crypt|bcrypt_sha256|argon2|scrypt)\.verify`,
	"php": `password_verify|hash_equals|openssl_verify|sodium_crypto_sign_verify_detached|sodium_crypto_pwhash_str_verify|sodium_memcmp`,
	"rb": `(?:(?:ActiveSupport::SecurityUtils|Rack::Utils|OpenSSL)\.)?(?:fixed_length_secure_compare|secure_compare)|@?\w+\.authenticate`,
	"java": `MessageDigest\.isEqual|BCrypt\.checkpw|\w*[Ee]ncoder\.matches`,
	"js": `(?:crypto\.)?timingSafeEqual|crypto\.verify|(?:bcrypt|bcryptjs)\.(?:compareSync|compare)|argon2\.verify`,
	"c": `SSL_get_verify_result|X509_verify_cert|RAND_priv_bytes|RAND_bytes|EVP_DigestVerifyFinal|EVP_DigestVerify|EVP_VerifyFinal|RSA_verify|ECDSA_verify|DSA_verify|CRYPTO_memcmp`,
}

# Objects whose verify() returns the verdict: a java.security.Signature and a
# Node.js crypto.createVerify() verifier.
_receiver_re := {
	"java": `(?:\bSignature\s+(\w+)\s*=|(\w+)\s*=\s*Signature\.getInstance\()`,
	"js": `(\w+)\s*=\s*(?:crypto\.)?createVerify\(`,
}

_receivers(lang, content) := {r |
	some m in regex.find_all_string_submatch_n(_receiver_re[lang], content, -1)
	some k in [1, 2]
	k < count(m)
	r := m[k]
	r != ""
}

_api_re(lang, content) := concat("|", array.concat([_apis[lang]], [concat("", [`\b`, r, `\.verify`]) | some r in _receivers(lang, content)]))

# Prefix allowed before the call on a bare statement.
_prefix := `^\s*(?:await\s+)?(?:\(void\)\s*|_\s*(?:,\s*_\s*)?:?=\s*)?`

_args := `\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`

_stmt_re(api) := concat("", [_prefix, `(?:`, api, `)\s*`, _args, `\s*;?[ \t]*(?:(?://|#)[^\n]*)?(?:\n|$)`])

# Some line of the file starts a statement with one of the APIs (or with any
# verify() call, for the receiver-typed objects).
_file_gate(lang) := concat("", [`(?m)`, _prefix, `(?:`, _apis[lang], `|\w+\.verify)\s*\(`])

_start_re(api) :=concat("", [_prefix, `(?:`, api, `)\s*\(`])

# The previous code line leaves an expression open: this line continues it.
_continues(lines, i) if {
	i > 0
	some k in numbers.range(max([0, i - 3]), i - 1)
	k < i
	trim_space(lines[k]) != ""
	not helpers.is_comment_line(lines[k])
	not _code_between(lines, k, i)
	regex.match(`(?:[=(,?+\-!\[\\]|&&|\|\||=>|\breturn|\band|\bor|\bnot|\bunless|\bif|\bwhile)\s*$`, lines[k])
}

_code_between(lines, k, i) if {
	k + 1 <= i - 1
	some m in numbers.range(k + 1, i - 1)
	trim_space(lines[m]) != ""
	not helpers.is_comment_line(lines[m])
}

# Ruby returns the last expression of a method or block.
_ruby_return(lines, end_line) if {
	j := helpers.next_code_index(lines, end_line, 4)
	regex.match(`^\s*(?:end\b|\}|else\b|elsif\b|rescue\b|ensure\b|when\b)`, lines[j])
}

_bare(path, lang, lines, i, api) if {
	window := concat("\n", array.slice(lines, i, i + 9))
	m := regex.find_n(_stmt_re(api), window, 1)
	count(m) == 1
	stmt := m[0]
	not regex.match(`=>|\bfunction\s*\(|\bdo\s*\|`, stmt)
	end_line := i + count(split(trim_right(stmt, "\n"), "\n")) - 1
	not _rb_returned(lang, lines, end_line)
}

_rb_returned("rb", lines, end_line) if _ruby_return(lines, end_line)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gated(lang, content)
	regex.match(_file_gate(lang), content)
	not helpers.is_test_path(path)
	api := _api_re(lang, content)
	start := _start_re(api)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(start, line)
	not helpers.is_comment_line(line)
	not _continues(lines, i)
	_bare(path, lang, lines, i, api)
	finding := {
		"rule_id": metadata.id,
		"message": "The result of this security check is discarded, so a failed check is never acted on. Test the return value (or error) and stop when verification fails",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# openssl_verify returns 1, 0 or -1 (error); -1 is truthy, so a bare if
# condition accepts an error as a valid signature.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "openssl_verify")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "openssl_verify")
	not helpers.is_comment_line(line)
	regex.match(concat("", [`\b(?:if|elseif|while)\s*\(\s*!?\s*openssl_verify\s*`, _args, `\s*\)`]), line)
	finding := {
		"rule_id": metadata.id,
		"message": "openssl_verify() returns -1 on error, which is truthy: compare its result with === 1",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
