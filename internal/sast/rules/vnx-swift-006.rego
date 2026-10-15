package vulnetix.rules.vnx_swift_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-SWIFT-006",
	"name": "Swift non-cryptographic PRNG (libc rand/random/drand48, GameplayKit) used for a security value",
	"description": "Reports a Swift call to a non-cryptographic generator, the libc rand(), random(), drand48(), lrand48(), mrand48(), erand48()/nrand48()/jrand48() or a GameplayKit random source or distribution (GKRandomSource, GKARC4RandomSource, GKLinearCongruentialRandomSource, GKMersenneTwisterRandomSource, GKRandomDistribution, GKGaussianDistribution, GKShuffledDistribution, which Apple documents as unsuitable for cryptography), when the result is a security value: the line, or a let/var opened up to three lines above it, assigns a name ending with token, nonce, salt, secret, password/passcode/passphrase, otp, csrf, sessionId, challenge, apiKey, a *Key, IV or PIN, or a verification/reset/auth/OTP code; or the enclosing function or type is named for one (generateToken, makeNonce, generateSessionKey, makeResetCode, enum OTP) and the line does not assign a jitter/delay/backoff/interval/colour/index-style value; and a nextInt/nextUniform/nextBool draw, assigned to such a name, from a variable the file assigns a GameplayKit source or distribution (let otp = source.nextInt(upperBound: 1_000_000)). Verification, reset, auth, OTP, challenge and confirmation codes count as security values. Not reported: arc4random(), arc4random_uniform(), arc4random_buf(), SystemRandomNumberGenerator, Int.random(in:) and other .random() members (all backed by the system CSPRNG on Apple platforms), SecRandomCopyBytes and CryptoKit, generators used for shuffling, jitter, delays, colours or cache/sort keys, seeding calls on their own, string literals, comment lines and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-swift-006/",
	"languages": ["swift"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [338],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["weak-random", "cryptography", "swift", "ios"],
}

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)[^/]*Tests?/`, path)

_is_test(path) if regex.match(`Tests?\.swift$`, path)

_strip(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`)

_gate_re := `rand\(|random\(|rand48\(|GK(?:Random|ARC4Random|LinearCongruentialRandom|MersenneTwisterRandom)Source|GK(?:Random|Gaussian|Shuffled)Distribution`

_weak_re := `(?:^|[^\w.])(?:rand|random|drand48|lrand48|mrand48)\s*\(\s*\)|(?:^|[^\w.])(?:erand48|nrand48|jrand48)\s*\(|\bGK(?:Random|ARC4Random|LinearCongruentialRandom|MersenneTwisterRandom)Source\b|\bGK(?:Random|Gaussian|Shuffled)Distribution\b`

# a name that holds a security value (identifier-final word)
_sensitive_name(n) if regex.match(`(token|nonce|salt|secret|password|passcode|passphrase|otp|csrf|sessionid|session_id|challenge|apikey|api_key|(?:verification|reset|auth|otp|pin|challenge|confirm|confirmation|invite|security|access|onetime|one_time)_?code)$`, lower(n))

_sensitive_name(n) if {
	regex.match(`(?:^(?:key|iv|pin)$|[a-z0-9_](?:Key|IV|Iv|Pin|PIN)$|_(?:key|iv|pin)$|^(?:IV|PIN)$)`, n)
	not regex.match(`(?i)(cache|sort|dict|lookup|primary|index|row|section|item|map|user|coding|hash|table|path|store|storage|default|font|color|key)key$`, n)
}

# a function or type named for one: generateToken, makeNonce, generateSessionKey
_sensitive_decl(n) if regex.match(`(?i)(token|nonce|salt|secret|password|passcode|otp|csrf|sessionid|apikey|(?:verification|reset|auth|otp|challenge|confirm|confirmation|invite|security|onetime)_?code)`, n)

_sensitive_decl(n) if regex.match(`(?:Key|IV|Pin|PIN)(?:[A-Z_]|s?$)`, n)

_assigns_sensitive(l) if {
	some m in regex.find_all_string_submatch_n(`(?:\b(?:let|var)\s+|^\s*(?:self\.)?)([A-Za-z_]\w*)\s*(?::[^=]*)?=[^=]`, l, -1)
	_sensitive_name(m[1])
}

_assigns_sensitive(l) if {
	some m in regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\[[^\]]*\]\s*=[^=]`, l, -1)
	_sensitive_name(m[1])
}

_enclosing_decl(lines, i) := n if {
	cands := [j |
		some j in numbers.range(max([0, i - 30]), i)
		regex.match(`\b(?:func|class|struct|enum|extension|actor)\s+[A-Za-z_]`, lines[j])
	]
	count(cands) > 0
	m := regex.find_all_string_submatch_n(`\b(?:func|class|struct|enum|extension|actor)\s+([A-Za-z_]\w*)`, lines[max(cands)], 1)
	n := m[0][1]
}

_security_context(lines, i) if {
	some j in numbers.range(max([0, i - 3]), i)
	not helpers.is_comment_line(lines[j])
	_assigns_sensitive(_strip(lines[j]))
}

_security_context(lines, i) if {
	_sensitive_decl(_enclosing_decl(lines, i))
	not regex.match(`(?i)\b(?:let|var)\s+\w*(?:jitter|delay|backoff|interval|timeout|retry|wait|sleep|colou?r|offset|index|idx|shuffle|duration|position|angle|speed|tint|alpha|hue)\b`, lines[i])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".swift")
	not _is_test(path)
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate_re, line)
	not helpers.is_comment_line(line)
	regex.match(_weak_re, regex.replace(_strip(line), `\bfunc\s+\w+`, "func _"))
	_security_context(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "A security value is produced with a non-cryptographic generator (libc rand/random/drand48 or GameplayKit), whose output is predictable; use SecRandomCopyBytes, CryptoKit (SymmetricKey, AES.GCM.Nonce) or SystemRandomNumberGenerator",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# a GameplayKit source or distribution held in a variable, then drawn from
# into a security value: let otp = source.nextInt(upperBound: 1_000_000)
_gk_vars(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`(?:let|var)\s+([A-Za-z_]\w*)\s*(?::[^=\n]*)?=\s*GK(?:Random|ARC4Random|LinearCongruentialRandom|MersenneTwisterRandom)Source\b|(?:let|var)\s+([A-Za-z_]\w*)\s*(?::[^=\n]*)?=\s*GK(?:Random|Gaussian|Shuffled)Distribution\b`, content, -1)
} | {m[2] |
	some m in regex.find_all_string_submatch_n(`(?:let|var)\s+([A-Za-z_]\w*)\s*(?::[^=\n]*)?=\s*GK(?:Random|ARC4Random|LinearCongruentialRandom|MersenneTwisterRandom)Source\b|(?:let|var)\s+([A-Za-z_]\w*)\s*(?::[^=\n]*)?=\s*GK(?:Random|Gaussian|Shuffled)Distribution\b`, content, -1)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".swift")
	not _is_test(path)
	contains(content, ".next")
	regex.match(`GK(?:Random|ARC4Random|LinearCongruentialRandom|MersenneTwisterRandom)Source|GK(?:Random|Gaussian|Shuffled)Distribution`, content)
	vars := _gk_vars(content) - {""}
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".next")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.])(?:self\.)?([A-Za-z_]\w*)\.next(?:Int|Uniform|Bool)\s*\(`, _strip(line), -1)
	m[1] in vars
	_assigns_sensitive(_strip(line))
	finding := {
		"rule_id": metadata.id,
		"message": "A security value is drawn from a GameplayKit random source, which Apple documents as unsuitable for cryptography; use SecRandomCopyBytes, CryptoKit or SystemRandomNumberGenerator",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
