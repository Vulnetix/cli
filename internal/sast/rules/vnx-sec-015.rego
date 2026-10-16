package vulnetix.rules.vnx_sec_015

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-SEC-015",
	"name": "JWT algorithm none attack",
	"description": "A JSON Web Token is issued unsigned, or accepted as an unsigned token, so anyone can forge one. Reported: 'none' among the allowed or signing algorithms (algorithms=[\"none\"], algorithms: ['HS256', 'none'], algorithm: 'none', 'algorithm' => 'none'), PyJWT jwt.encode(..., algorithm=None), a token header literal {\"alg\": \"none\"}; Ruby JWT.encode(payload, nil, 'none'); jjwt SignatureAlgorithm.NONE, the parser option .unsecured(), Jwts.parser()...parse(token) on a parser given no signing key (the generic parse, which accepts an unsigned token before jjwt 0.12), parseClaimsJwt/parsePlaintextJwt/parseUnsecuredClaims; auth0 Algorithm.none(); Nimbus PlainJWT.parse / new PlainJWT; golang-jwt SigningMethodNone and UnsafeAllowNoneSignatureType outside a comparison; jose UnsecuredJWT; PHP JWT::decode with 'none' allowed and lcobucci Signer\\None. Not reported: a specific signing algorithm, verify_signature: True, parseClaimsJws/parseSignedClaims, a jjwt 0.12 chain with verifyWith/keyLocator and no unsecured() before parse(), golang-jwt ParseUnverified and jwx ParseInsecure (commonly used to read the kid before verifying), a comparison that rejects alg none (alg === 'none', t.Method == jwt.SigningMethodNone), TLS verify=False outside a JWT decode, prose strings, tests, comments and documentation. Signature verification switched off for a signed token (PyJWT/python-jose verify_signature False or verify=False, Ruby JWT.decode(token, key, false), jjwt parse() after setSigningKey in Java/Kotlin, lestrrat-go/jwx jwt.WithVerify(false), ASP.NET RequireSignedTokens = false or a SignatureValidator that returns the token unchecked) is reported by VNX-JWT-001.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-015/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [345, 327],
	"capec": ["CAPEC-115"],
	"attack_technique": ["T1550.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["jwt", "authentication", "token"],
}

_ext_re := `\.(js|jsx|mjs|cjs|ts|tsx|py|go|java|kt|kts|cs|php|rb)$`

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(?i)\.min\.js$|(^|/)(node_modules|vendor)/`, path)

_skip(path) if regex.match(`(^|/)([A-Za-z]+Tests?|[A-Za-z.]+\.Tests?)/|(^|/)src/(it|test)/`, path)

_gate_words := ["none", "verify", "jwts.parser", "parseclaimsjwt", "parseplaintextjwt", "parseunsecured", "plainjwt", "requiresignedtokens", "signaturevalidator", "unsecuredjwt", "jwt.decode"]

_gate(content) if {
	lc := lower(content)
	contains(lc, "jwt")
	some w in _gate_words
	contains(lc, w)
}

# String literals that hold prose (they contain a space) are removed, so a
# message mentioning algorithm: 'none' is not an option.
_code(line) := strings.replace_n({s: `""` |
	some s in regex.find_n(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, line, -1)
	contains(s, " ")
}, line)

_none_algo_re := `(?i)\balgorithms?["']?\s*(?::|=>|=)\s*[\[(]?\s*(?:["'][\w-]+["']\s*,\s*)*["']none["']`

_unsafe(_, line) if regex.match(_none_algo_re, line)

_unsafe(path, line) if {
	endswith(path, ".py")
	regex.match(`\bencode\([^)]*\balgorithm\s*=\s*None\b`, line)
}

_unsafe(_, line) if regex.match(`(?i)[{,]\s*["']?alg["']?\s*(?::|=>)\s*["']none["']`, line)

# Signature verification switched off for a signed token (PyJWT/python-jose
# verify_signature False or verify=False, ruby-jwt JWT.decode(t, k, false),
# jjwt parse() after setSigningKey, jwx WithVerify(false), .NET
# RequireSignedTokens = false and an unchecking SignatureValidator) is
# reported by VNX-JWT-001; this rule keeps the 'none' algorithm and the
# unsigned-token APIs.

_unsafe(path, line) if {
	endswith(path, ".rb")
	regex.match(`(?i)\bJWT\.encode\(\s*[^,]+,\s*[^,]+,\s*["']none["']`, line)
}

_unsafe(path, line) if {
	regex.match(`\.(java|kt|kts)$`, path)
	regex.match(`\bSignatureAlgorithm\.NONE\b|\bAlgorithm\.none\(\)|\bPlainJWT\.parse\(|\bnew\s+PlainJWT\(|\.parse(?:ClaimsJwt|PlaintextJwt|UnsecuredClaims|UnsecuredContent)\(`, line)
}

_unsafe(path, line) if {
	regex.match(`\.(java|kt|kts)$`, path)
	regex.match(`\bJwts\.parser(?:Builder)?\(\)[^;]*\.parse\(`, line)
	not _jjwt_verified(line)
	not _jjwt_keyed(path, line)
}

# jjwt 0.12+: .unsecured() on the parser accepts unsigned tokens.
_unsafe(path, line) if {
	regex.match(`\.(java|kt|kts)$`, path)
	regex.match(`(?:^\s*|\bJwts\.parser(?:Builder)?\(\)[^;]*)\.unsecured\(\)`, line)
}

# jjwt 0.12's generic parse() rejects unsecured tokens unless .unsecured()
# was called: a chain with verifyWith/keyLocator and no unsecured() is safe.
_jjwt_verified(text) if {
	regex.match(`\.(verifyWith|keyLocator)\(`, text)
	not contains(text, ".unsecured()")
}

# A jjwt parse() after setSigningKey in Java/Kotlin is VNX-JWT-001's finding
# (verification of a signed token skipped); a .kts script is not read there.
_jjwt_keyed(path, text) if {
	regex.match(`\.(java|kt)$`, path)
	contains(text, "setSigningKey")
}

_unsafe(path, line) if {
	endswith(path, ".go")
	regex.match(`\bjwt\.(SigningMethodNone|UnsafeAllowNoneSignatureType)\b`, line)
	not regex.match(`[=!]=\s*jwt\.SigningMethodNone|jwt\.SigningMethodNone\s*[=!]=|case\s+jwt\.SigningMethodNone|\*jwt\.SigningMethodNone`, line)
}

_unsafe(path, line) if {
	regex.match(`\.(js|jsx|mjs|cjs|ts|tsx)$`, path)
	regex.match(`\bUnsecuredJWT\b\s*[.(]|\bnew\s+UnsecuredJWT\(`, line)
}

_unsafe(path, line) if {
	endswith(path, ".php")
	regex.match(`(?i)\bJWT::decode\([^;]*["']none["']|\\Signer\\None\b|\bnew\s+None\(\)`, line)
}

# A chained `.parse(token)` whose chain opened with Jwts.parser() above.
_chain_parse(path, lines, i, line) if {
	regex.match(`\.(java|kt|kts)$`, path)
	regex.match(`^\s*\.parse\(`, line)
	_chain_unbroken(lines, i)
	not _chain_keyed(path, lines, i)
}

# No statement ends between the Jwts.parser() line and this one.
_chain_unbroken(lines, i) if {
	starts := [j | some j in numbers.range(max([0, i - 6]), i - 1); regex.match(`\bJwts\.parser(?:Builder)?\(\)`, lines[j])]
	count(starts) > 0
	s := max(starts)
	not _ends_between(lines, s, i)
	not _jjwt_verified(concat(" ", array.slice(lines, s, i + 1)))
}

_chain_keyed(path, lines, i) if {
	starts := [j | some j in numbers.range(max([0, i - 6]), i - 1); regex.match(`\bJwts\.parser(?:Builder)?\(\)`, lines[j])]
	_jjwt_keyed(path, concat(" ", array.slice(lines, max(starts), i + 1)))
}

_ends_between(lines, s, i) if {
	some j in numbers.range(s, i - 1)
	regex.match(`;\s*(//.*)?$`, lines[j])
}

_reported(path, lines, i, line) if _unsafe(path, _code(line))

_reported(path, lines, i, line) if _chain_parse(path, lines, i, line)


findings contains finding if {
	some path, content in input.file_contents
	regex.match(_ext_re, path)
	_gate(content)
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)none|verify|parse|jwt|signaturevalidator|requiresigned|unsecured`, line)
	not helpers.is_comment_line(line)
	_reported(path, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "JWT signature is not enforced: the token is issued unsigned or accepted without verifying its signature. Require a specific signing algorithm (HS256, RS256, ES256) and verify every token",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
