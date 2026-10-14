package vulnetix.rules.vnx_jwt_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JWT-001",
	"name": "JWT signature verification disabled",
	"description": "A JWT is accepted without its signature being checked. Reported: PyJWT/python-jose options {\"verify_signature\": False} (in the decode call or a dict built for it) and the PyJWT 1.x verify=False argument; jsonwebtoken jwt.decode() applied to a request-derived token in a file that never calls verify(); jwt-simple decode(token, key, true) (noVerify); golang-jwt ParseUnverified() in a file that never calls Parse/ParseWithClaims; jjwt (pre-0.12 API) Jwts.parser()...setSigningKey(...).parse(), which accepts an unsigned token, and Auth0 java-jwt JWT.decode() in a Java/Kotlin file that never builds a JWT.require() verifier; ruby-jwt JWT.decode(token, key, false); .NET TokenValidationParameters RequireSignedTokens = false or a SignatureValidator that returns a new JwtSecurityToken/JsonWebToken without checking it. Not reported: decode with options that only relax exp/aud, a decode of the header followed by verify, a browser-side decode of a token read from storage, jjwt parseClaimsJws/parseSignedClaims and the 0.12 verifyWith() builder, comments and string literals. Accepting the 'none' algorithm is reported by VNX-JWT-004.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-jwt-001/",
	"languages": ["python", "javascript", "typescript", "go", "java", "kotlin", "ruby", "csharp"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [347],
	"capec": ["CAPEC-196"],
	"attack_technique": ["T1550.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["jwt", "authentication", "broken-auth"],
}

_js_ext(path) if endswith(path, ".js")

_js_ext(path) if endswith(path, ".mjs")

_js_ext(path) if endswith(path, ".cjs")

_js_ext(path) if endswith(path, ".jsx")

_js_ext(path) if endswith(path, ".ts")

_js_ext(path) if endswith(path, ".tsx")

_jvm_ext(path) if endswith(path, ".java")

_jvm_ext(path) if endswith(path, ".kt")

# A prefix with an unbalanced quote: the match sits inside a string literal.
_quoted(prefix) if count(regex.find_n(`"`, prefix, -1)) % 2 == 1

_quoted(prefix) if count(regex.find_n(`'`, prefix, -1)) % 2 == 1

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_window(lines, i, before) := concat("\n", [lines[j] | some j in numbers.range(max([0, i - before]), i)])

# ── Python: PyJWT / python-jose ──────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "verify_signature")
	regex.match(`\b(jwt|jose)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "verify_signature")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^(.*?)["']verify_signature["']\s*:\s*False\b`, line, 1)
	count(m) > 0
	not _quoted(m[0][1])
	f := _finding(path, i, line, "JWT signature verification disabled (verify_signature: False): any forged token is accepted; remove the option and pass the key and algorithms")
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "verify=False")
	contains(content, "decode")
	regex.match(`\bjwt\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\bverify\s*=\s*False\b`, line)
	not helpers.is_comment_line(line)
	regex.match(`\bdecode\s*\((?:[^()]|\([^()]*\))*\bverify\s*=\s*False\b[^\n]*$`, _window(lines, i, 4))
	f := _finding(path, i, line, "jwt.decode(..., verify=False) skips signature verification; any forged token is accepted")
}

# ── JavaScript / TypeScript ──────────────────────────────────────────────

# jwt-simple: decode(token, key, noVerify=true)
findings contains f if {
	some path, content in input.file_contents
	_js_ext(path)
	contains(content, "jwt-simple")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "decode")
	not helpers.is_comment_line(line)
	regex.match(`\.decode\s*\(\s*[^,()]+(?:\([^()]*\))?[^,()]*,\s*[^,]+,\s*true\b`, line)
	f := _finding(path, i, line, "jwt-simple decode() called with noVerify=true: the token signature is not checked")
}

_js_req_source := `\b(req|request|ctx)\.(headers|header|cookies|query|body|params|get)\b`

# jsonwebtoken: decode() of a request token in a file that never verifies.
findings contains f if {
	some path, content in input.file_contents
	_js_ext(path)
	contains(content, "jsonwebtoken")
	contains(content, ".decode(")
	not regex.match(`\.verify\s*\(|\bjwtVerify\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".decode(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\b(?:jwt|jsonwebtoken|JWT)\.decode\s*\(\s*([^,)]+)`, line, 1)
	count(m) > 0
	_js_request_arg(lines, i, m[0][1])
	f := _finding(path, i, line, "jsonwebtoken decode() does not verify the signature, and this file never calls jwt.verify(): the request token is trusted unverified")
}

_js_request_arg(_, _, arg) if regex.match(_js_req_source, arg)

_js_request_arg(lines, i, arg) if {
	some v in helpers.tainted_vars(lines, i, 15, _js_req_source)
	regex.match(concat("", [`^\s*`, v, `\b`]), arg)
}

# ── Go: golang-jwt ───────────────────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "ParseUnverified")
	not regex.match(`\.(Parse|ParseWithClaims)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ParseUnverified")
	not helpers.is_comment_line(line)
	regex.match(`\.ParseUnverified\s*\(`, line)
	f := _finding(path, i, line, "ParseUnverified() reads the claims without checking the signature, and this file never verifies the token with Parse/ParseWithClaims")
}

# ── Java / Kotlin ────────────────────────────────────────────────────────

# jjwt before 0.12: parse() after setSigningKey accepts an unsigned (alg none) token.
findings contains f if {
	some path, content in input.file_contents
	_jvm_ext(path)
	contains(content, "Jwts")
	contains(content, "setSigningKey")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".parse(")
	not helpers.is_comment_line(line)
	regex.match(`Jwts\s*\.\s*parser(?:Builder)?\s*\(\s*\)(?:[^;\n]|\n[ \t]*\.)*\bsetSigningKey(?:Resolver)?\s*\((?:[^;\n]|\n[ \t]*\.)*\bparse\s*\(`, _window(lines, i, 6))
	f := _finding(path, i, line, "jjwt parse() accepts an unsigned JWT even when a signing key is set; use parseClaimsJws() (or parseSignedClaims() on 0.12)")
}

# Auth0 java-jwt: JWT.decode() in a file that never builds a verifier.
findings contains f if {
	some path, content in input.file_contents
	_jvm_ext(path)
	contains(content, "com.auth0.jwt")
	contains(content, "JWT.decode(")
	not contains(content, "JWT.require(")
	not regex.match(`\.verify\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "JWT.decode(")
	not helpers.is_comment_line(line)
	regex.match(`\bJWT\.decode\s*\(`, line)
	f := _finding(path, i, line, "Auth0 JWT.decode() does not verify the signature, and this file never verifies the token with JWT.require(...).build().verify()")
}

# ── Ruby: ruby-jwt ───────────────────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".rb")
	contains(content, "JWT.decode")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "JWT.decode")
	not helpers.is_comment_line(line)
	regex.match(`\bJWT\.decode\s*\(\s*[^,]+,\s*[^,]+,\s*false\b`, line)
	f := _finding(path, i, line, "JWT.decode(token, key, false) skips signature verification; pass true and an explicit algorithm")
}

# ── C#: Microsoft.IdentityModel ──────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	contains(content, "RequireSignedTokens")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "RequireSignedTokens")
	not helpers.is_comment_line(line)
	regex.match(`\bRequireSignedTokens\s*=\s*false\b`, line)
	f := _finding(path, i, line, "RequireSignedTokens = false accepts unsigned JWTs")
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	contains(content, "SignatureValidator")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "SignatureValidator")
	not helpers.is_comment_line(line)
	regex.match(`\bSignatureValidator\s*=`, line)
	regex.match(`\bnew\s+(JwtSecurityToken|JsonWebToken)\s*\(`, helpers.code_window(lines, i, 0, 3))
	f := _finding(path, i, line, "A SignatureValidator that returns a new token without checking it disables JWT signature verification")
}
