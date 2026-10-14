package vulnetix.rules.vnx_jwt_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JWT-006",
	"name": "JWT missing audience or issuer verification",
	"description": "A JWT verifier does not check who the token was issued for, so a token minted for another application (by the same identity provider or signing key) is accepted here. Reported: audience or issuer validation switched off explicitly, by PyJWT/python-jose options {\"verify_aud\": False} or {\"verify_iss\": False} (Python) and TokenValidationParameters ValidateAudience = false or ValidateIssuer = false (C#); and a token verified against a shared identity provider's key set with no audience check anywhere in the file: jsonwebtoken jwt.verify, jose jwtVerify and express-jwt in a file that uses jwks-rsa or createRemoteJWKSet (JavaScript/TypeScript), Auth0 JWT.require() in a file using a JwkProvider (Java), and golang-jwt jwt.Parse/ParseWithClaims with a keyfunc/JWKS key set (Go) without WithAudience. Not reported: verification with a private shared secret and no audience (PyJWT already rejects an aud claim it was not told to expect), verifiers that pass an audience, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-jwt-006/",
	"languages": ["python", "javascript", "typescript", "csharp", "java", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [287],
	"capec": ["CAPEC-196"],
	"attack_technique": ["T1550.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["jwt", "authentication", "audience", "issuer"],
}

_odd_quotes(p) if count(indexof_n(p, `"`)) % 2 == 1

_odd_quotes(p) if count(indexof_n(p, "'")) % 2 == 1

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_js(path) if regex.match(`\.(?:js|mjs|cjs|jsx|ts|tsx)$`, path)

# ── Explicitly disabled ──────────────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "verify_")
	regex.match(`verify_(?:aud|iss)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "verify_")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^(.*?)["']verify_(?:aud|iss)["']\s*:\s*False\b`, line, 1)
	count(m) > 0
	not _odd_quotes(m[0][1])
	f := _finding(path, i, line, "JWT audience/issuer verification disabled: a token issued for another application is accepted. Pass audience= (and issuer=) instead")
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	contains(content, "TokenValidationParameters")
	regex.match(`Validate(?:Audience|Issuer)\s*=\s*false`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Validate")
	not helpers.is_comment_line(line)
	regex.match(`\bValidate(?:Audience|Issuer)\s*=\s*false\b`, line)
	f := _finding(path, i, line, "TokenValidationParameters disables audience/issuer validation: a token issued for another application is accepted. Set ValidAudience/ValidIssuer and keep validation on")
}

# ── Shared key set, no audience ──────────────────────────────────────────

_no_audience(lines) if {
	not regex.match(`(?i)audience|withAudience|\baud\b`, helpers.code_text(lines))
}

_jwks_sink := {
	"js": `^(.*?)(?:\b(?:jwt|jsonwebtoken)\.verify\s*\(|\bjwtVerify\s*\(|\bexpressjwt\s*\(|\bexpressJwt\s*\(|\bjwt\s*\(\s*\{)`,
	"java": `^(.*?)\bJWT\s*\.\s*require\s*\(`,
	"go": `^(.*?)(?:\bjwt\.(?:Parse|ParseWithClaims)\s*\(|\b[pP]arser\.(?:Parse|ParseWithClaims)\s*\()`,
}

_kind(path) := "js" if _js(path)

_kind(path) := "java" if endswith(path, ".java")

_kind(path) := "java" if endswith(path, ".kt")

_kind(path) := "go" if endswith(path, ".go")

_jwks_file("js", content) if {
	_has_jwks(content)
	regex.match(`jwks-rsa|jwksClient|createRemoteJWKSet|jwksUri|expressJwtSecret`, content)
}

_has_jwks(content) if contains(content, "jwks")

_has_jwks(content) if contains(content, "JWKS")

_jwks_file("java", content) if contains(content, "JwkProvider")

_jwks_file("go", content) if {
	contains(content, "golang-jwt")
	regex.match(`MicahParks/keyfunc|lestrrat-go/jwx|jwks|JWKS`, content)
}

findings contains f if {
	some path, content in input.file_contents
	k := _kind(path)
	_jwks_file(k, content)
	lines := split(content, "\n")
	_no_audience(lines)
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_jwks_sink[k], line, 1)
	count(m) > 0
	not _odd_quotes(m[0][1])
	f := _finding(path, i, line, "JWT verified against an identity provider's shared key set without an audience check: tokens the provider issued to any other application are accepted. Require the expected audience")
}
