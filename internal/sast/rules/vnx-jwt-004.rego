package vulnetix.rules.vnx_jwt_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JWT-004",
	"name": "JWT algorithm explicitly set to 'none'",
	"description": "A JWT is signed with, or a verifier accepts, the unsigned 'none' algorithm, so anyone can forge a valid token by dropping the signature. Reported: an algorithm/algorithms option (keyword argument, object or hash key, including a list split over several lines) whose value is or contains 'none' in any case, and PyJWT jwt.encode(..., algorithm=None), in Python, JavaScript/TypeScript and Ruby; ruby-jwt JWT.encode(payload, nil, 'none') and PyJWT jwt.encode(payload, key, 'none'); jose UnsecuredJWT; Auth0 java-jwt Algorithm.none() and jjwt Jwts.parser().unsecured() (Java/Kotlin); golang-jwt SigningMethodNone used to sign and UnsafeAllowNoneSignatureType. Not reported: code that compares a token's alg with 'none' to reject it, strong algorithm lists, comments and string literals. Verification switched off by other means (verify_signature: False, jjwt parse()) is VNX-JWT-001.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-jwt-004/",
	"languages": ["python", "javascript", "typescript", "ruby", "java", "kotlin", "go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-196"],
	"attack_technique": ["T1550.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["jwt", "algorithm", "authentication", "none-alg"],
}

_lang(path) := "js" if regex.match(`\.(?:js|mjs|cjs|jsx|ts|tsx)$`, path)

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "rb" if endswith(path, ".rb")

_lang(path) := "jvm" if endswith(path, ".java")

_lang(path) := "jvm" if endswith(path, ".kt")

_lang(path) := "go" if endswith(path, ".go")

_odd_quotes(p) if count(indexof_n(p, `"`)) % 2 == 1

_odd_quotes(p) if count(indexof_n(p, "'")) % 2 == 1

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "JWT 'none' algorithm used or accepted: an unsigned token passes as valid. Sign and verify with an explicit strong algorithm (HS256, RS256, ES256)",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# The option key opens on this line; its value (or a list continuing for up
# to 5 lines) names 'none'.
_opt_re := `^([^\n]*?)(?:["']?\balgorithms?["']?|["']?\b(?i:jwt_(?:\w+_)?algorithms?)["']?\]?)\s*(?:=>|[:=])\s*(?:[\[\(]\s*(?:["'][\w-]*["']\s*,\s*)*)?["'](?i:none)["']`

_win(lines, i) := concat("\n", [l |
	some j in numbers.range(i, min([count(lines) - 1, i + 5]))
	l := lines[j]
	not helpers.is_comment_line(l)
])

_line_re := {
	"py": [
		`^(.*?)\bjwt\.encode\s*\((?:[^()]|\([^()]*\))*\balgorithm\s*=\s*None\b`,
		`^(.*?)\bjwt\.encode\s*\(\s*(?:\{[^{}]*\}|[^,{}]+)\s*,\s*[^,]+,\s*["'](?i:none)["']`,
	],
	"rb": [`^(.*?)\bJWT\.encode\s*\(\s*(?:\{[^{}]*\}|[^,{}]+)\s*,\s*[^,]+,\s*["'](?i:none)["']`],
	"js": [`^(.*?)(?:\bnew\s+UnsecuredJWT\s*\(|\bUnsecuredJWT\s*\.\s*decode\s*\()`],
	"jvm": [
		`^(.*?)\bAlgorithm\s*\.\s*none\s*\(\s*\)`,
		`^(.*?)\bJwts\s*\.\s*parser\s*\(\s*\)[^;]*\.unsecured\s*\(\s*\)`,
		`^(.*?)\bnew\s+PlainJWT\s*\(`,
		`^(.*?)\bPlainJWT\s*\.\s*parse\s*\(`,
	],
	"go": [
		`^(.*?)\bjwt\.UnsafeAllowNoneSignatureType\b`,
		`^(.*?)\bjwt\.NewWithClaims\s*\(\s*jwt\.SigningMethodNone\b`,
		`^(.*?)\bjwt\.New\s*\(\s*jwt\.SigningMethodNone\b`,
		`^(.*?)\bWithValidMethods\s*\(\s*\[\]string\s*\{[^}]*"(?i:none)"`,
	],
}

_anchor := {
	"py": ["jwt"],
	"rb": ["JWT"],
	"js": ["UnsecuredJWT"],
	"jvm": ["none(", "unsecured(", "PlainJWT"],
	"go": ["None", "\"none\""],
}

_anchored(lang, s) if {
	some a in _anchor[lang]
	contains(s, a)
}

# The option belongs to a JWT library, not a compressor or a database.
_jwt_file(content) if contains(content, "jwt")

_jwt_file(content) if contains(content, "JWT")

_jwt_file(content) if contains(content, "jose")

# algorithm / algorithms option naming 'none'
findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	lang in {"py", "js", "rb"}
	regex.match(`(?i)["']none["']`, content)
	regex.match(`(?i)lgorithm`, content)
	_jwt_file(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)lgorithm`, line)
	not _test_issue(path, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_opt_re, _win(lines, i), 1)
	count(m) > 0
	not _odd_quotes(m[0][1])
	f := _finding(path, i, line)
}

findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	res := _line_re[lang]
	_anchored(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	some re in res
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	not _odd_quotes(m[0][1])
	not _test_issue(path, line)
	f := _finding(path, i, line)
}

# A test that mints an unsigned token (to prove the verifier rejects it) is
# not the weakness; accepting 'none' in a test is still reported.
_test_issue(path, line) if {
	helpers.is_test_path(path)
	regex.match(`\.sign\s*\(|\b(?:jwt|JWT)\.encode\s*\(|\bjwt\.(?:NewWithClaims|New)\s*\(\s*jwt\.SigningMethodNone|\.SignedString\s*\(|\bnew\s+(?:UnsecuredJWT|PlainJWT)\s*\(`, line)
}
