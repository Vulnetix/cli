package vulnetix.rules.vnx_jwt_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JWT-002",
	"name": "JWT token signed without expiration",
	"description": "A JWT is issued with no expiry, so a leaked token stays valid for ever. Reported: jsonwebtoken jwt.sign() and jose new SignJWT() (JavaScript/TypeScript), PyJWT/python-jose jwt.encode() (Python), jjwt Jwts.builder() and Auth0 JWT.create() (Java), golang-jwt jwt.NewWithClaims() (Go), ruby-jwt JWT.encode() and firebase/php-jwt JWT::encode() (PHP), when neither the call itself (its arguments, options and builder chain) nor the definition of a payload, claims or options variable it uses (assigned within 25 lines above) sets an expiry: exp, expiresIn, setExpiration/expiration, withExpiresAt, ExpiresAt or setExpirationTime. Not reported: test files, comments, decode/verify calls, and payloads or options built further away or in another function or file (those are a documented gap rather than a guess).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-jwt-002/",
	"languages": ["python", "javascript", "typescript", "java", "go", "ruby", "php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [613],
	"capec": ["CAPEC-60"],
	"attack_technique": ["T1550.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["jwt", "session-management", "authentication"],
}

# File extension -> the token-issuing call for that language.
_sink(path) := `\b(?:jwt|jsonwebtoken|JWT)\.sign\s*\(|\bnew\s+SignJWT\s*\(` if {
	regex.match(`\.(?:js|mjs|cjs|jsx|ts|tsx)$`, path)
}

_sink(path) := `\bjwt\.encode\s*\(` if endswith(path, ".py")

_sink(path) := `\bJwts\s*\.\s*builder\s*\(\s*\)|\bJWT\s*\.\s*create\s*\(\s*\)` if endswith(path, ".java")

_sink(path) := `\bjwt\.NewWithClaims\s*\(` if endswith(path, ".go")

_sink(path) := `\bJWT\.encode\s*\(` if endswith(path, ".rb")

_sink(path) := `\bJWT::encode\s*\(` if endswith(path, ".php")

_expiry := `(?i)\bexp\b|expires|expiration|ExpiresAt`

_balance(lines, i, k) := sum([n |
	some j in numbers.range(i, k)
	n := count(indexof_n(lines[j], "(")) - count(indexof_n(lines[j], ")"))
])

# Last line of the call or builder chain that starts at line i.
_call_end(lines, i) := e if {
	last := min([count(lines) - 1, i + 10])
	ends := [k |
		some k in numbers.range(i, last)
		_balance(lines, i, k) <= 0
		not _chain_continues(lines, k)
	]
	e := min(array.concat(ends, [last]))
}

_chain_continues(lines, k) if {
	k + 1 < count(lines)
	startswith(trim_space(lines[k + 1]), ".")
}

_call_text(lines, i) := concat("\n", [l |
	some j in numbers.range(i, _call_end(lines, i))
	l := lines[j]
	not helpers.is_comment_line(l)
])

_has_expiry(lines, i) if regex.match(_expiry, _call_text(lines, i))

# An identifier the call uses was assigned within 25 lines above, and the
# lines from that assignment to the call set an expiry.
_has_expiry(lines, i) if {
	some w in regex.find_n(`[A-Za-z_]\w+`, _call_text(lines, i), -1)
	assign_re := concat("", [`(?:^|[^\w.])\$?`, w, `\s*:?=[^=]`])
	some j in numbers.range(max([0, i - 25]), i - 1)
	contains(lines[j], w)
	regex.match(assign_re, lines[j])
	not helpers.is_comment_line(lines[j])
	txt := concat("\n", [l | some k in numbers.range(j, i - 1); l := lines[k]; not helpers.is_comment_line(l)])
	regex.match(_expiry, txt)
}

findings contains finding if {
	some path, content in input.file_contents
	sink := _sink(path)
	regex.match(concat("", ["(?m)", sink]), content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(sink, line)
	not helpers.is_comment_line(line)
	not _in_string(line, sink)
	not _has_expiry(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "JWT issued without an expiry (no exp / expiresIn / setExpiration); a leaked token never stops working. Set a short lifetime",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The call appears inside a quoted string on this line.
_in_string(line, sink) if {
	m := regex.find_all_string_submatch_n(concat("", [`^(.*?)(?:`, sink, `)`]), line, 1)
	prefix := m[0][1]
	_odd_quotes(prefix)
}

_odd_quotes(p) if count(indexof_n(p, `"`)) % 2 == 1

_odd_quotes(p) if count(indexof_n(p, "'")) % 2 == 1
