package vulnetix.rules.vnx_jwt_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JWT-005",
	"name": "Sensitive credential data stored in JWT payload",
	"description": "A password, password hash, secret, API key, social security number or card number is put into a JWT's claims. A JWS payload is only base64url-encoded, so anyone holding the token can read it. Reported: such a key in the payload literal of jsonwebtoken jwt.sign / jose new SignJWT (JavaScript/TypeScript, including the { password } shorthand), PyJWT jwt.encode (Python), ruby-jwt JWT.encode (Ruby), firebase/php-jwt JWT::encode (PHP) and golang-jwt jwt.NewWithClaims (Go); in a payload variable defined or extended (payload[\"password\"] = ...) within 20 lines above the call; in a jjwt .claim(...) / Auth0 .withClaim(...) of a builder chain (Java); and a Go claims struct embedding jwt.RegisteredClaims/StandardClaims with such a json-tagged field. Not reported: lookalike keys (passwordChangedAt, hasPassword), credentials in request bodies, forms or login structs that never reach a token, comments and strings. Passing a whole user record as the payload is not detected.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-jwt-005/",
	"languages": ["python", "javascript", "typescript", "java", "go", "ruby", "php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [522],
	"capec": ["CAPEC-37"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["jwt", "credentials", "sensitive-data", "authentication"],
}

_names := `(?:password|passwd|pwd|password_?hash|hashed_?password|pass_?hash|secret|client_?secret|api_?key|ssn|social_?security_?number|credit_?card(?:_?number)?|card_?number|cvv|cvc)`

# A dict/object/hash/array key, or JS shorthand property.
_key_re := concat("", [`(?i)(?:(?:^|[{,(\[\s])["':]?`, _names, `["']?\s*(?::[^:]|=>)|[{,]\s*`, _names, `\s*[,}]|^\s*`, _names, `\s*,?\s*$)`])

# Java builder claim and map put.
_java_key_re := concat("", [`(?i)\.(?:claim|withClaim|put)\s*\(\s*"`, _names, `"`])

_sink(path) := `\b(?:jwt|jsonwebtoken|JWT)\.sign\s*\(|\bnew\s+SignJWT\s*\(` if {
	regex.match(`\.(?:js|mjs|cjs|jsx|ts|tsx)$`, path)
}

_sink(path) := `\bjwt\.encode\s*\(` if endswith(path, ".py")

_sink(path) := `\bJWT\.encode\s*\(` if endswith(path, ".rb")

_sink(path) := `\bJWT::encode\s*\(` if endswith(path, ".php")

_sink(path) := `\bjwt\.NewWithClaims\s*\(` if endswith(path, ".go")

_sink(path) := `\bJwts\s*\.\s*builder\s*\(\s*\)|\bJWT\s*\.\s*create\s*\(\s*\)` if endswith(path, ".java")

_key_pattern(path) := _java_key_re if endswith(path, ".java")

_key_pattern(path) := _key_re if not endswith(path, ".java")

_balance(lines, i, k) := sum([n |
	some j in numbers.range(i, k)
	n := count(indexof_n(lines[j], "(")) - count(indexof_n(lines[j], ")"))
])

_chain_continues(lines, k) if {
	k + 1 < count(lines)
	startswith(trim_space(lines[k + 1]), ".")
}

_call_end(lines, i) := e if {
	last := min([count(lines) - 1, i + 10])
	ends := [k |
		some k in numbers.range(i, last)
		_balance(lines, i, k) <= 0
		not _chain_continues(lines, k)
	]
	e := min(array.concat(ends, [last]))
}

_odd_quotes(p) if count(indexof_n(p, `"`)) % 2 == 1

_odd_quotes(p) if count(indexof_n(p, "'")) % 2 == 1

_finding(path, j, line) := {
	"rule_id": metadata.id,
	"message": "Credential or sensitive value placed in JWT claims; the payload is readable by anyone holding the token. Keep only an opaque identifier in the token",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": j + 1,
	"snippet": line,
}

_is_key_line(line, kp) if {
	not helpers.is_comment_line(line)
	regex.match(kp, line)
}

# Lines that put a sensitive key into the token issued at line i. Outside
# Java the key must sit inside a {...} or [...] opened after the sink (the
# payload literal), so a positional key argument named `secret` is no claim.
_key_line(lines, i, kp, j, _) if {
	j >= i
	kp == _java_key_re
	_is_key_line(lines[j], kp)
}

_key_line(lines, i, kp, j, pi) if {
	j >= i
	kp != _java_key_re
	_is_key_line(lines[j], kp)
	km := regex.find_all_string_submatch_n(concat("", [`^(.*?)(?:`, kp, `)`]), lines[j], 1)
	_depth(lines, i, pi, j, count(km[0][1])) > 0
}

_braces(s) := (count(indexof_n(s, "{")) + count(indexof_n(s, "["))) - (count(indexof_n(s, "}")) + count(indexof_n(s, "]")))

_depth(lines, i, pi, j, pj) := _braces(substring(lines[i], pi, pj - pi)) if {
	j == i
	pj >= pi
}

_depth(lines, i, pi, j, pj) := d if {
	j > i
	mid := sum([n | some k in numbers.range(i + 1, j - 1); k < j; n := _braces(lines[k])])
	d := (_braces(substring(lines[i], pi, -1)) + mid) + _braces(substring(lines[j], 0, pj))
}

# The first argument is a variable defined (or extended) shortly above.
_key_line(lines, i, kp, j, _) if {
	j < i
	m := regex.find_all_string_submatch_n(`\(\s*(?:jwt\.SigningMethod\w+\s*,\s*)?\$?([A-Za-z_]\w*)\s*[,)]`, lines[i], 1)
	v := m[0][1]
	assign_re := concat("", [`(?:^|[^\w.])\$?`, v, `\s*(?::?=|=)\s*[^=]`])
	some a in numbers.range(max([0, i - 20]), i - 1)
	contains(lines[a], v)
	regex.match(assign_re, lines[a])
	a <= j
	_in_literal(lines, a, j)
	_is_key_line(lines[j], kp)
}

# Line j is the assignment line itself or still inside the literal it opens.
_in_literal(_, a, a)

_in_literal(lines, a, j) if {
	j > a
	sum([n |
		some k in numbers.range(a, j - 1)
		l := lines[k]
		n := (count(indexof_n(l, "{")) + count(indexof_n(l, "["))) - (count(indexof_n(l, "}")) + count(indexof_n(l, "]")))
	]) > 0
}

_key_line(lines, i, kp, j, _) if {
	j < i
	m := regex.find_all_string_submatch_n(`\(\s*\$?([A-Za-z_]\w*)\s*[,)]`, lines[i], 1)
	v := m[0][1]
	ext_re := concat("", [`(?i)\$?\b`, v, `\s*(?:\[\s*["']`, _names, `["']\s*\]|\.`, _names, `)\s*=[^=]`])
	contains(lines[j], v)
	not helpers.is_comment_line(lines[j])
	regex.match(ext_re, lines[j])
}

findings contains f if {
	some path, content in input.file_contents
	sink := _sink(path)
	regex.match(concat("", ["(?m)", sink]), content)
	regex.match(concat("", ["(?i)", _names]), content)
	kp := _key_pattern(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(sink, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`^(.*?)(?:`, sink, `)`]), line, 1)
	not _odd_quotes(m[0][1])
	pi := count(m[0][1])
	some j in numbers.range(max([0, i - 20]), _call_end(lines, i))
	_key_line(lines, i, kp, j, pi)
	f := _finding(path, j, lines[j])
}

# Go: a claims struct that embeds the library's claims and carries a secret.
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`jwt\.(?:Registered|Standard)Claims`, content)
	lines := split(content, "\n")
	some j, line in lines
	contains(line, "json:")
	regex.match(concat("", [`(?i)json:"`, _names, `[",]`]), line)
	s := _struct_start(lines, j)
	e := _struct_end(lines, j)
	some k in numbers.range(s, e)
	regex.match(`^\s*\*?jwt\.(?:Registered|Standard)Claims\b`, lines[k])
	f := _finding(path, j, line)
}

_struct_start(lines, j) := max([k |
	some k in numbers.range(max([0, j - 30]), j)
	regex.match(`^type\s+\w+\s+struct\s*\{`, lines[k])
])

_struct_end(lines, j) := min([k |
	some k in numbers.range(j, min([count(lines) - 1, j + 30]))
	startswith(lines[k], "}")
])
