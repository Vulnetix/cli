package vulnetix.rules.vnx_go_031

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-031",
	"name": "Missing signature validation on JWT",
	"description": "A JWT's claims are used without its signature being verified. Reported: jwt.UnsafeAllowNoneSignatureType returned from a key function or held in a variable (golang-jwt / dgrijalva jwt-go then accept alg \"none\" tokens, which carry no signature); lestrrat-go/jwx jwt.WithVerify(false); golang-jwt ParseUnverified, jwx jwt.ParseInsecure and go-jose UnsafeClaimsWithoutVerification / UnsafePayloadWithoutVerification and lestrrat-go/jwx jws.Parse (which only decodes) in a file that handles requests (net/http, gin, echo, fiber, gRPC metadata, an Authorization or Bearer header) when the same function never verifies the token with jwt.Parse, ParseWithClaims, a go-jose Claims(key, ...) or a Verify call; jwt.Parse/ParseWithClaims whose error is discarded (tok, _ := jwt.Parse(...)) and whose token's Claims are read with no token.Valid check (the token is returned even when the signature fails); ParseWithClaims whose token and error are both discarded, or whose claims variable is then read with no error or token.Valid check (the claims are filled in either way); and a go-jose tok.Claims(key, &c) call whose error is dropped. Not reported: signing with SigningMethodNone (SignedString(jwt.UnsafeAllowNoneSignatureType)), unverified parsing to pick a key that is followed by verification, unverified parsing in tools that do not serve requests, a parse whose error or token.Valid is checked, key functions that skip the signing-method check (golang-jwt v4+ rejects a key of the wrong type, so that alone is not a bypass), test files, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-031/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [347],
	"capec": ["CAPEC-64"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["jwt", "token", "signature", "authentication"],
}

_needles := ["UnsafeAllowNoneSignatureType", "ParseUnverified", "ParseInsecure", "WithoutVerification", "WithVerify(false)", "Parse(", "ParseWithClaims(", ".Claims("]

_gate(content) if {
	regex.match(`jwt|jws|jose`, content)
	some n in _needles
	contains(content, n)
}

# Code text: string literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `\s//.*$`, "")

# The file serves requests: an unverified token here is attacker-supplied.
_serves_requests(content) if regex.match(`\*http\.Request|gin\.Context|echo\.Context|fiber\.Ctx|metadata\.FromIncomingContext|"Authorization"|Bearer `, content)

_go_jose(content) if regex.match(`go-jose[^"\n]*/jwt"`, content)

# Enclosing function: from the nearest "func " line above (at most 80 lines)
# to the first column-0 "}" below (at most 80 lines).
_fn_lo(lines, i) := lo if {
	floor := max([0, i - 80])
	starts := [j | some j in numbers.range(floor, i); regex.match(`^func\b`, lines[j])]
	lo := max(array.concat([floor], starts))
}

_fn_hi(lines, i) := hi if {
	ceil := min([count(lines) - 1, i + 80])
	ends := [j | some j in numbers.range(i, ceil); startswith(lines[j], "}")]
	hi := min(array.concat([ceil], ends))
}

# Text of the function except line i, comments and strings removed.
_fn_text(lines, i) := concat("\n", [_code(l) |
	some j in numbers.range(_fn_lo(lines, i), _fn_hi(lines, i))
	j != i
	l := lines[j]
	not helpers.is_comment_line(l)
])

_verify_re := `\bjwt\.Parse\(|\.ParseWithClaims\(|\.Parse\(\s*\w+\s*,\s*(?:func|\w+)|\.Claims\(\s*&?[\w\.\[\]]+\s*,|\bVerify\w*\(|\bjws\.Verify\(|jwt\.WithKey\(|WithKeySet\(`

# 1. alg "none" accepted by verification (not used to sign).
_kind(_, _, _, code) := "a key function that returns jwt.UnsafeAllowNoneSignatureType accepts unsigned alg \"none\" tokens" if {
	contains(code, "UnsafeAllowNoneSignatureType")
	not regex.match(`Sign(?:ed|ing)?String\([^)]*UnsafeAllowNoneSignatureType|\.Sign\([^)]*UnsafeAllowNoneSignatureType`, code)
	regex.match(`\breturn\s+[\w\.]*UnsafeAllowNoneSignatureType\b`, code)
}

# ...or held in a variable by a function that signs nothing.
_kind(lines, i, _, code) := "jwt.UnsafeAllowNoneSignatureType held as a verification key accepts unsigned alg \"none\" tokens" if {
	regex.match(`=\s*[\w\.]*UnsafeAllowNoneSignatureType\s*$`, code)
	not regex.match(`NewWithClaims\(|\bjwt\.New\(|Sign(?:ed|ing)String\(|\.Sign\(`, _fn_text(lines, i))
}

# 2. jwx verification switched off.
_kind(_, _, _, code) := "jwt.WithVerify(false) parses the token without checking its signature" if {
	regex.match(`\bWithVerify\(\s*false\s*\)`, code)
}

# 3. Unverified parsing in request-handling code, never followed by verification.
_kind(lines, i, content, code) := "the token is parsed without verifying its signature and nothing in this function verifies it; its claims are attacker-chosen" if {
	regex.match(`\.ParseUnverified\(|\bjwt\.ParseInsecure\(|\.Unsafe(?:Claims|Payload)WithoutVerification\(`, code)
	_serves_requests(content)
	not regex.match(_verify_re, _fn_text(lines, i))
}

# 4. golang-jwt parse error discarded and token.Valid never consulted.
_kind(lines, i, content, code) := "the parse error is discarded and token.Valid is never checked: jwt.Parse returns the token even when its signature does not verify" if {
	not _go_jose(content)
	ms := regex.find_all_string_submatch_n(`^\s*(\w+)\s*,\s*_\s*:?=\s*[\w\.\(\)]*\bParse(?:WithClaims)?\(`, code, 1)
	count(ms) > 0
	tok := ms[0][1]
	tok != "_"
	end := min([count(lines) - 1, _fn_hi(lines, i), i + 30])
	after := concat("\n", [lines[k] | some k in numbers.range(i + 1, end)])
	regex.match(concat("", [`\b`, tok, `\.Claims\b`]), after)
	not regex.match(concat("", [`\b`, tok, `\.Valid\b`]), after)
}

# 4b. ParseWithClaims into a claims value whose result and error are both
# dropped: the claims are filled in even when the signature fails.
_kind(_, _, content, code) := "the token and error from ParseWithClaims are both discarded, but the claims it fills in are used: they are filled in even when the signature does not verify" if {
	not _go_jose(content)
	regex.match(`^\s*(?:_\s*,\s*)?_\s*:?=\s*[\w\.\(\)]*\bParseWithClaims\(`, code)
}

# ...or the token is kept, the error dropped, and the claims variable read
# with no token.Valid check.
_kind(lines, i, content, code) := "the parse error is discarded and token.Valid is never checked: ParseWithClaims fills in the claims even when the signature does not verify" if {
	not _go_jose(content)
	ms := regex.find_all_string_submatch_n(`^\s*(\w+)\s*,\s*_\s*:?=\s*[\w\.\(\)]*\bParseWithClaims\([^,]+,\s*&(\w+)\s*,`, code, 1)
	count(ms) > 0
	tok := ms[0][1]
	tok != "_"
	cv := ms[0][2]
	end := min([count(lines) - 1, _fn_hi(lines, i), i + 30])
	after := concat("\n", [lines[k] | some k in numbers.range(i + 1, end)])
	regex.match(concat("", [`\b`, cv, `\.\w`]), after)
	not regex.match(concat("", [`\b`, tok, `\.Valid\b`]), after)
	not regex.match(concat("", [`\b`, tok, `\.Claims\b`]), after)
}

# 3b. jwx jws.Parse only decodes the message; jws.Verify checks it.
_kind(lines, i, content, code) := "jws.Parse decodes the message without verifying its signature and nothing in this function verifies it; its payload is attacker-chosen" if {
	regex.match(`\bjws\.Parse(?:String|Reader)?\(`, code)
	_serves_requests(content)
	not regex.match(_verify_re, _fn_text(lines, i))
}

# 5. go-jose signature check whose error is dropped.
_kind(_, _, content, code) := "the error from tok.Claims(key, ...) is the signature check, and it is dropped" if {
	_go_jose(content)
	regex.match(`^\s*(?:_\s*=\s*)?\w+\.Claims\(\s*&?[\w\.\[\]]+\s*,\s*&?[\w\.]+(?:\s*,\s*&?[\w\.]+)*\s*\)\s*;?\s*$`, code)
}

# Inside a /* ... */ block whose lines carry no leading '*'.
_in_block_comment(lines, i) if {
	i > 0
	some j in numbers.range(max([0, i - 40]), i - 1)
	contains(lines[j], "/*")
	not contains(substring(lines[j], indexof(lines[j], "/*") + 2, -1), "*/")
	not _closed_between(lines, j, i)
}

_closed_between(lines, j, i) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	contains(lines[k], "*/")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Unsafe|Unverified|Insecure|WithVerify|Parse|\.Claims\(`, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	some msg in {m | m := _kind(lines, i, content, code)}
	not _in_block_comment(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": concat("", ["JWT signature not verified: ", msg, ". Verify with jwt.ParseWithClaims (or go-jose tok.Claims(key, ...)) and reject the token on error"]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
