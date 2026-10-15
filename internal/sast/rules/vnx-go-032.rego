package vulnetix.rules.vnx_go_032

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-032",
	"name": "JWT missing expiration validation",
	"description": "A JWT's expiry is never enforced, so a leaked token works for ever. Reported on the verifying side: golang-jwt jwt.WithoutClaimsValidation() and the v3/v4 Parser field SkipClaimsValidation: true (exp, nbf and iat are then not checked), lestrrat-go/jwx jwt.WithValidate(false), and a go-jose tok.Claims(key, &c) whose function never calls Validate/ValidateWithLeeway (go-jose verifies only the signature in Claims; expiry is checked by Validate). Reported on the issuing side: golang-jwt jwt.NewWithClaims with a claims composite literal (inline, or a variable assigned one in the same function) and jwt.New followed by token.Claims.(jwt.MapClaims) edits, go-jose jwt.Signed(...) with a jwt.Claims or map literal, and a lestrrat-go/jwx jwt.NewBuilder() chain with no Expiration(...), when the function sets no \"exp\", ExpiresAt or Expiry. Not reported: claims built by a helper or passed in as a parameter (the expiry may be set there), default parsing (golang-jwt v4+ checks exp when present), WithExpirationRequired/WithLeeway/WithValidate(true), test files, comments and strings. Tokens that omit exp are accepted by golang-jwt unless WithExpirationRequired is set; that default is not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-032/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [613],
	"capec": ["CAPEC-64"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["jwt", "token", "expiration", "authentication"],
}

_needles := ["WithoutClaimsValidation", "NewBuilder(", "SkipClaimsValidation", "WithValidate(", "NewWithClaims(", "jwt.New(", ".Claims(", "Signed("]

_gate(content) if {
	contains(content, "jwt")
	some n in _needles
	contains(content, n)
}

# Code text: string literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `\s//.*$`, "")

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

# The function's code, comments removed (string literals kept: "exp" is a key).
_fn_text(lines, i) := concat("\n", [l |
	some j in numbers.range(_fn_lo(lines, i), _fn_hi(lines, i))
	l := lines[j]
	not helpers.is_comment_line(l)
])

# The expiry is set, or the registered claims come from somewhere else.
_exp_re := `"exp"|\bExpiresAt\b|\bExpiry\b|\bExp\w*\s*:|\.Exp\w*\s*=|\.SetExpiration|RegisteredClaims\s*[:=]\s*\w+\(|StandardClaims\s*[:=]\s*\w+\(`

# 1-3. Expiry validation switched off.
_kind(_, _, _, code) := "jwt.WithoutClaimsValidation() turns off the exp, nbf and iat checks" if regex.match(`\bWithoutClaimsValidation\(\s*\)`, code)

_kind(_, _, _, code) := "SkipClaimsValidation: true turns off the exp, nbf and iat checks" if regex.match(`\bSkipClaimsValidation\s*(?::|=)\s*true\b`, code)

_kind(_, _, _, code) := "jwt.WithValidate(false) turns off the exp, nbf and iat checks" if regex.match(`\bWithValidate\(\s*false\s*\)`, code)

# 4. go-jose: the signature is checked, the expiry never is.
_kind(lines, i, content, code) := "go-jose tok.Claims(key, ...) checks only the signature, and nothing in this function calls Validate or ValidateWithLeeway on the claims" if {
	_go_jose(content)
	regex.match(`\b\w+\.Claims\(\s*&?[\w\.\[\]]+\s*,\s*&?\w`, code)
	not regex.match(`\.Validate(?:WithLeeway)?\(`, _fn_text(lines, i))
}

# 5. Issued with a claims literal that carries no exp.
_claims_literal(lines, i, code) if regex.match(`\b\w*(?i:jwt)\w*\.NewWithClaims\(\s*[\w\.]+\s*,\s*&?[\w\.]+\{`, code)

_claims_literal(lines, i, code) if {
	ms := regex.find_all_string_submatch_n(`\b\w*(?i:jwt)\w*\.NewWithClaims\(\s*[\w\.]+\s*,\s*&?(\w+)\s*[,)]`, code, 1)
	count(ms) > 0
	v := ms[0][1]
	lo := _fn_lo(lines, i)
	some k in numbers.range(lo, i)
	regex.match(concat("", [`^\s*(?:var\s+)?`, v, `\s*(?::=|=)\s*&?[\w\.]+\{`]), lines[k])
}

_kind(lines, i, _, code) := "the token is issued without an exp claim, so it never expires" if {
	_claims_literal(lines, i, code)
	not regex.match(_exp_re, _fn_text(lines, i))
}

_kind(lines, i, _, code) := "the token is issued without an exp claim, so it never expires" if {
	regex.match(`\bjwt\.New\(\s*[\w\.]+\s*\)`, code)
	txt := _fn_text(lines, i)
	contains(txt, ".Claims.(jwt.MapClaims)")
	not regex.match(_exp_re, txt)
}

_kind(lines, i, content, code) := "the token is issued without an Expiry claim, so it never expires" if {
	_go_jose(content)
	regex.match(`\bjwt\.Signed\(`, code)
	txt := _fn_text(lines, i)
	regex.match(`\bjwt\.Claims\{|map\[string\](?:interface\{\}|any)\{`, txt)
	not regex.match(_exp_re, txt)
}

# lestrrat-go/jwx: jwt.NewBuilder() chain that never calls Expiration.
_kind(lines, i, content, code) := "the token is built without an exp claim (no .Expiration(...) on the jwx builder), so it never expires" if {
	contains(content, "lestrrat-go/jwx")
	regex.match(`\bjwt\.NewBuilder\(\s*\)`, code)
	txt := _fn_text(lines, i)
	not regex.match(`\bExpiration\(|ExpirationKey`, txt)
	not regex.match(_exp_re, txt)
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
	regex.match(`ClaimsValidation|WithValidate|NewWithClaims|NewBuilder\(|jwt\.New\(|\.Claims\(|Signed\(`, line)
	not helpers.is_comment_line(line)
	not startswith(line, "func ")
	code := _code(line)
	some msg in {m | m := _kind(lines, i, content, code)}
	not _in_block_comment(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": concat("", ["JWT expiry not enforced: ", msg, ". Set exp on every token you issue and keep claims validation on (golang-jwt: jwt.WithExpirationRequired(); go-jose: claims.ValidateWithLeeway)"]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
