package vulnetix.rules.vnx_go_033

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-033",
	"name": "JWT missing audience validation",
	"description": "A Go service verifies a JWT without checking its audience (aud) claim, so a token issued by the same identity provider for a different service is accepted. Reported: a golang-jwt jwt.Parse/ParseWithClaims call or jwt.NewParser/jwt.Parser construction whose own arguments carry no jwt.WithAudience option, a lestrrat jwx jwt.Parse/ParseString/ParseRequest call likewise, and a go-jose jwt.ParseSigned/ParseSignedAndEncrypted call, each only when nothing else in the same file checks the audience (WithAudience, VerifyAudience, GetAudience, jwt.Expected{AnyAudience/Audience}, a read of .Audience, .Aud or claims[\"aud\"]); and a go-oidc oidc.Config with SkipClientIDCheck: true, which turns the audience check off. Not reported: a wrapper that forwards its caller's parser options (opts...), a method on a parser variable (the construction is judged instead), jwt.ParseUnverified, including jwt.NewParser().ParseUnverified (no signature check at all, a different weakness), test files, comments and string literals. Audience checks performed in another file are not seen.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-033/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [347],
	"capec": ["CAPEC-64"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["jwt", "token", "audience", "authentication"],
}

# String literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `//.*$`, "")

# The JWT packages' import aliases in this file ("jwt" always), so
# `jwtlib "github.com/golang-jwt/jwt/v5"` is followed as well.
_import_re := `(?m)^\s*(?:import\s+)?(\w+)\s+"(?:github\.com/(?:golang-jwt/jwt|dgrijalva/jwt-go|form3tech-oss/jwt-go|lestrrat-go/jwx(?:/v\d+)?/jwt|go-jose/go-jose/v\d+/jwt|square/go-jose/jwt)|gopkg\.in/(?:square/)?go-jose\.v\d/jwt|gopkg\.in/go-jose/go-jose\.v\d/jwt)[^"]*"`

_aliases(content) := {a | some m in regex.find_all_string_submatch_n(_import_re, content, -1); a := m[1]; a != "_"} | {"jwt"}

_verify_re(pfx) := sprintf(`\b(?:%s)\.(?:Parse|ParseWithClaims|ParseString|ParseRequest|ParseSigned|ParseSignedAndEncrypted|NewParser)\(|&(?:%s)\.Parser\{|new\((?:%s)\.Parser\)`, [pfx, pfx, pfx])

_aud_re := `WithAudience\(|VerifyAudience\(|GetAudience\(|AnyAudience|\bAudience\s*:|\.(?:Audience|Aud)\b|\[\s*"aud"\s*\]`

_depth(s) := count(indexof_n(s, "(")) - count(indexof_n(s, ")"))

# The call's text, from the call to the line where its parentheses close
# (at most 15 lines).
_call(lines, i, first) := first if _depth(first) <= 0

_call(lines, i, first) := txt if {
	_depth(first) > 0
	end := min([count(lines) - 1, i + 15])
	end >= i + 1
	ks := [k |
		some k in numbers.range(i + 1, end)
		_depth(concat("\n", array.concat([first], [_code(lines[j]) | some j in numbers.range(i + 1, k)]))) <= 0
	]
	txt := concat("\n", array.concat([first], [_code(lines[j]) | some j in numbers.range(i + 1, _last(ks, end))]))
}

_last(ks, end) := ks[0] if count(ks) > 0

_last(ks, end) := end if count(ks) == 0

_msg := "JWT is verified without checking its audience (aud) claim: a token minted for another service by the same issuer is accepted. Pass jwt.WithAudience(...) (or validate the aud claim)"

_msg_oidc := "oidc.Config sets SkipClientIDCheck: true, so the ID token's audience is never checked; set ClientID instead"

_hit(_, _, code, _, _) := _msg_oidc if regex.match(`\bSkipClientIDCheck\s*:\s*true\b`, code)

_hit(lines, i, code, aud_in_file, pfx) := _msg if {
	not aud_in_file
	not contains(code, "ParseUnverified(")
	ms := regex.find_all_string_submatch_n(_verify_re(pfx), code, 1)
	count(ms) > 0
	txt := _call(lines, i, substring(code, indexof(code, ms[0][0]), -1))
	not contains(txt, "WithAudience(")
	not regex.match(`\w\.\.\.\s*\)`, txt)
}

_gate(content) if regex.match(`jwt\.(?:Parse|NewParser)|jwt\.Parser|SkipClientIDCheck`, content)

_gate(content) if {
	contains(content, "jwt")
	regex.match(_import_re, content)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	_gate(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	aud_in_file := regex.match(_aud_re, helpers.code_text(lines))
	pfx := concat("|", sort(_aliases(content)))
	line_re := sprintf(`\b(?:%s)\.|SkipClientIDCheck`, [pfx])
	some i, line in lines
	regex.match(line_re, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	some msg in {m | m := _hit(lines, i, code, aud_in_file, pfx)}
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
