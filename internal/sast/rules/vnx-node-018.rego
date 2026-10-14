package vulnetix.rules.vnx_node_018

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-018",
	"name": "JWT decoded without signature verification",
	"description": "A jsonwebtoken token is accepted without its signature being checked. Reported, in JavaScript and TypeScript files that import or require jsonwebtoken: decode() called through a name bound to the module (require, default or namespace import) or through decode imported by name (including an `as` alias), in a file whose code never calls verify(); and an algorithms list passed to jsonwebtoken that contains 'none'. decode() only base64-decodes the payload, so a token anyone wrote is trusted. Not reported: a decode() in a file that also verifies (reading the header to pick a key, then verify()), the browser-side jwt-decode package, jwt-simple's decode(token, key) which verifies, test files, comments and string literals. Overlaps VNX-JWT-001 (request-derived token decoded without verify) and VNX-JWT-004 (the 'none' algorithm).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-018/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [347],
	"capec": ["CAPEC-196"],
	"attack_technique": ["T1550.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["jwt", "authentication", "signature-bypass", "node"],
}

_is_js(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)

_mod := `['"]jsonwebtoken['"]`

_alias_res := [
	concat("", [`\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*`, _mod, `\s*\)`]),
	concat("", [`\bimport\s+(?:\*\s+as\s+)?(\w+)\s*(?:,\s*\{[^}]*\}\s*)?from\s+`, _mod]),
	concat("", [`\bimport\s+(\w+)\s*=\s*require\(\s*`, _mod]),
]

_named_res := [
	concat("", [`\bimport\s*(?:\w+\s*,\s*)?\{([^}]*)\}\s*from\s*`, _mod]),
	concat("", [`\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*`, _mod]),
]

_strip(line) := regex.replace(line, `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`, `""`)

_aliases(lines) := {a |
	some l in lines
	contains(l, "jsonwebtoken")
	not helpers.is_comment_line(l)
	some re in _alias_res
	some m in regex.find_all_string_submatch_n(re, l, -1)
	a := m[1]
}

_named(lines) := {local |
	some l in lines
	contains(l, "jsonwebtoken")
	not helpers.is_comment_line(l)
	some re in _named_res
	some m in regex.find_all_string_submatch_n(re, l, -1)
	some item in split(m[1], ",")
	parts := regex.split(`\s+as\s+|\s*:\s*`, trim_space(item))
	parts[0] == "decode"
	local := trim_space(parts[count(parts) - 1])
}

_decode_re(aliases, named) := concat("|", array.concat(
	[concat("", [`\b`, a, `\s*\.\s*decode\s*\(`]) | some a in aliases],
	[concat("", [`(?:^|[^.\w])`, n, `\s*\(`]) | some n in named],
))

_source := `\b(?:req|request)\.(?:headers?|cookies|signedCookies|query|body|params|get)\b|\bctx\.(?:request|headers|cookies|query|get)\b|\bevent\.headers\b|\bhandshake\b|\bauthorization\b|\bAuthorization\b`

# The decoded argument: the text after the paren, or the next code line.
_decode_arg(lines, i, code, re) := arg if {
	parts := regex.split(re, code)
	count(parts) > 1
	rest := trim_space(parts[1])
	arg := _arg_or_next(lines, i, rest)
}

_arg_or_next(_, _, rest) := rest if rest != ""

_arg_or_next(lines, i, "") := trim_space(lines[j]) if j := helpers.next_code_index(lines, i, 3)

# The token is a variable the code above assigned from something other than
# the request (a token the server issued and stored itself): decoding it to
# read iat or exp trusts nothing an attacker sent.
_internal_token(lines, i, arg) if {
	not regex.match(_source, arg)
	m := regex.find_all_string_submatch_n(`^([A-Za-z_$][\w$]*)\s*[,)]`, arg, 1)
	v := m[0][1]
	tainted := helpers.tainted_names(lines, i, 15, _source)
	some j in numbers.range(max([0, i - 15]), i - 1)
	l := lines[j]
	regex.match(concat("", [`^\s*(?:(?:const|let|var)\s+)?`, v, `\s*(?::[^=]+)?=[^=]`]), l)
	not regex.match(_source, l)
	not _mentions_any(l, tainted)
}

_mentions_any(l, names) if {
	some n in names
	regex.match(concat("", [`\b`, n, `\b`]), l)
}

_verifies(code) if regex.match(`\bverify\s*\(`, code)

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	not helpers.is_test_path(path)
	contains(content, "jsonwebtoken")
	regex.match(`decode\s*\(`, content)
	lines := split(content, "\n")
	not _verifies(_strip(helpers.code_text(lines)))
	re := _decode_re(_aliases(lines), _named(lines))
	re != ""
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	code := _strip(line)
	regex.match(re, code)
	not _internal_token(lines, i, _decode_arg(lines, i, code, re))
	finding := {
		"rule_id": metadata.id,
		"message": "jsonwebtoken decode() does not check the signature, and this file never calls verify(): a forged token is accepted. Use jwt.verify() with the expected key and algorithms",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	not helpers.is_test_path(path)
	contains(content, "jsonwebtoken")
	regex.match(`(?i)['"]none['"]`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "algorithms")
	not helpers.is_comment_line(line)
	regex.match(`\balgorithms\s*:\s*\[[^\]]*['"](?i:none)['"]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "jsonwebtoken is told to accept the 'none' algorithm, so an unsigned token passes verification; list only the signing algorithms you issue",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
