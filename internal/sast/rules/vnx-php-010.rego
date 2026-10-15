package vulnetix.rules.vnx_php_010

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-010",
	"name": "PHP type juggling in comparison",
	"description": "A loose comparison (== , != or <>) decides an authentication or integrity check, where PHP type juggling lets an attacker pass it: numeric strings compare as numbers (two different '0e...' magic hashes are equal), JSON true equals any non-empty string, and before PHP 8 0 equals any non-numeric string. Reported: (1) the result of md5(), sha1(), hash(), hash_hmac(), crypt() or *_file() compared loosely with a variable, call or property, or with a '0e<digits>' literal; (2) user input (a $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER/$_FILES element, or a variable assigned within the 30 lines above from a superglobal, json_decode(), php://input or $request->input()/get()/query()/header()/cookie()) compared loosely with a variable, call or property when either side names a secret as a whole identifier word, split at underscores and camelCase (password, pass, pwd, token, secret, hash, sig/signature, hmac, otp, nonce, csrf, api key, auth, digest, answer, code, pin), so author, hashtag, passenger or encoding do not count; (3) strcmp()/strcasecmp()/strncmp() of user input whose result is compared loosely with 0 or negated, which an array argument (NULL) bypasses. Not reported: strict === / !== comparisons, hash_equals() and password_verify(), user input compared with a constant literal (a request value is always a string, so a non-numeric literal does not juggle), comparisons of names that do not denote a secret, in_array()/switch loose matching, and the comparison inside a comment or a string literal.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-010/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [697],
	"capec": ["CAPEC-153"],
	"attack_technique": ["T1548"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["type-juggling", "authentication", "comparison", "php"],
}

_op := `(\$\w+(?:\s*\[[^\]]*\]|->\w+|::\$?\w+)*(?:\s*\((?:[^()]|\([^()]*\))*\))?|[A-Za-z_][\w\\]*(?:::\w+)?\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|-?\d[\w.]*|\w+)`

_cmp_re := concat("", [_op, `\s*(?:==|!=|<>)\s*`, _op])

_source_re := `\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|\bjson_decode\s*\(|php://input|\$request->(input|get|query|post|header|cookie|json)\s*\(|\brequest\s*\(\s*['"]|\bgetallheaders\s*\(`

# Secret names are matched as whole identifier words (snake_case and
# camelCase are split), so author, hashtag, passenger or encoding do not
# count as auth, hash, pass or code.
_secret_words := {
	"pass", "passwd", "password", "passphrase", "pwd", "pw", "token", "secret",
	"hash", "sig", "signature", "hmac", "otp", "nonce", "csrf", "xsrf", "apikey",
	"auth", "digest", "answer", "pin", "code", "totp", "mfa",
}

_names_secret(s) if {
	norm := lower(regex.replace(s, `([a-z0-9])([A-Z])`, "${1}_${2}"))
	some w in regex.find_n(`[a-z]+`, norm, -1)
	_secret_words[w]
}

_names_secret(s) if regex.match(`(?i)api_?key`, s)

_hash_re := `^(md5|sha1|hash|hash_hmac|crypt|md5_file|sha1_file|hash_file)\s*\(`

# A string literal that itself contains a comparison operator is prose.
# Literals are found left to right so quote pairs are matched correctly.
_masked(line) := strings.replace_n(
	{lit: `''` |
		some lit in regex.find_n(`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`, line, -1)
		regex.match(`==|!=|<>`, lit)
	},
	line,
)

_is_lit(op) if regex.match(`(?i)^(['"]|-?\d|true$|false$|null$)`, op)

_magic_lit(op) if regex.match(`^['"]0e\d+['"]$`, op)

_tainted(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 30]), i - 1)
	prev := lines[j]
	regex.match(_source_re, prev)
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(_direct_re, prev, 1)
	v := m[0][1]
}

# The assigned value IS the input (optionally through a trivial wrapper), not
# merely computed with it: $row = fetch_user($_POST['u']) is database data.
_direct_re := `^\s*\$(\w+)\s*=\s*(?:(?:trim|strtolower|strtoupper|urldecode|rawurldecode|base64_decode|stripslashes|json_decode|isset|\(string\))\s*\(?\s*)*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|json_decode\s*\(|file_get_contents\s*\(\s*['"]php://input|\$request->|request\s*\(|getallheaders\s*\()`

_is_user(op, _) if regex.match(`^\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b`, op)

_is_user(op, tainted) if {
	m := regex.find_all_string_submatch_n(`^\$(\w+)`, op, 1)
	tainted[m[0][1]]
}

_is_user(op, _) if regex.match(`^(\$request->(input|get|query|post|header|cookie)|request)\s*\(`, op)

_juggles(l, r, _) if {
	regex.match(_hash_re, l)
	not _is_lit(r)
}

_juggles(l, r, _) if {
	regex.match(_hash_re, l)
	_magic_lit(r)
}

_juggles(l, r, tainted) if {
	_is_user(l, tainted)
	not _is_lit(r)
	not _is_user(r, tainted)
	_names_secret(concat(" ", [l, r]))
}

_loose(code, tainted) if {
	some m in regex.find_all_string_submatch_n(_cmp_re, code, -1)
	l := trim_space(m[1])
	r := trim_space(m[2])
	_either(l, r, tainted)
}

_either(l, r, tainted) if _juggles(l, r, tainted)

_either(l, r, tainted) if _juggles(r, l, tainted)

_strcmp_re := `\bstrn?(?:case)?cmp\s*\(((?:[^()]|\([^()]*\))*)\)`

_strcmp_bypass(code, tainted) if {
	regex.match(`\bstrn?(?:case)?cmp\s*\((?:[^()]|\([^()]*\))*\)\s*(?:==|!=|<>)\s*0\b|\b0\s*(?:==|!=|<>)\s*strn?(?:case)?cmp\s*\(|!\s*strn?(?:case)?cmp\s*\(`, code)
	some m in regex.find_all_string_submatch_n(_strcmp_re, code, -1)
	_args_user(m[1], tainted)
}

_args_user(args, _) if regex.match(_source_re, args)

_args_user(args, tainted) if {
	some v in tainted
	regex.match(concat("", [`\$`, v, `\b`]), args)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`[^=!](==|!=|<>)[^=]|\bstrn?(case)?cmp\s*\(`, line)
	not helpers.is_comment_line(line)
	code := _masked(line)
	tainted := _tainted(lines, i)
	_report(code, tainted)
	finding := {
		"rule_id": metadata.id,
		"message": "Loose comparison decides an authentication or integrity check and is open to PHP type juggling; use === , hash_equals() or password_verify()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_report(code, tainted) if _loose(code, tainted)

_report(code, tainted) if _strcmp_bypass(code, tainted)

# Cheap whole-file gate: a comparison can only be reported in a file that
# reads input, hashes, or calls strcmp.
_gate(content) if {
	some s in ["$_", "json_decode", "$request", "request(", "md5", "sha1", "hash", "crypt(", "cmp("]
	contains(content, s)
}
