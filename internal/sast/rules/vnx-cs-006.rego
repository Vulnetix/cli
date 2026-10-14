package vulnetix.rules.vnx_cs_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CS-006",
	"name": "C# System.Random output used for a token, password, key, salt, nonce or session value",
	"description": "A value that must be unpredictable is drawn from System.Random, whose output can be reproduced from its seed or from a few observed values. Reported: a Next, NextInt64, NextDouble, NextSingle, NextBytes or GetItems call on System.Random (an inline new Random(...), Random.Shared, or a variable, field or parameter declared as Random or assigned new Random(...)) when the call sits in a security-sensitive context: the line or the enclosing method's name names a password, token, secret, API/private/signing key, salt, nonce, IV, session, CSRF/XSRF, OTP/PIN, reset, verification, activation or invitation code, credential or cipher, or a line up to four lines below uses the assigned variable or the NextBytes buffer in such a context (aes.IV = buffer). Not reported: RandomNumberGenerator, RNGCryptoServiceProvider and BouncyCastle SecureRandom; System.Random for shuffling, jitter, colours, sampling and other non-security values; the declaration of the Random instance itself; calls in test projects; and the pattern in comments and string literals. A value that becomes a secret only in another method or file is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-006/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [338],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["weak-random", "cryptography", "csharp"],
}

_is_cs(path) if endswith(path, ".cs")

_is_cs_test(path) if helpers.is_test_path(path)

_is_cs_test(path) if regex.match(`(^|/)[^/]*\.(Tests?|UnitTests|IntegrationTests|FunctionalTests|Specs?)/`, path)

_is_cs_test(path) if regex.match(`Tests?\.cs$`, path)

_methods := `(?:Next|NextInt64|NextDouble|NextSingle|NextBytes|GetItems)`

_call_re := concat("", [`\.\s*`, _methods, `\s*\(`])

# Receivers that are System.Random: a declaration typed Random (local, field,
# parameter) or a name assigned new Random(...).
_receivers(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.]|System\.)Random\s+([A-Za-z_]\w*)\s*[=;,)]`, content, -1)
	n := m[1]
} | {n |
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*new\s+(?:System\.)?Random\s*\(`, content, -1)
	n := m[1]
}

# Code of a line with string literals emptied and a trailing comment dropped.
_strip_strings(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

_call_sink(code, _) if regex.match(concat("", [`\bnew\s+(?:System\.)?Random\s*\([^()]*\)\s*\)?\s*`, _call_re]), code)

_call_sink(code, _) if regex.match(concat("", [`\b(?:System\.)?Random\.Shared\s*`, _call_re]), code)

_call_sink(code, recv) if {
	some n in recv
	regex.match(concat("", [`(?:^|[^\w.])`, n, `\s*`, _call_re]), code)
}

_sensitive_re := `(?i)(passw|passphrase|\bpwd|token|secret|api_?key|private_?key|signing_?key|encryption_?key|master_?key|session|nonce|salt|\biv\b|csrf|xsrf|\botp|totp|hotp|\bpin(?:code)?\b|reset|verif|activation|invitation|invite|credential|cipher|\baes\b|hmac|auth_?code|confirmation_?code)`

_key_re := `\b[kK]ey(?:s|Bytes|Material)?\b|\bKEY\b`

_sensitive(text) if regex.match(_sensitive_re, text)

_sensitive(text) if regex.match(_key_re, text)

_method_decl_re := `^\s*(?:(?:public|private|protected|internal|static|async|override|virtual|sealed|unsafe|extern|new)\s+)+[\w<>\[\],.?]+(?:\s*<[^>]*>)?\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(`

# Name of the nearest method declaration up to 40 lines above.
_enclosing_method(lines, i) := name if {
	idx := [j |
		some j in numbers.range(max([0, i - 40]), i)
		regex.match(_method_decl_re, lines[j])
	]
	count(idx) > 0
	m := regex.find_all_string_submatch_n(_method_decl_re, lines[idx[count(idx) - 1]], 1)
	name := m[0][1]
}

# The value the call produces: the NextBytes buffer, or the assigned name.
_tracked(code) := v if {
	m := regex.find_all_string_submatch_n(`NextBytes\s*\(\s*([A-Za-z_]\w*)`, code, 1)
	count(m) > 0
	v := m[0][1]
}

_tracked(code) := v if {
	not regex.match(`NextBytes\s*\(\s*[A-Za-z_]`, code)
	v := helpers.assigned_first(code)
}

_context(_, _, code) if _sensitive(code)

_context(lines, i, _) if _sensitive(_enclosing_method(lines, i))

_context(lines, i, code) if {
	v := _tracked(code)
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 4]))
	not helpers.is_comment_line(lines[j])
	later := _strip_strings(lines[j])
	regex.match(concat("", [`\b`, v, `\b`]), later)
	_sensitive(later)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_cs(path)
	contains(content, "Random")
	not _is_cs_test(path)
	regex.match(concat("", [`(?m)`, _call_re]), content)
	recv := _receivers(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_call_re, line)
	not helpers.is_comment_line(line)
	code := _strip_strings(line)
	_call_sink(code, recv)
	_context(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": "System.Random generates a security-sensitive value; use System.Security.Cryptography.RandomNumberGenerator (GetBytes, GetInt32, GetItems) instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
