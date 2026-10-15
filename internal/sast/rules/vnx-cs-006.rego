package vulnetix.rules.vnx_cs_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CS-006",
	"name": "C# System.Random output used for a token, password, key, salt, nonce or session value",
	"description": "A value that must be unpredictable is drawn from System.Random, whose output can be reproduced from its seed or from a few observed values. Reported: a Next, NextInt64, NextDouble, NextSingle, NextBytes or GetItems call on System.Random (an inline new Random(...), Random.Shared, or a variable, field or parameter declared as Random or assigned new Random(...), or the .Value of a ThreadLocal<Random>/Lazy<Random>) when the call sits in a security-sensitive context: the line, the enclosing method's name or the enclosing class's name (PasswordGenerator, InviteCodes) names a password, token, secret, API/private/signing key, salt, nonce, IV, session, CSRF/XSRF, OTP/PIN, reset, verification, activation or invitation code, credential or cipher, or a line up to four lines below uses the assigned variable or the NextBytes buffer in such a context (aes.IV = buffer), or a fixed-width numeric code such as code = r.Next(100000, 999999). Not reported: RandomNumberGenerator, RNGCryptoServiceProvider and BouncyCastle SecureRandom; names that only count, index or size tokens, keys or sessions (DrawTokenCount, sessionIndex, sessions[i], token buckets), and method or class names where reset, verify, session or activation name an operation rather than an issued value (ResetBoard, VerifyLayout, SimulateSessionTraffic); System.Random for shuffling, jitter, colours, sampling and other non-security values; the declaration of the Random instance itself; calls in test projects; and the pattern in comments and string literals. A value that becomes a secret only in another method or file is not followed.",
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
} | {concat("", [m[1], `\s*\.\s*Value`]) |
	# ThreadLocal<Random> / Lazy<Random>: the call is on .Value.
	some m in regex.find_all_string_submatch_n(`(?:ThreadLocal|Lazy)\s*<\s*(?:System\.)?Random\s*>\s+([A-Za-z_]\w*)\s*[=;,)]`, content, -1)
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

# Names that only count or locate tokens and keys (DrawTokenCount, pinIndex,
# sessionTimeout) say nothing about secrecy; they are removed before the test.
_benign_compound := `(?i)(token|key|session|pin|salt|nonce)s?[._]?(count|index|idx|length|len|position|pos|kind|type|timeout|delay|duration|limit|size|width|height|colou?r|bucket)|(?i)(token|key|session|pin|salt|nonce)s\s*\[`

_sensitive(text) if regex.match(_sensitive_re, regex.replace(text, _benign_compound, ""))

_sensitive(text) if regex.match(_key_re, regex.replace(text, _benign_compound, ""))

# A fixed-width numeric code (Next(100000, 999999), Next(1000, 10000))
# assigned to a name saying code: the shape of a one-time or verification code.
_sensitive(text) if {
	regex.match(`\bNext\s*\(\s*10{3,8}\s*,\s*(?:9{4,9}|10{4,9})\s*\)`, text)
	regex.match(`(?i)\b\w*code\w*\s*=[^=]`, text)
}

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

# In a method or class name, reset/verify/session/activation alone describe
# an operation (ResetBoard, VerifyLayout, SimulateSessionTraffic), not a
# secret; they count when paired with what is issued (ResetLink, SessionId).
_name_sensitive(name) if _sensitive(regex.replace(name, `(?i)reset|verif\w*?(?:y|ication)?|session|activation`, " "))

_name_sensitive(name) if regex.match(`(?i)(reset|verif\w*|session|activation)(link|token|code|key|id|url|secret)`, name)

_context(lines, i, _) if _name_sensitive(_enclosing_method(lines, i))

# The enclosing class names what it generates (PasswordGenerator, InviteCodes).
_class_decl_re := `\b(?:class|struct|record)\s+([A-Za-z_]\w*)`

_enclosing_class(lines, i) := name if {
	idx := [j |
		some j in numbers.range(max([0, i - 300]), i)
		contains(lines[j], "class ")
		regex.match(_class_decl_re, lines[j])
		not helpers.is_comment_line(lines[j])
	]
	count(idx) > 0
	name := regex.find_all_string_submatch_n(_class_decl_re, lines[idx[count(idx) - 1]], 1)[0][1]
}

_context(lines, i, _) if _name_sensitive(_enclosing_class(lines, i))

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
