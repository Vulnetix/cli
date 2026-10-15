# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_294

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-294",
	"name": "Authentication Bypass by Capture-replay",
	"description": "A signed token is accepted without its age being enforced, so a token captured once (from a log, a proxy, browser history or a leaked link) can be replayed indefinitely. Reported: expiry verification switched off (jsonwebtoken { ignoreExpiration: true } in JavaScript/TypeScript; PyJWT/python-jose options {\"verify_exp\": False}, inline, in an options dict or dict(verify_exp=False), and the old verify_expiration=False); a clock leeway of a day or more, which keeps expired tokens valid (jsonwebtoken/jose clockTolerance, PyJWT leeway= in a file that uses jwt, jjwt setAllowedClockSkewSeconds/clockSkewSeconds, Nimbus setMaxClockSkew, Auth0 java-jwt acceptLeeway/acceptExpiresAt and Spring Security new JwtTimestampValidator(Duration)), where the value can be read off the line: an integer or a product of integers (60 * 60 * 24 * 30), Long/Integer.MAX_VALUE, Infinity, TimeUnit.DAYS.toSeconds(n), Duration.ofDays/ofHours/ofMinutes/ofSeconds(n), timedelta(days=..), or a jose duration string ('2 days', '30d'); and a timestamped signature read without a maximum age (itsdangerous URLSafeTimedSerializer/TimedSerializer/TimestampSigner .loads()/.unsign(), through a name assigned from the constructor or inline, and Django signing.loads() or TimestampSigner().unsign(), without max_age in the call or with max_age=None). A leeway held in a variable or configuration is not judged. Not reported: verify_exp True, ignoreExpiration false, a leeway under a day, calls that pass max_age, untimed serializers and signers (which carry no age to check), json/pickle loads, and comments or string literals. Tokens issued without an exp claim are VNX-JWT-002; nonce or jti replay caches are not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-294/",
	"languages": ["java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [294],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["auth", "replay", "token-expiry", "cwe-294"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
}

# String literals are tokenised left to right: a literal that is a bare
# identifier ("verify_exp") becomes <verify_exp>, any other literal becomes <>,
# so a key inside a longer string never looks like a key.
_code(line) := regex.replace(line, `["'](\w+)["']|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, "<${1}>")

_day := 86400

_disabled := {
	"js": `\b(ignoreExpiration|<ignoreExpiration>)\s*:\s*true\b`,
	"py": `<verify_exp>\s*:\s*False\b|\bverify_exp(iration)?\s*=\s*False\b`,
}

_needle := {"js": "ignoreExpiration", "py": "verify_exp"}

# The leeway key, matched on the line with string literals tokenised (so a key
# named inside a message is not a key).
_leeway_key := {
	"js": `\b(clockTolerance|<clockTolerance>)\s*:`,
	"py": `\bleeway\s*=`,
	"java": `\.(setAllowedClockSkewSeconds|clockSkewSeconds|acceptLeeway|acceptExpiresAt|setMaxClockSkew)\(|\bnew\s+JwtTimestampValidator\(`,
}

# The leeway value, read from the raw line.
_leeway_re := {
	"js": `\bclockTolerance["']?\s*:\s*([^,}]+?)\s*(?:,|\}|$)`,
	"py": `\bleeway\s*=\s*((?:datetime\.)?timedelta\([^)]*\)|\d+(?:\.\d+)?)`,
	"java": `(?:\.(?:setAllowedClockSkewSeconds|clockSkewSeconds|acceptLeeway|acceptExpiresAt|setMaxClockSkew)|\bnew\s+JwtTimestampValidator)\(\s*(Duration\.of\w+\(\s*\d+L?\s*\)|.+?)\s*\)\s*(?:\.|;|$)`,
}

# Spring Security's JwtTimestampValidator(Duration clockSkew) is the leeway
# of every Spring resource server that sets it.
_leeway_needle := {"js": "clockTolerance", "py": "leeway", "java": "Skew"}

_leeway_line("java", line) if contains(line, "JwtTimestampValidator")

_leeway_needle_alt := {"js": "clockTolerance", "py": "leeway", "java": "accept"}

_unit := {
	"s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
	"m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
	"h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
	"d": 86400, "day": 86400, "days": 86400,
	"w": 604800, "week": 604800, "weeks": 604800,
	"y": 31557600, "yr": 31557600, "yrs": 31557600, "year": 31557600, "years": 31557600,
}

# The leeway in seconds, for the forms that can be read off the line: an
# integer, a product of integers, MAX_VALUE/Infinity, TimeUnit.X.toSeconds(n),
# timedelta(days=..), and a jose duration string ("2 days", "30d"). Anything
# else (a variable, a config lookup) is not judged.
_seconds(e) := to_number(trim_suffix(e, "L")) if {
	regex.match(`^\d+L?$`, e)
} else := product([to_number(trim_suffix(trim_space(x), "L")) | some x in split(e, "*")]) if {
	regex.match(`^\d+L?(\s*\*\s*\d+L?)+$`, e)
} else := 1e18 if {
	regex.match(`^(Long\.MAX_VALUE|Integer\.MAX_VALUE|Number\.MAX_SAFE_INTEGER|Number\.MAX_VALUE|Infinity)$`, e)
} else := to_number(m[0][2]) * _unit[lower(m[0][1])] if {
	m := regex.find_all_string_submatch_n(`^TimeUnit\.(DAYS|HOURS|MINUTES|SECONDS)\.toSeconds\(\s*(\d+)L?\s*\)$`, e, 1)
	count(m) > 0
} else := to_number(m[0][2]) * _unit[lower(m[0][1])] if {
	m := regex.find_all_string_submatch_n(`^Duration\.of(Days|Hours|Minutes|Seconds)\(\s*(\d+)L?\s*\)$`, e, 1)
	count(m) > 0
} else := _timedelta_seconds(e) if {
	regex.match(`^(datetime\.)?timedelta\(`, e)
} else := to_number(m[0][1]) * _unit[lower(m[0][2])] if {
	m := regex.find_all_string_submatch_n(`^["'\x60]\s*(\d+(?:\.\d+)?)\s*([A-Za-z]+)\s*["'\x60]$`, e, 1)
	count(m) > 0
	_unit[lower(m[0][2])]
}

_timedelta_seconds(e) := sum([s |
	some kv in regex.find_all_string_submatch_n(`\b(weeks|days|hours|minutes|seconds)\s*=\s*(\d+(?:\.\d+)?)`, e, -1)
	s := to_number(kv[2]) * _unit[kv[1]]
])

_too_long(v) if _seconds(v) >= _day

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# Expiry verification switched off.
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, _needle[lang])
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`ignoreExpiration|verify_exp`, line)
	not helpers.is_comment_line(line)
	regex.match(_disabled[lang], _code(line))
	finding := _finding(path, i, line, "Token expiry is not verified, so a token captured once stays valid for ever and can be replayed. Remove ignoreExpiration/verify_exp=False and keep tokens short-lived; refresh them instead of accepting expired ones")
}

# A leeway of a day or more.
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_leeway_file(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	_leeway_line(lang, line)
	not helpers.is_comment_line(line)
	regex.match(_leeway_key[lang], _code(line))
	m := regex.find_all_string_submatch_n(_leeway_re[lang], line, 1)
	count(m) > 0
	_too_long(trim_space(m[0][1]))
	finding := _finding(path, i, line, "The clock leeway accepts tokens a day or more after they expire, which makes expiry meaningless and lets a captured token be replayed. Keep the leeway to seconds or a few minutes")
}

_leeway_file("py", content) if {
	contains(content, "leeway")
	contains(content, "jwt")
}

_leeway_file("js", content) if contains(content, "clockTolerance")

_leeway_file("java", content) if regex.match(`ClockSkewSeconds|clockSkewSeconds|acceptLeeway|acceptExpiresAt|setMaxClockSkew|JwtTimestampValidator`, content)

# max_age given a value; max_age=None is no maximum at all.
_bounded_age(text) if {
	contains(text, "max_age")
	not regex.match(`\bmax_age\s*=\s*None\b`, text)
}

_leeway_line(lang, line) if contains(line, _leeway_needle[lang])

_leeway_line(lang, line) if contains(line, _leeway_needle_alt[lang])

# ── Timestamped signatures read without max_age (Python) ─────────────────

_timed_ctor := `\b(URLSafe)?Timed(JSONWebSignature)?Serializer\s*\(|\bTimestampSigner\s*\(`

_timed_names(lines) := {m[0][1] |
	some l in lines
	contains(l, "Time")
	m := regex.find_all_string_submatch_n(`^\s*(?:self\.)?(\w+)\s*(?::\s*[\w\[\]\.]+\s*)?=\s*(?:[\w\.]+\.)?((URLSafe)?Timed(JSONWebSignature)?Serializer|TimestampSigner)\s*\(`, l, 1)
	count(m) > 0
}

# The call's text up to the line that closes its parentheses.
_call_text(lines, i) := txt if {
	end := min([count(lines) - 1, i + 8])
	closes := [k |
		some k in numbers.range(i, end)
		_balance(lines, i, k) <= 0
	]
	last := min(array.concat([end], closes))
	txt := concat("\n", [lines[k] | some k in numbers.range(i, last); not helpers.is_comment_line(lines[k])])
}

_balance(lines, i, k) := sum([n |
	some j in numbers.range(i, k)
	c := _code(lines[j])
	n := (count(split(c, "(")) - 1) - (count(split(c, ")")) - 1)
])

_timed_call(lines, line) if {
	some r in _timed_names(lines)
	regex.match(concat("", [`\b(self\.)?`, r, `\.(loads|unsign|loads_unsafe)\s*\(`]), line)
}

_timed_call(_, line) if {
	regex.match(`\b((URLSafe)?Timed(JSONWebSignature)?Serializer|TimestampSigner)\s*\([^)]*\)\s*\.(loads|unsign|loads_unsafe)\s*\(`, line)
}

_timed_call(_, line) if regex.match(`\bsigning\.loads\s*\(`, line)

_timed_file(content) if {
	contains(content, "itsdangerous")
	regex.match(`Timed(JSONWebSignature)?Serializer|TimestampSigner`, content)
}

_timed_file(content) if {
	contains(content, "django")
	contains(content, "signing")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	_timed_file(content)
	regex.match(`\.(loads|unsign|loads_unsafe)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(loads|unsign|loads_unsafe)\s*\(`, line)
	not helpers.is_comment_line(line)
	_timed_call(lines, _code(line))
	not _bounded_age(_call_text(lines, i))
	finding := _finding(path, i, line, "This timestamped signature is checked without max_age, so the signed value never expires and a captured link or token can be replayed at any time. Pass max_age (seconds) to loads()/unsign()")
}
