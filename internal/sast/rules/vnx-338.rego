# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_338

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-338",
	"name": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
	"description": "A value drawn from a non-cryptographic PRNG becomes a secret. Reported: JavaScript/TypeScript Math.random(); PHP rand(), mt_rand(), lcg_value(), str_shuffle() and array_rand() (all Mersenne Twister or LCG based); Ruby Kernel#rand, Random.rand, Random.new.rand/bytes and Array#sample/#shuffle; Go math/rand and math/rand/v2 draws (Int, Intn, Int63, Uint64, Float64, Read, Perm, N, under the package's import alias), when the draw is stored under, keyed by or returned as a security name (token, password, secret, nonce, salt, OTP, PIN, CSRF/XSRF, session id, API/secret/signing key, reset/verification/activation/invite code, session cookie): the name on the left of the assignment or object key, the string key of a setter or cookie call, an assignment opened on the line above, a return from a function named for a secret, or a variable assigned from the draw that reaches such a name within six lines. Not reported: crypto.randomBytes/randomUUID/getRandomValues, random_bytes()/random_int(), SecureRandom (including .sample(random: SecureRandom)) and crypto/rand; draws for jitter, sleeps, retries, colours, sampling and counts (names such as token_count, max_tokens, token_expiry); test files; and the pattern in comments or string literals. Overlaps VNX-GO-008, which covers Go in more depth; Python, Java, C# and C/C++ are covered by VNX-PY-005, VNX-JAVA-016, VNX-CS-006 and VNX-CRYPTO-009.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-338/",
	"languages": ["node", "php", "ruby", "go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [338],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["prng", "security", "cwe-338"],
}

_rule_single_words := set()

_rule_negative_words := set()

# ── Security context ──────────────────────────────────────────────────────
# A value is security-relevant when the name it is stored under (or the
# function that returns it) says it is a secret. Names are split into words
# at camelCase, snake_case and punctuation boundaries, so `resetToken`,
# `$_SESSION['session_token']`, `SESSION_ID` and `csrftoken` all qualify, and
# `tokenizer`, `max_tokens`, `token_expiry` and `monkey` do not.

_single_words := {
	"otp", "totp", "hotp", "salt", "iv", "pin", "pincode", "pwd", "sid", "jti",
	"nonce", "credential", "credentials", "captcha", "passphrase", "sessid",
}

_substr_words := {
	"token", "password", "passwd", "secret", "csrf", "xsrf", "apikey",
	"sessionid", "sessiontoken", "passcode",
}

_pair_words := {
	"session id", "session key", "session token", "session secret", "session value", "session cookie",
	"api key", "api secret", "api token", "auth key", "auth code", "auth token",
	"access key", "access token", "access code", "refresh token", "private key", "secret key",
	"signing key", "encryption key", "crypto key", "aes key", "hmac key", "master key",
	"shared key", "reset code", "reset key", "reset link", "reset id", "reset url",
	"verification code", "verify code", "activation code", "activation key", "invite code",
	"invitation code", "confirm code", "confirmation code", "recovery code", "recovery key",
	"login code", "magic link", "one time", "cookie value", "cookie id", "remember me",
	"pin code", "otp code", "security code", "unlock code", "auth id",
}

# Words that make a name about the secret's bookkeeping, not the secret.
_negative_words := {
	"count", "counts", "len", "length", "limit", "max", "min", "num", "size", "index",
	"idx", "type", "kind", "pos", "offset", "budget", "usage", "tokens", "expiry",
	"expires", "expire", "expiration", "exp", "ttl", "timeout", "created", "issued",
	"iat", "nbf", "age", "lifetime", "deadline", "duration", "interval", "elapsed",
	"updated", "delay", "sleep", "retry", "retries", "backoff", "jitter", "color",
	"colour", "width", "height", "time", "timestamp", "ts", "date", "start", "end",
	"attempt", "attempts", "tries", "failures", "failed", "errors", "error", "version",
	"hits", "uses", "used", "name", "label", "prefix", "path", "file", "dir", "field",
	"header", "param", "column", "pattern", "regex", "format", "placeholder", "hint",
	"tokenizer", "tokenize", "tokenized", "strength", "policy", "rule", "rules", "valid",
	"invalid", "is", "has", "check", "validate", "matches", "match",
	"encrypted", "salted", "input", "debug",
}

_words(name) := [w |
	some w in regex.split(`[^a-z0-9]+`, lower(regex.replace(name, `([a-z0-9])([A-Z])`, "${1}_${2}")))
	w != ""
]

_secure_name(name) if {
	ws := _words(name)
	not _has_negative(ws)
	_secure_words(ws)
}

_has_negative(ws) if {
	some w in ws
	w in _negative_words
}

_has_negative(ws) if {
	some w in ws
	w in _rule_negative_words
}

_secure_words(ws) if {
	some w in ws
	w in _single_words
}

_secure_words(ws) if {
	some w in ws
	w in _rule_single_words
}

_secure_words(ws) if {
	some w in ws
	some s in _substr_words
	contains(w, s)
	not startswith(w, "tokeniz")
}

_secure_words(ws) if {
	count(ws) > 1
	some k in numbers.range(0, count(ws) - 2)
	concat(" ", [ws[k], ws[k + 1]]) in _pair_words
}

# The name assigned (=, :=, .=, +=, ||=), keyed (key: / 'key' =>) or
# annotated (name: str =) last before position p of a line.
_key_re := `(?:\[\s*(?::|["'])([\w$@-]+)["']?\s*\]|([A-Za-z_$@][\w$@]*)["']?)\s*(?::=|\.=|\+=|\|\|=|\?\?=|=>|=|:)(?:[^=:>]|$)`

# A subscript counts only with a quoted or symbol key ($_SESSION['token'],
# session[:csrf]); cache[token] = ... is keyed by the token, not named for it.
_last_key(prefix) := concat("", [m[1], m[2]]) if {
	ms := regex.find_all_string_submatch_n(_key_re, prefix, -1)
	count(ms) > 0
	m := ms[count(ms) - 1]
}

_ctx(_, _, prefix) if _secure_name(_last_key(prefix))

# name: Type = <sink>
_ctx(_, _, prefix) if {
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:export|const|let|var|val|readonly|private|public|protected|static|declare)\s+)*(?:self\.|this\.)?([A-Za-z_$][\w$]*)\s*[?!]?\s*:\s*[A-Za-z_][\w\[\]., |<>]*=[^=:]*$`, prefix, 1)
	count(m) > 0
	_secure_name(m[0][1])
}

# A setter or store keyed by a string naming a secret:
# setValue("csrf-token", ...), localStorage.setItem('token', ...).
_ctx(_, _, prefix) if {
	ms := regex.find_all_string_submatch_n(`\w\s*\(\s*["']([^"']{1,60})["']\s*,[^,]*$`, prefix, -1)
	some m in ms
	_secure_name(m[1])
}

# A cookie set under a session or auth name: setcookie("dvwaSession", ...).
_ctx(_, _, prefix) if {
	ms := regex.find_all_string_submatch_n(`(?i)(?:setcookie|setrawcookie|set_cookie|\.cookie|new\s+Cookie|cookies\.set)\s*\(\s*["']([^"']+)["']\s*,[^,]*$`, prefix, -1)
	some m in ms
	regex.match(`(?i)sess|sid|auth|token|remember|login`, m[1])
}

# A Go cookie literal named for a session: &http.Cookie{Name: "session_id", Value: <sink>}.
_ctx(_, _, prefix) if {
	ms := regex.find_all_string_submatch_n(`Cookie\s*\{[^}]*\bName:\s*"([^"]+)"[^}]*\bValue:[^,}]*$`, prefix, -1)
	some m in ms
	regex.match(`(?i)sess|sid|auth|token|remember|login`, m[1])
}

# A C string function writing into a buffer named for a secret.
_ctx(_, _, prefix) if {
	ms := regex.find_all_string_submatch_n(`\b(?:snprintf|sprintf|strcpy|strncpy|strcat|memcpy)\s*\(\s*&?([A-Za-z_][\w.\->\[\]]*)`, prefix, -1)
	some m in ms
	_secure_name(m[1])
}

# The assignment opens on the line above: `String sessionId =` / `token:`.
_ctx(lines, i, prefix) if {
	not _last_key(prefix)
	i > 0
	m := regex.find_all_string_submatch_n(`([A-Za-z_$@][\w$@]*)["'\]\s]*(?::=|=|:|=>)\s*$`, lines[i - 1], 1)
	count(m) > 0
	_secure_name(m[0][1])
}

# Returned from a function whose name says it makes a secret.
_ctx(lines, i, prefix) if {
	regex.match(`^\s*return\b`, prefix)
	_secure_name(_enclosing_fn(lines, i))
}

# The body of a one-line function named for a secret:
# fun newOtp(): String = rng.nextInt(...), def token = ..., => Math.random().
_ctx(_, _, prefix) if _secure_name(_fn_name(prefix))

# Ruby's implicit return: the last expression before `end`.
_ctx(lines, i, prefix) if {
	not _last_key(prefix)
	i + 1 < count(lines)
	regex.match(`^\s*end\b`, lines[i + 1])
	regex.match(`^\s*def\s`, lines[max([0, i - 1])])
	_secure_name(_enclosing_fn(lines, i))
}

_fn_kw_re := `^\s*(?:export\s+)?(?:default\s+)?(?:(?:public|private|protected|static|async|final|override|internal|suspend)\s+)*(?:def|function|func|fn|fun|sub)\s+(?:\([^)]*\)\s*)?&?(?:self\.)?([A-Za-z_$][\w$]*)`

_fn_arrow_re := `^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)`

_fn_typed_re := `^\s*(?:(?:public|private|protected|static|final|synchronized|inline|extern|const|unsigned|virtual)\s+)*[A-Za-z_][\w<>\[\],.:*&]*\s+\**&?([A-Za-z_]\w*)\s*\([^;=]*$`

_fn_method_re := `^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{\s*$`

_not_fn := {"if", "for", "while", "switch", "return", "catch", "new", "else", "elif", "sizeof", "do", "case", "throw", "await"}

_fn_name(line) := n if {
	m := regex.find_all_string_submatch_n(_fn_kw_re, line, 1)
	count(m) > 0
	n := m[0][1]
} else := n if {
	m := regex.find_all_string_submatch_n(_fn_arrow_re, line, 1)
	count(m) > 0
	n := m[0][1]
} else := n if {
	not regex.match(`^\s*(?:return|else|new|throw|await)\b`, line)
	m := regex.find_all_string_submatch_n(_fn_typed_re, line, 1)
	count(m) > 0
	n := m[0][1]
	not n in _not_fn
} else := n if {
	m := regex.find_all_string_submatch_n(_fn_method_re, line, 1)
	count(m) > 0
	n := m[0][1]
	not n in _not_fn
}

_enclosing_fn(lines, i) := _fn_name(lines[j]) if {
	js := [k | some k in numbers.range(max([0, i - 40]), i); _fn_name(lines[k])]
	count(js) > 0
	j := max(js)
}

# The sink line assigns a variable that reaches a security context within
# the next six lines: `ts = str(time.time())` then `token = md5(ts)`.
_flows(lines, i, prefix) if {
	v := _last_key(prefix)
	count(v) > 0
	not _secure_name(v)
	i + 1 < count(lines)
	pat := concat("", [`(^|[^\w$@])`, strings.replace_n({"$": `\$`}, v), `([^\w$@]|$)`])
	some j in numbers.range(i + 1, min([i + 6, count(lines) - 1]))
	not helpers.is_comment_line(lines[j])
	regex.match(pat, lines[j])
	count(lines[j]) <= 400
	some idx in indexof_n(lines[j], v)
	_word_at(lines[j], idx, v)
	_ctx(lines, j, substring(lines[j], 0, idx))
}

# v at idx is the whole identifier, not part of a longer name and not a
# quoted string of its own (the key in {"issued": issued}).
_word_at(line, idx, v) if {
	idx > 0
	before := substring(line, idx - 1, 1)
	after := substring(line, idx + count(v), 1)
	not regex.match(`[\w$@]`, before)
	not regex.match(`^[\w$@]`, after)
	not _quoted(before, after)
}

_quoted(b, a) if {
	b in {`"`, "'"}
	a == b
}

_in_security_context(lines, i, prefix) if _ctx(lines, i, prefix)

_in_security_context(lines, i, prefix) if _flows(lines, i, prefix)

# The line with string literals emptied (an f-string or a Ruby "#{...}" keeps
# its code) and any trailing comment removed.
_code(line) := c if {
	s := regex.replace(line, `(^|[^A-Za-z0-9_])"(?:[^"\\#]|\\.|#[^{])*"`, `${1}""`)
	s2 := regex.replace(s, `(^|[^A-Za-z0-9_])'(?:[^'\\#]|\\.|#[^{])*'`, `${1}''`)
	c := regex.replace(s2, `(?:\s//|\s#[^{\[!]|/\*).*$`, "")
}

# The 0-based indexes of the lines of content holding any of the literal
# tokens, found with indexof_n instead of a loop over every line.
_token_lines(content, tokens) := {count(indexof_n(substring(content, 0, idx), "\n")) |
	some t in tokens
	some idx in indexof_n(content, t)
}

# ── Weak PRNG draws ───────────────────────────────────────────────────────

_lang(path) := "node" if regex.match(`\.(?:jsx?|tsx?|mjs|cjs)$`, path)

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "ruby" if endswith(path, ".rb")

_lang(path) := "go" if endswith(path, ".go")

_gate("node", content) if contains(content, "Math.random")

_gate("php", content) if regex.match(`(?:mt_rand|rand|lcg_value|str_shuffle|array_rand)\s*\(`, content)

_gate("ruby", content) if regex.match(`\brand\b|\.sample\b|\.shuffle\b|Random\.`, content)

_gate("go", content) if contains(content, `"math/rand`)

_go_alias(content) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`(?m)^\s*(?:import\s+)?([A-Za-z]\w*)\s+"math/rand(?:/v2)?"`, content, 1)
	count(m) > 0
} else := "rand"

_sink_re("node", _) := `Math\.random\s*\(\s*\)`

_sink_re("php", _) := `(?:^|[^\w$>:])(?:mt_rand|rand|lcg_value|str_shuffle|array_rand)\s*\(`

_sink_re("ruby", _) := `(?:^|[^\w.:@$])rand\b|(?:^|[^\w:])Random\.rand\b|Random\.new(?:\([^)]*\))?\.(?:rand|bytes)\b|\.(?:sample|shuffle)\b`

_sink_re("go", content) := concat("", [`(?:^|[^\w.])`, _go_alias(content), `\.(?:Int|Intn|IntN|Int31|Int31n|Int32|Int32N|Int63|Int63n|Int64|Int64N|Uint32|Uint64|Float32|Float64|Read|Perm|N)\(`])

# A cryptographic source on the same line, or a timing/retry use.
_safe_re := `(?i)randomBytes\(|randomUUID\(|getRandomValues\(|random_bytes\(|random_int\(|SecureRandom|crypto/rand|sleep|delay|jitter|backoff|setTimeout|retry`

_message := "A value from a non-cryptographic PRNG (Math.random, mt_rand/rand/str_shuffle, Ruby rand/sample, math/rand) is used as a secret; its output can be predicted from a few observed values. Use crypto.randomBytes/randomUUID, random_bytes/random_int, SecureRandom or crypto/rand"

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	not helpers._should_skip(path)
	not helpers.is_test_path(path)
	re := _sink_re(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(re, line)
	not helpers.is_comment_line(line)
	not regex.match(_safe_re, line)
	ms := regex.find_all_string_submatch_n(re, _code(line), 1)
	count(ms) > 0
	idx := indexof(line, ms[0][0])
	idx >= 0
	_in_security_context(lines, i, substring(line, 0, idx))
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
