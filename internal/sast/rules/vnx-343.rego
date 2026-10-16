# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_343

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-343",
	"name": "Predictable Value Range from Previous Values",
	"description": "A secret is the previous value plus a small random step, so anyone who has seen one value knows the next lies in a narrow window just above it (the classic weak TCP initial-sequence-number and incrementing-token design). Reported: `x += <random draw>` where x is named for a secret or an initial sequence number (token, session id, reset code, OTP, CSRF, password, API key, isn), and `<previous> + <random draw>` where the previous value is named last/prev/previous/current/old/next or for a secret and the sum is stored under, returned as, or flows within six lines into a secret. A random draw is random.randint/randrange/getrandbits/uniform, secrets.randbelow, Math.random() (also inside Math.floor), rand()/mt_rand()/random_int(), nextInt/nextLong (Random, ThreadLocalRandom, kotlin.random.Random), Go rand.Intn/IntN/Int63n/Int31n (also inside a numeric conversion), Ruby rand/random_number and C rand()/random()/arc4random_uniform. Languages: Python, Java, Kotlin, JavaScript/TypeScript, PHP, Ruby, Go, C/C++. Not reported: jitter, delays, poll intervals and other non-secret values, counts and bookkeeping names, a draw written before the previous value (`rand() + last`), an increment by a constant (VNX-342), test files, and the pattern in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-343/",
	"languages": ["python", "java", "kotlin", "node", "php", "ruby", "go", "c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [343],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["randomness", "predictable", "predictable-value-range", "cwe-343"],
}

# An initial sequence number is a secret against connection spoofing.
_rule_single_words := {"isn"}

_rule_negative_words := {"poll", "wait", "position", "score", "total", "sum", "offset"}

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
	not v in _not_value_names
	not _secure_name(v)
	i + 1 < count(lines)
	vq := strings.replace_n({"$": `\$`}, v)
	pat := concat("", [`(^|[^\w$@])`, vq, `([^\w$@]|$)`])
	some j in numbers.range(i + 1, min([i + 6, count(lines) - 1]))
	not helpers.is_comment_line(lines[j])
	regex.match(pat, lines[j])
	# A lifetime added to the timestamp makes it an expiry: $now + TOKEN_LIFE.
	not regex.match(concat("", [`(^|[^\w$@])`, vq, `\s*[+-]\s*(?:\d|[\w:$>.]*(?i:life|ttl|expir|timeout|duration|seconds|minutes|hours|days))`]), lines[j])
	count(lines[j]) <= 400
	some idx in indexof_n(lines[j], v)
	_word_at(lines[j], idx, v)
	_ctx(lines, j, substring(lines[j], 0, idx))
}

# Error and status results (`err = signer.SignHTTP(..., time.Now())` and then
# `return "", err`) carry no value derived from the clock.
_not_value_names := {"err", "error", "errs", "ok", "ex", "exc", "e", "status", "res", "resp", "response", "result"}

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


# ── Previous value plus a random step ─────────────────────────────────────

_lang(path) if regex.match(`\.(?:py|java|kt|kts|jsx?|tsx?|mjs|cjs|php|rb|go|c|cc|cpp|cxx|h|hh|hpp|hxx)$`, path)

# The target: a name with member accesses and quoted or symbol subscripts.
_t := `([$@]{0,2}[A-Za-z_]\w*(?:(?:\.|->|::|\?\.)\$?[A-Za-z_]\w*|\[\s*["':]?[\w-]*["']?\s*\])*)`

# A random draw directly after the `+`, optionally parenthesised or wrapped
# in one conversion or rounding call: (rand() % 64), Math.floor(Math.random()
# * 100), uint64(rand.Intn(1000)), ThreadLocalRandom.current().nextInt(9).
_draw := `(?:\(\s*(?:unsigned\s+|const\s+|struct\s+)?[A-Za-z_]\w*\s*\**\s*\)\s*)?\(?\s*(?:[\w.]+\s*\(\s*)?(?:[\w$]+(?:\(\))?(?:\.|->|::))*(?:rand|random|randint|randrange|randbelow|getrandbits|uniform|mt_rand|random_int|random_number|nextInt|nextLong|getInt|Intn|IntN|Int63n|Int31n|Uint32N|arc4random_uniform|arc4random|rand_r|lrand48)\s*\(`

_aug_re := concat("", [_t, `\s*\+=\s*`, _draw])

_plus_re := concat("", [_t, `\s*\+\s*`, _draw])

_file_re := concat("", [`\+=?\s*`, _draw])

_secret_file_re := `(?i)token|sess|passw|secret|otp|csrf|xsrf|reset|cookie|api_?key|confirm|activation|verif|invit|magic|\bpin|\bsid\b|isn`

_prev_words := {"last", "prev", "previous", "current", "cur", "old", "next", "latest"}

_previous(name) if {
	some w in _words(name)
	w in _prev_words
}

_previous(name) if _secure_name(name)

# The name a target stands for: its last quoted key, else its last segment.
_target_name(t) := n if {
	ks := regex.find_all_string_submatch_n(`\[\s*["':]([\w-]+)`, t, -1)
	count(ks) > 0
	n := ks[count(ks) - 1][1]
} else := n if {
	segs := regex.find_all_string_submatch_n(`[A-Za-z_]\w*`, t, -1)
	n := segs[count(segs) - 1][0]
}

# `token += rand(...)`: the secret itself moves by a random step.
_report(_, _, line, code) if {
	count(regex.find_n(_aug_re, code, 1)) > 0
	some m in regex.find_all_string_submatch_n(_aug_re, line, -1)
	_secure_name(_target_name(m[1]))
}

# `token = last + rand(...)`, returned or flowing into a secret.
_report(lines, i, line, code) if {
	count(regex.find_n(_plus_re, code, 1)) > 0
	some m in regex.find_all_string_submatch_n(_plus_re, line, -1)
	_previous(_target_name(m[1]))
	idx := indexof(line, m[0])
	idx >= 0
	prefix := substring(line, 0, idx)
	_in_security_context(lines, i, prefix)
}

_message := "A secret is its previous value plus a small random step, so an attacker who has seen one value can guess the next from a narrow range. Generate each secret independently with a CSPRNG: secrets.token_urlsafe, crypto.randomBytes, random_bytes, SecureRandom, crypto/rand"

_hits contains [path, i] if {
	some path, content in input.file_contents
	_lang(path)
	regex.match(_file_re, content)
	regex.match(_secret_file_re, content)
	not helpers._should_skip(path)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_file_re, line)
	not helpers.is_comment_line(line)
	_report(lines, i, line, _code(line))
}

findings contains finding if {
	some [path, i] in _hits
	line := split(input.file_contents[path], "\n")[i]
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
