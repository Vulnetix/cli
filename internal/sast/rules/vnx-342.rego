# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_342

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-342",
	"name": "Predictable Exact Value from Previous Values",
	"description": "A secret is the next value of a counter, so anyone who has seen one value (their own session id, reset code or token) knows the next one exactly. Reported: an increment (++x, x++, x += 1, x + 1, incrementAndGet/getAndIncrement/addAndGet, Go atomic.AddInt64/Uint64 and .Add(1), Python next(counter), Ruby .succ/.next) of a variable named as a counter or previous value (count, ctr, seq, last, prev, next, serial, latest, max, id, num) or for a secret, whose target is itself named for a secret (sessionId++, $_SESSION['last_session_id']++), or whose result is stored under, returned as, or set as the cookie value of a secret (token, password, session id, reset/confirmation/invite code, OTP, CSRF, API key), on the same line, through a standalone increment of a variable used as a secret within four lines, or through a variable that reaches one within six lines. Languages: Java, Kotlin, Python, JavaScript/TypeScript, PHP, Ruby, Go. Not reported: anonymous loop variables (i++, n += 1), counters used as nonces, IVs, JWT ids or sequence numbers (uniqueness is all they need), HOTP/HMAC over a counter, lines that also draw from a CSPRNG, counts, indexes, attempts and other bookkeeping names, loop headers, test files, and the pattern in comments or string literals. A secret mixing a counter with the clock is also VNX-341.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-342/",
	"languages": ["java", "kotlin", "python", "node", "php", "ruby", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [342],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["randomness", "predictable", "cwe-342"],
}

_rule_single_words := set()

# A counter is the right tool for a nonce, an IV, a JWT id or a sequence
# number; and a name about a lexer's or a pager's token is not a secret.
_rule_negative_words := {
	"nonce", "iv", "jti", "nbf", "seq", "sequence", "serial", "counter", "ctr",
	"request", "req", "msg", "message", "page", "cursor", "line", "row", "col",
	"char", "lexer", "parser", "scanner", "stream", "buffer", "ptr", "depth",
	"level", "indent", "generation", "epoch", "notifier", "listener", "callback",
}

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


# ── Counter increments ────────────────────────────────────────────────────

_lang(path) := "java" if regex.match(`\.(?:java|kt|kts)$`, path)

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "node" if regex.match(`\.(?:jsx?|tsx?|mjs|cjs)$`, path)

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "ruby" if endswith(path, ".rb")

_lang(path) := "go" if endswith(path, ".go")

# A file names a secret, or it cannot match. Literal checks, not a
# case-insensitive regex: that runs the slow matcher over every byte.
# The words are checked most-common first, so a file that names a token
# stops at the first test.
_secret_words := [
	"oken", "ession", "assw", "ecret", "srf", "SESSION", "TOKEN", "SECRET", "PASSW",
	"SRF", "ESSID", "otp", "Otp", "OTP", "eset", "piKey", "pi_key", "PI_KEY", "nvite",
	"onfirm", "erific", "ctivation", "agic", "aptcha", "inCode", "in_code",
]

_secret_file(content) if {
	some w in _secret_words
	contains(content, w)
}


# An increment of something named like a counter, a previous value or a
# secret (lastToken++, ++counter, $_SESSION['next_session_id']++,
# ids.getAndIncrement(), atomic.AddInt64(&sessionCounter, 1), next(_ids)).
# A bare `i++` or `n += 1` is never examined: an anonymous loop variable is
# where most increments are, and the counters that become secrets are named.
_frag := `(?i:count|ctr|seq|last|prev|next|serial|cur|latest|max|id|num|token|sess|sid|passw|secret|otp|csrf|xsrf|reset|cookie|key|code|pin|invit|confirm|verif|activation|magic)`

_incr_file_re := concat("", [
	_frag, `[\w$@'"\]]*\s*(?:\+\+|\+=?\s*1\b|\.\s*(?:incrementAndGet|getAndIncrement|addAndGet|getAndAdd|Add\s*\(|succ|next\b))`,
	`|\+\+\s*[\w$@.>-]*`, _frag,
	`|atomic\.Add\w+\(\s*&\s*[\w.]*`, _frag,
	`|next\s*\(\s*[\w.]*`, _frag,
])

# The same test over a whole file, cheaply. An expression that starts with a
# literal lets the matcher jump between occurrences of it instead of running
# at every byte, so `name++`, `name += 1` and `name + 1` are looked for in
# the reversed file, where the operator comes first.
_rev_frag := `(?i:tnuoc|rtc|qes|tsal|verp|txen|laires|ruc|tsetal|xam|di|mun|nekot|sses|dis|wssap|terces|pto|fsrc|fsrx|teser|eikooc|yek|edoc|nip|tivni|mrifnoc|firev|noitavitca|cigam|ahctpa)`

_named_incr_file(content) if regex.match(concat("", [`\+\+\s*[\w$@.>-]*?`, _frag]), content)

_named_incr_file(content) if {
	rev := strings.reverse(content)
	regex.match(concat("", [`\+\+\s*[\]'"]*[\w$@]*?`, _rev_frag]), rev)
}

_named_incr_file(content) if {
	rev := strings.reverse(content)
	regex.match(concat("", [`1\s*=?\+\s*[\]'"]*[\w$@]*?`, _rev_frag]), rev)
}

# The incremented target: a name with member accesses and quoted or symbol
# subscripts ($_SESSION['last_session_id'], self._last, @@counter).
_t := `([$@]{0,2}[A-Za-z_]\w*(?:(?:\.|->|::|\?\.)\$?[A-Za-z_]\w*|\[\s*["':]?[\w-]*["']?\s*\])*)`

_sink_res := {
	"pre": concat("", [`\+\+\s*`, _t]),
	"post": concat("", [_t, `\s*\+\+`]),
	"pluseq": concat("", [_t, `\s*\+=\s*1\b`]),
	"plusone": concat("", [_t, `\s*\+\s*1(?:[^.\w]|$)`]),
	"method": concat("", [_t, `\s*\.\s*(?:incrementAndGet|getAndIncrement|addAndGet|getAndAdd|Add)\s*\(\s*1?L?\s*\)`]),
	"goatomic": concat("", [`atomic\.Add(?:Int|Uint)(?:32|64)\s*\(\s*&\s*`, _t, `\s*,\s*1\s*\)`]),
	"pynext": concat("", [`(?:^|[^\w.])next\s*\(\s*`, _t, `\s*\)`]),
	"rbsucc": concat("", [_t, `\.(?:succ|next)(?:[^\w(!?]|$)`]),
}

_kind_lang("pynext", lang) if lang == "python"

_kind_lang("rbsucc", lang) if lang == "ruby"

_kind_lang("goatomic", lang) if lang == "go"

_kind_lang(k, _) if k in {"pre", "post", "pluseq", "plusone", "method"}

# Forms that are not an increment by syntax alone: name + 1, next(x),
# x.succ. Their target must be named for a counter or a previous value.
_weak := {"plusone", "pynext", "rbsucc"}

_counter_words := {
	"counter", "ctr", "count", "seq", "sequence", "last", "prev", "previous",
	"next", "serial", "current", "cur", "latest", "max", "id", "ids", "num",
}

_counterish(name) if {
	some w in _words(name)
	w in _counter_words
}

# The name a target stands for: its last quoted key, else its last segment.
_target_name(t) := n if {
	ks := regex.find_all_string_submatch_n(`\[\s*["':]([\w-]+)`, t, -1)
	count(ks) > 0
	n := ks[count(ks) - 1][1]
} else := n if {
	segs := regex.find_all_string_submatch_n(`[A-Za-z_]\w*`, t, -1)
	n := segs[count(segs) - 1][0]
}

_strong_enough(kind, _) if not kind in _weak

_strong_enough(kind, name) if {
	kind in _weak
	_counterish(name)
}

_safe_re := `random_bytes|random_int|openssl_random|secrets\.|urandom|randomBytes|randomUUID|getRandomValues|SecureRandom|crypto/rand|rand\.Read|uuid4|uuid\.New|token_hex|token_urlsafe|(?i:hmac|hotp)`

_loop_re := `^\s*(?:\}\s*)?(?:for|while|foreach)\b|\bfor\s*\(`

_sinks(lang, line, code) := {[kind, m[0], m[1]] |
	some kind, re in _sink_res
	_kind_lang(kind, lang)
	count(regex.find_n(re, code, 1)) > 0
	some m in regex.find_all_string_submatch_n(re, line, -1)
}

# A: the incremented value is itself named for a secret.
_reportable(_, _, kind, _, target, _) if {
	not kind in {"pynext"}
	_secure_name(_target_name(target))
}

# B: its result is stored, returned or set as a secret on the same line.
_reportable(lines, i, kind, text, target, line) if {
	_strong_enough(kind, _target_name(target))
	idx := indexof(line, text)
	idx >= 0
	_ctx(lines, i, substring(line, 0, idx))
}

# C: a standalone increment, and the variable is used as a secret within
# four lines: `$_SESSION['n']++;` then `setcookie("sid", $_SESSION['n'])`.
_reportable(lines, i, kind, text, target, line) if {
	_strong_enough(kind, _target_name(target))
	regex.match(`^\s*[;{]?\s*$`, replace(replace(line, text, ""), ";", ""))
	i + 1 < count(lines)
	some j in numbers.range(i + 1, min([i + 4, count(lines) - 1]))
	not helpers.is_comment_line(lines[j])
	idx := indexof(lines[j], target)
	idx >= 0
	not regex.match(`^[\w$]`, substring(lines[j], idx + count(target), 1))
	_ctx(lines, j, substring(lines[j], 0, idx))
}

# D: assigned to a variable that reaches a secret within six lines.
_reportable(lines, i, kind, text, target, line) if {
	_strong_enough(kind, _target_name(target))
	idx := indexof(line, text)
	idx >= 0
	_flows(lines, i, substring(line, 0, idx))
}

_message := "A secret is the next value of a counter, so anyone who has seen one value (their own session id, reset code or token) can compute the next. Generate secrets with a CSPRNG: secrets.token_urlsafe, crypto.randomBytes, random_bytes, SecureRandom, crypto/rand, SecureRandom.hex"

# One pass per file. Lines with a `+` are tested inline, because a function
# call per line costs more than the rest of the rule; the other increment
# forms are rare words, found without reading every line.
_hits contains [path, i] if {
	some path, content in input.file_contents
	lang := _lang(path)
	_secret_file(content)
	not helpers._should_skip(path)
	not helpers.is_test_path(path)
	rare := {k | some t in _rare_tokens(lang); contains(content, t); some k in _token_lines(content, {t})}
	named := {1 | _named_incr_file(content)}
	count(rare) + count(named) > 0
	lines := split(content, "\n")
	adds := {j |
		count(named) > 0
		some j, l in lines
		contains(l, "+")
		regex.match(`\+\+|\+=?\s*1\b`, l)
	}
	some i in rare | adds
	_line_hit(lang, lines, i, lines[i])
}

_rare_tokens("go") := {"AndIncrement", "AndAdd", "atomic.Add", ".Add(1)"}

_rare_tokens("python") := {"next(_", "next(self", "next(counter", "next(id", "next(seq", "next(count"}

_rare_tokens("ruby") := {".succ", ".next"}

_rare_tokens(lang) := {"AndIncrement", "incrementAndGet", "AndAdd", "addAndGet"} if lang in {"java", "node", "php"}

_line_hit(lang, lines, i, line) if {
	not regex.match(_loop_re, line)
	regex.match(_incr_file_re, line)
	not helpers.is_comment_line(line)
	not regex.match(_safe_re, line)
	code := _code(line)
	some s in _sinks(lang, line, code)
	_reportable(lines, i, s[0], s[1], s[2], line)
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
