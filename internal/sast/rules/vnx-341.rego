# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_341

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-341",
	"name": "Predictable from Observable State",
	"description": "A secret is built from state an attacker can observe or estimate: the clock (time(), time(NULL), microtime(), date(), time.time(), datetime.now(), Date.now(), new Date(), getTime(), System.currentTimeMillis()/nanoTime(), Instant.now(), time.Now(), Time.now, clock(), tv_sec/tv_usec, hrtime, performance.now()), the process id (getpid(), os.getpid(), os.Getpid(), getmypid(), Process.pid, process.pid, ProcessHandle pid), or the client address or host name (REMOTE_ADDR, getRemoteAddr(), request.remote_addr, req.ip, remote_ip, RemoteAddr, gethostname(), uuid.getnode()). Reported when such a value, raw or hashed, is stored under, keyed by or returned as a security name (token, password, secret, nonce, salt, OTP, CSRF, session id, session cookie value, API/secret key, reset/confirmation code), set as the value of a session or auth cookie, written with snprintf/strcpy into a buffer named for a secret, or assigned to a variable that reaches one of those within six lines. Not reported: timestamps stored as bookkeeping (iat, exp, expires, created, last_activity, login_time, token_expiry, ttl), cookie expiry arguments, a timestamp variable later used only with a lifetime added ($now + TOKEN_LIFE), error and status results of a call that takes the clock (err = signer.Sign(..., time.Now())), comparisons, a line that also draws from a CSPRNG (random_bytes, secrets, os.urandom, crypto.randomBytes, SecureRandom, crypto/rand, RAND_bytes, getrandom, uuid4), PRNG seeding (VNX-337), test files, and the pattern in comments or string literals. Identifier generators such as uniqid() and time-based UUIDs are VNX-340.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-341/",
	"languages": ["c", "cpp", "python", "node", "php", "java", "kotlin", "go", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [341],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["randomness", "predictable", "cwe-341"],
}

_rule_single_words := set()

_rule_negative_words := {"seed", "started", "now", "stamp", "last", "activity", "seen", "login", "modified", "mtime"}

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
	"encrypted", "salted", "input", "debug", "usable", "expired", "stale", "fresh",
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

# Returned from a function whose name says it makes a secret. A return built
# from comparisons is a yes/no answer about the secret (an expiry check:
# `return t.Token != "" && time.Now().Before(t.ExpiresAt)`), not the secret.
_ctx(lines, i, prefix) if {
	regex.match(`^\s*return\b`, prefix)
	not regex.match(`==|!=|&&|\|\||<=|>=|\s[<>]\s|\bnot\b|\band\b|\bor\b`, prefix)
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

# Two hops: the clock value goes through a second variable (`sum := sha1.Sum(seed)`)
# which reaches the security context.
_flows(lines, i, prefix) if {
	v := _last_key(prefix)
	count(v) > 0
	not v in _not_value_names
	not _secure_name(v)
	vq := strings.replace_n({"$": `\$`}, v)
	pat := concat("", [`(^|[^\w$@])`, vq, `([^\w$@]|$)`])
	some j in numbers.range(i + 1, min([i + 6, count(lines) - 1]))
	not helpers.is_comment_line(lines[j])
	regex.match(pat, lines[j])
	not regex.match(concat("", [`(^|[^\w$@])`, vq, `\s*[+-]\s*(?:\d|[\w:$>.]*(?i:life|ttl|expir|timeout|duration|seconds|minutes|hours|days))`]), lines[j])
	count(lines[j]) <= 400
	some idx in indexof_n(lines[j], v)
	_word_at(lines[j], idx, v)
	w := _last_key(substring(lines[j], 0, idx))
	count(w) > 0
	w != v
	not w in _not_value_names
	not _secure_name(w)
	wq := strings.replace_n({"$": `\$`}, w)
	pat2 := concat("", [`(^|[^\w$@])`, wq, `([^\w$@]|$)`])
	some k in numbers.range(j + 1, min([j + 6, count(lines) - 1]))
	not helpers.is_comment_line(lines[k])
	regex.match(pat2, lines[k])
	count(lines[k]) <= 400
	some idx2 in indexof_n(lines[k], w)
	_word_at(lines[k], idx2, w)
	_ctx(lines, k, substring(lines[k], 0, idx2))
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

# ── Observable state ──────────────────────────────────────────────────────

_lang(path) := "c" if regex.match(`\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$`, path)

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "node" if regex.match(`\.(?:jsx?|tsx?|mjs|cjs)$`, path)

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "java" if regex.match(`\.(?:java|kt|kts)$`, path)

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "ruby" if endswith(path, ".rb")

_tokens("c") := {"time(", "getpid", "clock(", "tv_sec", "tv_usec", "tv_nsec", "gethostname"}

_tokens("python") := {"time.time", "datetime.", "getpid", "remote_addr", "gethostname", "getnode", "perf_counter", "monotonic"}

_tokens("node") := {"Date.now", "new Date", "getTime()", "hrtime", "performance.now", "process.pid", "req.ip", "remoteAddress", "hostname()"}

_tokens("php") := {"time(", "microtime", "getmypid", "REMOTE_ADDR", "hrtime", "date(", "gethostname"}

_tokens("java") := {"currentTimeMillis", "nanoTime", "Instant.now", "new Date()", "getTime()", "getRemoteAddr", "LocalDateTime.now", "ProcessHandle", "getLocalHost"}

_tokens("go") := {"time.Now()", "os.Getpid", "RemoteAddr", "os.Hostname"}

_tokens("ruby") := {"Time.now", "Time.current", "DateTime.now", "Process.pid", "remote_ip", "request.ip"}

_gate(lang, content) if {
	some t in _tokens(lang)
	contains(content, t)
}

_sink_re("c") := `(?:^|[^\w.>])time\s*\(\s*(?:NULL|nullptr|0)?\s*\)|(?:^|[^\w.>])getpid\s*\(\s*\)|(?:^|[^\w.>])clock\s*\(\s*\)|\btv_(?:sec|usec|nsec)\b|(?:^|[^\w.>])gethostname\s*\(`

_sink_re("python") := `\btime\.time(?:_ns)?\(\)|datetime\.(?:datetime\.)?(?:now|utcnow|today)\(|\bos\.getpid\(\)|\bremote_addr\b|\bgethostname\(\)|\buuid\.getnode\(\)|\bperf_counter(?:_ns)?\(\)|\bmonotonic(?:_ns)?\(\)`

_sink_re("node") := `\bDate\.now\(\)|\bnew\s+Date\(\)|\.getTime\(\)|\bprocess\.hrtime\b|\bperformance\.now\(\)|\bprocess\.pid\b|\breq\.ip\b|\.remoteAddress\b|\bos\.hostname\(\)`

_sink_re("php") := `(?:^|[^\w$>:])(?:time|microtime|hrtime|getmypid|gethostname)\s*\(|(?:^|[^\w$>:])date\s*\(\s*["']`

_sink_re("java") := `System\.(?:currentTimeMillis|nanoTime)\(\)|\bInstant\.now\(\)|\bnew\s+Date\(\)|\.getTime\(\)|\bLocalDateTime\.now\(\)|\.getRemoteAddr\(\)|ProcessHandle\.current\(\)\.pid\(\)|InetAddress\.getLocalHost\(\)`

_sink_re("go") := `\btime\.Now\(\)|\bos\.Getpid\(\)|\.RemoteAddr\b|\bos\.Hostname\(\)`

_sink_re("ruby") := `\bTime\.(?:now|current)\b|\bDateTime\.now\b|\bProcess\.pid\b|\bremote_ip\b|\brequest\.ip\b`

# The first observable value on the line, outside string literals. PHP's
# $_SERVER['REMOTE_ADDR'] is a string key, so it is looked for on the raw line.
_sink(lang, line) := ms[0][0] if {
	ms := regex.find_all_string_submatch_n(_sink_re(lang), _code(line), 1)
	count(ms) > 0
} else := ms[0][0] if {
	lang == "php"
	ms := regex.find_all_string_submatch_n(`\$_SERVER\s*\[\s*["']REMOTE_ADDR["']\s*\]`, line, 1)
	count(ms) > 0
}

_safe_re := `random_bytes\(|random_int\(|openssl_random_pseudo_bytes\(|secrets\.|urandom|randomBytes\(|randomUUID\(|getRandomValues\(|SecureRandom|crypto/rand|RAND_bytes|getrandom\(|arc4random|uuid4\(|uuid\.New\(\)|UUID\.randomUUID|srand|\.Seed\(|setSeed|random\.seed|NewSource|seedrandom`

_message := "A secret is derived from observable state (the clock, the process id, the client address or the host name), so an attacker can reproduce it by trying the few plausible values. Generate secrets with a CSPRNG: secrets.token_urlsafe, crypto.randomBytes, random_bytes, SecureRandom, crypto/rand, RAND_bytes"

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	not helpers._should_skip(path)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i in _token_lines(content, _tokens(lang))
	line := lines[i]
	not helpers.is_comment_line(line)
	not regex.match(_safe_re, line)
	s := _sink(lang, line)
	idx := indexof(line, s)
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
