# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_337

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-337",
	"name": "Predictable Seed in Pseudo-Random Number Generator (PRNG)",
	"description": "A PRNG is seeded from the clock, the process id or another observable value, so an attacker who knows roughly when the process started (or reads its PID) can enumerate the few candidate seeds and reproduce every value. Reported: a seed built from time(NULL), time.time(), time.Now(), datetime.now(), System.currentTimeMillis()/nanoTime(), Instant.now(), Date.now()/new Date(), microtime(), hrtime(), Time.now, clock(), gettimeofday/tv_sec/tv_usec, getpid()/os.getpid()/os.Getpid()/getmypid()/Process.pid/process.pid, performance.now() and similar (inline, or through a variable assigned one of those within eight lines above) passed to Python random.seed()/random.Random(); Java/Kotlin new Random(), new SecureRandom(bytes) and setSeed(); Go rand.Seed/NewSource/NewPCG/NewChaCha8; C/C++ srand/srandom/srand48/seed48, std::mt19937/default_random_engine constructors and engine.seed(); PHP mt_srand/srand and Random\\Engine constructors; Ruby srand, Random.new and Random.srand; JavaScript seedrandom(). A time-seeded SecureRandom or ChaCha8 is always reported. A general-purpose PRNG is reported only when its output is security-relevant: the seed call sits in a function named for a secret, the generator is stored under a secret's name, or the same file draws from a PRNG into a token, password, key, salt, nonce, OTP, CSRF or session value. Not reported: clock seeds for jitter, sampling, games and load spreading with no secret in the file, OS-seeded generators, test files, and calls in comments or string literals. Constant seeds are VNX-336 and seeds narrowed to a small range are VNX-339.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-337/",
	"languages": ["python", "java", "kotlin", "go", "c", "cpp", "php", "ruby", "node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [337],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["prng", "seed", "cwe-337"],
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

# An indexed store: token[i] = letters[rand.Intn(n)]
_ctx(_, _, prefix) if {
	ms := regex.find_all_string_submatch_n(`([A-Za-z_$@][\w$@]*)\s*\[[^\]\[]*\]\s*(?::=|\+=|=)(?:[^=:>]|$)`, prefix, -1)
	count(ms) > 0
	_secure_name(ms[count(ms) - 1][1])
}

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

# ── PRNG seeding calls ────────────────────────────────────────────────────

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "java" if regex.match(`\.(?:java|kt|kts)$`, path)

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "c" if regex.match(`\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$`, path)

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "ruby" if endswith(path, ".rb")

_lang(path) := "node" if regex.match(`\.(?:jsx?|tsx?|mjs|cjs)$`, path)

_seed_gate := `random\.seed|Random\s*\(|Random\.new|Random\.srand|setSeed|\.Seed\s*\(|NewSource|NewPCG|NewChaCha8|srand|seed48|mt19937|default_random_engine|minstd_rand|ranlux|knuth_b|\.seed\s*\(|Mt19937|Xoshiro256|PcgOneseq|seedrandom`

# Literal tokens: a file holding none of its language's tokens is skipped,
# and only the lines holding one are examined.
_tokens("python") := {"seed(", "Random("}

_tokens("java") := {"Random(", "setSeed("}

_tokens("go") := {"Seed(", "NewSource", "NewPCG(", "NewChaCha8("}

_tokens("c") := {"srand", "seed48(", ".seed(", "mt19937", "_engine", "minstd_rand"}

_tokens("php") := {"srand(", "Mt19937(", "Xoshiro256StarStar(", "PcgOneseq128XslRr64("}

_tokens("ruby") := {"srand", "Random.new(", "Random.srand"}

_tokens("node") := {"seedrandom"}

_gate(lang, content) if {
	some t in _tokens(lang)
	contains(content, t)
}

# The last capture group of each expression is the seed argument; a
# setSeed() expression also captures its receiver.
_seed_res("python") := [
	`(?:^|[^.\w])random\.seed\s*\((.*)\)`,
	`(?:^|[^.\w])(?:random\.)?Random\s*\((.+)\)`,
]

_seed_res("java") := [
	`(?:^|[^\w.])(?:new\s+)?(?:java\.util\.|kotlin\.random\.)?Random\s*\((.+)\)`,
	`(?:^|[^\w.])new\s+(?:java\.security\.)?SecureRandom\s*\((.+)\)`,
	`([A-Za-z_]\w*)\.setSeed\s*\((.+)\)`,
]

_seed_res("go") := [
	`\.Seed\s*\((.+)\)`,
	`\.NewSource(?:64)?\s*\((.+)\)`,
	`\.NewPCG\s*\((.+)\)`,
	`\.NewChaCha8\s*\((.+)\)`,
]

_seed_res("c") := [
	`(?:^|[^\w.>])(?:srand|srandom|srand48|seed48)\s*\((.*)\)`,
	`(?:mt19937(?:_64)?|default_random_engine|minstd_rand0?|ranlux\d+|knuth_b)\s+\w+\s*[({](.+)[)}]`,
	`\.seed\s*\((.+)\)`,
]

_seed_res("php") := [
	`(?:^|[^\w>:$])(?:mt_srand|srand)\s*\((.*)\)`,
	`(?:Mt19937|PcgOneseq128XslRr64|Xoshiro256StarStar)\s*\((.+)\)`,
]

_seed_res("ruby") := [
	`(?:^|[^\w.])srand\s*\((.*)\)`,
	`(?:^|[^\w.])srand\s+([^\s(].*)$`,
	`Random\.new\s*\((.+)\)`,
	`Random\.srand\s*\((.+)\)`,
]

_seed_res("node") := [
	`(?:^|[^\w])seedrandom\s*\((.+)\)`,
	`seedrandom\.\w+\s*\((.+)\)`,
]

# Draws from a general-purpose PRNG, used to decide whether the seeded
# generator feeds a secret somewhere in the file.
_draw_re("python") := `\.(?:randint|randrange|random|choice|choices|getrandbits|sample|randbytes)\(`

_draw_re("java") := `\.(?:nextInt|nextLong|nextBytes|nextDouble|nextFloat|nextBoolean|nextGaussian|ints|longs)\(`

_draw_re("go") := `\.(?:Int|Intn|IntN|Int31|Int31n|Int63|Int63n|Uint32|Uint64|Float64|Read|Perm|N)\(`

_draw_re("c") := `(?:^|[^\w.>])(?:rand|random|lrand48|mrand48|drand48|rand_r)\s*\(|\b(?:dist|distrib|distribution|gen|rng|engine|eng|mt|generator)\w*\s*\(\s*\w*\s*\)`

_draw_re("php") := `(?:^|[^\w$>:])(?:mt_rand|rand|array_rand|str_shuffle|shuffle)\s*\(|->(?:getInt|nextInt|getBytes|shuffleArray|shuffleBytes|pickArrayKeys)\(`

_draw_re("ruby") := `(?:^|[^\w.:@$])rand\b|\.rand\b|\.sample\b|\.shuffle\b|\.bytes\(`

_draw_re("node") := `Math\.random\(\)|\b(?:rng|prng|random|rand|seeded\w*|\w+Rng|\w+Random)\s*(?:\.\w+)?\(\s*\)`

_draw_safe_re := `(?i)secure|secrets\.|SystemRandom|crypto|urandom|random_bytes|random_int`

_file_draws_secret(lines, lang) if {
	re := _draw_re(lang)
	some j, l in lines
	regex.match(re, l)
	not helpers.is_comment_line(l)
	not regex.match(_draw_safe_re, l)
	ms := regex.find_all_string_submatch_n(re, _code(l), 1)
	count(ms) > 0
	idx := indexof(l, ms[0][0])
	idx >= 0
	_in_security_context(lines, j, substring(l, 0, idx))
}

# A seeded cryptographic generator: SHA1PRNG and DRBG instances seeded
# before first use are deterministic, and ChaCha8 is fully determined by
# its seed.
_csprng(line, _, _) if contains(line, "SecureRandom")

_csprng(line, _, _) if contains(line, "NewChaCha8")

_csprng(_, mm, content) if {
	count(mm) == 3
	recv := mm[1]
	regex.match(concat("", [`SecureRandom\s+`, recv, `\b|\b`, recv, `\s*=\s*(?:new\s+(?:java\.security\.)?SecureRandom|SecureRandom\.getInstance)`]), content)
}

# The seed argument, or the variable it names, assigned a few lines above.
_bad_seed(_, _, arg) if _bad_arg(arg)

_bad_seed(lines, i, arg) if {
	v := _seed_var(arg)
	i > 0
	some j in numbers.range(max([0, i - 8]), i - 1)
	contains(lines[j], v)
	a := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.$])`, strings.replace_n({"$": `\$`}, v), `\s*(?::=|=)\s*(.+?)\s*;?\s*$`]), lines[j], 1)
	count(a) > 0
	_bad_arg(a[0][1])
}

# The variable a seed argument names, bare or wrapped in a conversion call:
# seed, String(seed), int(seed), Number(seed).
_seed_var(arg) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*(\$?[A-Za-z_]\w*)[\s)]*$`, arg, 1)
	count(m) > 0
} else := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*(?:[A-Za-z_][\w.]*)\(\s*(\$?[A-Za-z_]\w*)\s*\)\s*$`, arg, 1)
	count(m) > 0
}

# Every seeding call whose argument this rule's _bad_arg classifies.
_hits contains h if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	regex.match(_time_file_re, content)
	not helpers._should_skip(path)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i in _token_lines(content, _tokens(lang))
	line := lines[i]
	regex.match(_seed_gate, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	some re in _seed_res(lang)
	mm := regex.find_all_string_submatch_n(re, code, 1)[0]
	_bad_seed(lines, i, _arg(mm[count(mm) - 1]))
	h := {"path": path, "lang": lang, "i": i, "line": line, "code": code, "mm": mm}
}

_hit_files := {[h.path, h.lang] | some h in _hits}

# Files with a seeding hit that also draw a PRNG value into a secret
# (evaluated once per file).
_draw_files contains path if {
	some [path, lang] in _hit_files
	_file_draws_secret(split(input.file_contents[path], "\n"), lang)
}

_reportable(h, _) if _csprng(h.line, h.mm, input.file_contents[h.path])

_reportable(h, lines) if _secure_name(_enclosing_fn(lines, h.i))

_reportable(h, lines) if {
	idx := indexof(h.code, h.mm[0])
	idx >= 0
	_ctx(lines, h.i, substring(h.code, 0, idx))
}

_reportable(h, _) if h.path in _draw_files

_message(h) := _msg_csprng if _csprng(h.line, h.mm, input.file_contents[h.path])

else := _msg_prng

findings contains finding if {
	some h in _hits
	lines := split(input.file_contents[h.path], "\n")
	_reportable(h, lines)
	finding := {
		"rule_id": metadata.id,
		"message": _message(h),
		"artifact_uri": h.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": h.i + 1,
		"snippet": h.line,
	}
}

# The seed argument proper: the capture runs to the last `)` on the line,
# so cut it at the first unbalanced closing parenthesis
# (`new Random().nextInt(xs.length)` has no argument at all).
_arg(raw) := regex.find_n(`^(?:[^(){}]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|\{[^{}]*\})*`, raw, 1)[0]

# ── Clock and process-id seeds ────────────────────────────────────────────

_time_re := `(?:^|[^\w.])time\s*\(\s*(?:NULL|nullptr|0)?\s*\)|time\.time(?:_ns)?\(\)|time\.Now\(\)|datetime\.(?:datetime\.)?(?:now|utcnow|today)\(|System\.(?:currentTimeMillis|nanoTime)\(\)|Instant\.now\(\)|new\s+Date\(\)|Date\.now\(\)|\bmicrotime\(|\bhrtime\(|Time\.now|Process\.pid|(?:^|[^\w.])getpid\s*\(|os\.getpid\(\)|os\.Getpid\(\)|getmypid\(\)|(?:^|[^\w.])clock\s*\(\s*\)|gettimeofday|\btv_(?:sec|usec|nsec)\b|ProcessHandle\.current\(\)|currentThread\(\)\.getId\(\)|performance\.now\(\)|process\.pid|process\.hrtime|perf_counter|monotonic\(|process_time\(|GetTickCount|QueryPerformanceCounter|mach_absolute_time|clock_gettime|\bnow\(\)`

_bad_arg(a) if regex.match(_time_re, a)

# A file naming none of the clock or process-id sources cannot hold a seed
# from one (checked once per file, before it is split into lines).
_time_file_re := `time|Time|now\(|pid|Pid|clock|tv_|Tick|PerformanceCounter|mach_absolute|getId\(`

_msg_csprng := "A cryptographic generator (SecureRandom, ChaCha8) is seeded from the clock or process id, so its output can be reproduced by trying the few likely seeds. Do not seed it; let it seed itself from the operating system"

_msg_prng := "A PRNG whose output feeds a secret is seeded from the clock or process id; an attacker can enumerate the likely seeds and reproduce its values. Use a CSPRNG (secrets, SecureRandom, crypto/rand, random_bytes, crypto.randomBytes) for security values"
