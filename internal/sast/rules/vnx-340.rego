# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_340

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-340",
	"name": "Generation of Predictable Numbers or Identifiers",
	"description": "A secret is produced by an identifier generator whose output is predictable: a time-based UUID (version 1 or 6: Python uuid.uuid1(), JavaScript uuid v1/v6/uuidv1() (including v1/v3/v5/v6 destructured from the uuid package under any local name, such as import { v1 as makeId } from 'uuid'), PHP Ramsey Uuid::uuid1()/uuid6(), Go google/uuid NewUUID() and gofrs NewV1/NewV6, Java UuidCreator time-based and java-uuid-generator timeBasedGenerator(), Ruby UUIDTools timestamp_create), a name-based UUID that is a hash of its input (version 3 or 5: uuid3/uuid5, uuid v3/v5, Uuid::uuid3/uuid5, uuid.NewMD5/NewSHA1/NewV3/NewV5, Java UUID.nameUUIDFromBytes() and nameBasedGenerator(), Ruby Digest::UUID.uuid_v3/uuid_v5 and UUIDTools md5_create/sha1_create), or PHP uniqid(), which is the current time in hex. Reported when the identifier is stored under, keyed by or returned as a security name (token, password, secret, nonce, salt, OTP, CSRF, session id, API/secret key, reset/confirmation/invite code, a session cookie), directly or through a variable that reaches such a name within six lines. Not reported: random UUIDs (uuid4, crypto.randomUUID, UUID.randomUUID, uuid.New, SecureRandom.uuid, Uuid::uuid4), uniqid() or time-based UUIDs used as file names, request ids, cache keys and other identifiers that are not secrets, values combined on the same line with a CSPRNG (random_bytes, secrets, crypto.randomBytes), test files, and the call in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-340/",
	"languages": ["python", "node", "php", "go", "java", "kotlin", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [340],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["randomness", "predictable", "uuid", "cwe-340"],
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

# A setter named for a secret receiving the value: user.setConfirmationToken(raw).
_ctx(_, _, prefix) if {
	ms := regex.find_all_string_submatch_n(`\bset([A-Z]\w*)\s*\(\s*$`, prefix, 1)
	count(ms) > 0
	_secure_name(ms[0][1])
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

# Two hops: the variable is copied into a second one (`raw = id.toString()`)
# which reaches the security context.
_flows(lines, i, prefix) if {
	v := _last_key(prefix)
	count(v) > 0
	not _secure_name(v)
	pat := concat("", [`(^|[^\w$@])`, strings.replace_n({"$": `\$`}, v), `([^\w$@]|$)`])
	some j in numbers.range(i + 1, min([i + 6, count(lines) - 1]))
	not helpers.is_comment_line(lines[j])
	regex.match(pat, lines[j])
	count(lines[j]) <= 400
	some idx in indexof_n(lines[j], v)
	_word_at(lines[j], idx, v)
	w := _last_key(substring(lines[j], 0, idx))
	count(w) > 0
	w != v
	not _secure_name(w)
	pat2 := concat("", [`(^|[^\w$@])`, strings.replace_n({"$": `\$`}, w), `([^\w$@]|$)`])
	some k in numbers.range(j + 1, min([j + 6, count(lines) - 1]))
	not helpers.is_comment_line(lines[k])
	regex.match(pat2, lines[k])
	count(lines[k]) <= 400
	some idx2 in indexof_n(lines[k], w)
	_word_at(lines[k], idx2, w)
	_ctx(lines, k, substring(lines[k], 0, idx2))
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

# ── Predictable identifier generators ─────────────────────────────────────

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "node" if regex.match(`\.(?:jsx?|tsx?|mjs|cjs)$`, path)

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if regex.match(`\.(?:java|kt|kts)$`, path)

_lang(path) := "ruby" if endswith(path, ".rb")

_tokens("python") := {"uuid1", "uuid3", "uuid5"}

_tokens("node") := {"uuidv1", "uuidv3", "uuidv5", "uuidv6", "uuid.v1", "uuid.v3", "uuid.v5", "uuid.v6", "v1()", "v6()"}

_tokens("php") := {"uniqid", "Uuid::uuid1", "Uuid::uuid3", "Uuid::uuid5", "Uuid::uuid6"}

_tokens("go") := {"uuid.New"}

_tokens("java") := {"nameUUIDFromBytes", "timeBasedGenerator", "nameBasedGenerator", "UuidCreator.getTimeBased", "UuidCreator.getNameBased"}

_tokens("ruby") := {"UUIDTools::UUID", "Digest::UUID"}

_gate(lang, content) if {
	some t in _tokens(lang)
	contains(content, t)
}

_gate("node", content) if {
	contains(content, "uuid")
	count(_node_uuid_names(content)) > 0
}

# A bare v1()/v6() counts only in a file that imports it from the uuid package.
_node_bare(content) if regex.match(`(?:from\s+["']uuid["']|require\(\s*["']uuid["']\s*\))`, content)

_sink_re("python", _) := `\buuid[135]\s*\(`

_node_base_re := `\buuid(?:\.v[1356]|v[1356])\s*\(`

# Local names bound to v1/v3/v5/v6 by a destructuring import from the uuid
# package: import { v1 as makeId, v5 } from 'uuid', const { v1: id } = require('uuid').
_node_uuid_names(content) := {n |
	some m in regex.find_all_string_submatch_n(`\{([^}]*)\}\s*(?:from\s*["']uuid["']|=\s*require\(\s*["']uuid["']\s*\))`, content, -1)
	some part in split(m[1], ",")
	mm := regex.find_all_string_submatch_n(`^\s*(v[1356])\s*(?:(?:as|:)\s*([A-Za-z_$][\w$]*))?\s*$`, part, 1)
	count(mm) > 0
	n := _local_name(mm[0])
}

_local_name(mm) := mm[2] if mm[2] != ""

else := mm[1]

_sink_re("node", content) := concat("", [_node_base_re, `|(?:^|[^\w.$])(?:`, concat("|", names), `)\s*\(`]) if {
	names := _node_uuid_names(content)
	count(names) > 0
} else := concat("", [_node_base_re, `|(?:^|[^\w.])v[16]\s*\(\s*\)`]) if _node_bare(content)

else := _node_base_re

_all_tokens("node", content) := _tokens("node") | _node_uuid_names(content)

_all_tokens(lang, _) := _tokens(lang) if lang != "node"

_sink_re("php", _) := `(?:^|[^\w$>:])uniqid\s*\(|Uuid::uuid[1356]\s*\(`

_sink_re("go", _) := `\buuid\.(?:NewUUID|NewV1|NewV3|NewV5|NewV6|NewMD5|NewSHA1)\s*\(`

_sink_re("java", _) := `\bUUID\.nameUUIDFromBytes\s*\(|Generators\.(?:timeBasedGenerator|timeBasedReorderedGenerator|nameBasedGenerator)\s*\(|UuidCreator\.(?:getTimeBased|getTimeOrdered|getNameBased)\w*\s*\(`

_sink_re("ruby", _) := `UUIDTools::UUID\.(?:timestamp_create|md5_create|sha1_create)\b|Digest::UUID\.uuid_v[35]\b`

_safe_re := `random_bytes\(|random_int\(|openssl_random_pseudo_bytes\(|secrets\.|os\.urandom|randomBytes\(|randomUUID\(|getRandomValues\(|SecureRandom|crypto/rand|uuid4\(|Uuid::uuid4`

_message := "A secret is generated with a predictable identifier function (a time-based or name-based UUID, or PHP uniqid()); its value can be guessed from the time, the host or the input it hashes. Use a CSPRNG: secrets.token_urlsafe, crypto.randomBytes/randomUUID, random_bytes, crypto/rand, SecureRandom"

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	not helpers._should_skip(path)
	not helpers.is_test_path(path)
	re := _sink_re(lang, content)
	lines := split(content, "\n")
	some i in _token_lines(content, _all_tokens(lang, content))
	line := lines[i]
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
