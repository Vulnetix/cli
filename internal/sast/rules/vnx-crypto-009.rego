package vulnetix.rules.vnx_crypto_009

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-009",
	"name": "Use of cryptographically weak PRNG (rand/srand/random in C/C++)",
	"description": "A value from a non-cryptographic C/C++ PRNG (rand(), random(), rand_r(), the drand48/lrand48/mrand48/erand48/nrand48/jrand48 family, std::rand(), or a <random> engine such as std::mt19937, minstd_rand or default_random_engine) becomes a security value: it is assigned to (or snprintf'd into, also across a line break) a token, nonce, salt, IV, secret, password, session id, CSRF token, OTP, PIN, challenge, cookie, ticket or crypto key, including through a pointer (*pin = ...), directly or through a variable (not one named as a count or size) assigned a few lines before, or it is produced inside a function whose name pairs a making verb with one (generate_token, make_nonce, new_otp, make_session_id; fuzz_tokens and parse_token are not makers). Not reported: rand() used for sampling, shuffling, jitter, hashing seeds, dictionary keys, counts, sizes and timeouts (the overwhelming majority of rand() calls); srand()/srand48()/seed48() on their own; arc4random(), getrandom(), RAND_bytes(), randombytes_buf() and std::random_device; calls inside comments or string literals; and test files. Flows through more than one intermediate variable, or across functions, are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-009/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [338, 330],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "prng", "c", "rand", "weak-randomness"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".m", ".mm", ".inl", ".ipp"}

_c_family(path) if {
	some ext in _exts
	endswith(path, ext)
}

_has_prng_word(content) if contains(content, "rand")

_has_prng_word(content) if contains(content, "mt19937")

_has_prng_word(content) if contains(content, "ranlux")

_has_prng_word(content) if contains(content, "knuth_b")

# A call to a libc PRNG that yields a value. Member calls (obj.random(),
# p->rand()), other identifiers (my_rand, arc4random, operand) and the seeding
# functions (srand, srand48, seed48, srandom) are not this.
_prng_call := `(?:^|[^\w.>:]|std::)(?:rand|random|rand_r|random_r|drand48|erand48|lrand48|nrand48|mrand48|jrand48)\s*\(`

# A <random> engine declaration: the variable is a predictable generator.
_engine_decl := `(?:std::|boost::random::|boost::)?\b(?:mt19937(?:_64)?|minstd_rand0?|default_random_engine|ranlux(?:24|48)(?:_base)?|knuth_b)\s+(?:&\s*)?([A-Za-z_]\w*)\s*[({;=]`

_engine_words := ["mt19937", "minstd_rand", "default_random_engine", "ranlux", "knuth_b"]

# Whole-file checks are plain substring tests: a regular expression over the
# content of every C file costs more than the rest of the rule.
_engine_set(content, lines) := {e |
	some w in _engine_words
	contains(content, w)
	some i in _occurrence_lines(content, w, lines)
	some g in regex.find_all_string_submatch_n(_engine_decl, lines[i], -1)
	e := g[1]
}

# The lines that can hold a PRNG call, found without walking every line of a
# large file in Rego: split the content on the word and count the newlines
# before each occurrence. A file with very many occurrences (generated code)
# falls back to the plain line walk.
_occurrence_lines(content, word, lines) := {i |
	parts := split(content, word)
	count(parts) > 1
	nls := [strings.count(p, "\n") | some p in parts]
	some k in numbers.range(0, count(parts) - 2)
	i := sum(array.slice(nls, 0, k + 1))
} if strings.count(content, word) <= 400

else := {i | some i, l in lines; contains(l, word)}

_candidate_lines(content, engines, lines) := rand_lines | engine_lines if {
	rand_lines := _occurrence_lines(content, "rand", lines)
	engine_lines := {i | some e in engines; some i in _occurrence_lines(content, e, lines)}
}

_uses_prng(code, _) if regex.match(_prng_call, code)

_uses_prng(code, engines) if {
	some e in engines
	contains(code, e)
	regex.match(concat("", [`(?:\b`, e, `\s*\(\s*\)|\(\s*`, e, `\s*\))`]), code)
}

# ── What counts as a security value ───────────────────────────────────────
# Identifiers are split into lower-case words (camelCase, snake_case, ::), so
# `token_count` is a count, `operand` is not `rand`, `dictGetRandomKey` is a
# dictionary key.

_secret_word := `^(?:auth|access|refresh|api|csrf|xsrf|reset|session|c|client|server)?(?:token|tokens|nonce|nonces|salt|salts|iv|ivs|secret|secrets|password|passwords|passwd|passphrase|pwd|session|sessid|sessionid|sid|csrf|xsrf|otp|totp|hotp|challenge|cookie|ticket|credential|credentials|keymat|pincode|passcode|keygen|authcode|apikey|authkey|privkey|seckey|sesskey)(?:s|buf|buffer|bytes|str|string|val|value|id|ids|hex|data)?$`

_key_word := `^(?:key|keys|keybuf|keydata|keybytes)$`

_key_qualifier := `^(?:aes|des|enc|encryption|crypto|crypt|cipher|secret|session|private|priv|master|sign|signing|hmac|mac|sym|symmetric|wrap|wrapping|kek|dek|api|auth|access|shared|aead|gcm|cbc|masking|mask|xor|otp)$`

_code_qualifier := `^(?:reset|verify|verification|confirm|confirmation|activation|auth|login|pin|security|access|invite|magic|recovery|otp|sms|mfa|twofa|totp)$`

# The value is a size, count or time, not the secret itself.
_measure_word := `^(?:count|counts|len|length|size|idx|index|pos|offset|num|max|min|delay|timeout|ms|sec|secs|interval|ratio|prob|bits|expiry|ttl|age|retries|attempts)$`

_words(name) := ws if {
	a := regex.replace(name, `([A-Z]+)([A-Z][a-z])`, "${1}_${2}")
	b := regex.replace(a, `([a-z0-9])([A-Z])`, "${1}_${2}")
	ws := [w | some w in regex.split(`[_:]+`, lower(b)); w != ""]
}

_measure(ws) if regex.match(_measure_word, ws[count(ws) - 1])

_secret_name(name) if {
	ws := _words(name)
	count(ws) > 0
	not _measure(ws)
	_secret_words(ws)
}

_secret_words(ws) if {
	some w in ws
	regex.match(_secret_word, w)
}

_secret_words(ws) if {
	some w in ws
	regex.match(_key_word, w)
	some q in ws
	regex.match(_key_qualifier, q)
}

_secret_words(ws) if {
	some w in ws
	regex.match(`^codes?$`, w)
	some q in ws
	regex.match(_code_qualifier, q)
}

# ── Code text ─────────────────────────────────────────────────────────────
# String literals blanked out and trailing comments dropped, so a call named
# inside either is not code.
_code(line) := c if {
	a := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)
	b := regex.replace(a, `/\*.*?\*/`, " ")
	c := regex.replace(b, `//.*$`, "")
}

# ── Sinks: where the value lands ─────────────────────────────────────────
# Assignment target: the last name of `a`, `a[i]`, `s->f`, `s.f[i]`, with an
# optional single-line for/while/if header and declaration in front, assigned
# with = += ^= |=.
_lhs_re := `^\s*(?:(?:for|while|if)\s*\(.*\)\s*)?(?:[A-Za-z_][\w:<>,\s\*&]*?[\s\*&])?\**\s*((?:[A-Za-z_]\w*(?:\s*\[[^\]]*\])*\s*(?:->|\.))*[A-Za-z_]\w*)\s*((?:\[[^\]]*\]\s*)*)[+^|]?=(?:[^=]|$)`

_target(code) := t if {
	m := regex.find_all_string_submatch_n(_lhs_re, code, 1)
	count(m) > 0
	t := {"chain": m[0][1], "indexed": m[0][2] != ""}
}

_chain_names(chain) := [n |
	some p in regex.split(`\s*(?:->|\.)\s*`, chain)
	n := regex.replace(p, `\s*\[.*$`, "")
	n != ""
]

_last(chain) := names[count(names) - 1] if names := _chain_names(chain)

_secret_target(t) if _secret_name(_last(t.chain))

# `session->id`, `token.value`: a generic field of a security-named object.
_secret_target(t) if {
	names := _chain_names(t.chain)
	count(names) > 1
	ws := _words(names[count(names) - 1])
	every w in ws {
		regex.match(`^(?:id|ids|value|val|data|buf|buffer|bytes|hex|str|string|raw|bin)$`, w)
	}
	some n in array.slice(names, 0, count(names) - 1)
	_secret_name(n)
}

# `int pin = rand() % 10000`: a PIN only as an assigned target.
_secret_target(t) if {
	ws := _words(_last(t.chain))
	some w in ws
	regex.match(`^pins?$`, w)
	not _measure(ws)
}

# A bare `key` is a key buffer only while it is being filled (`key[i] =`);
# `char *key = stringFromLongLong(rand())` is a dictionary key.
_secret_target(t) if {
	t.indexed
	ws := _words(_last(t.chain))
	count(ws) == 1
	regex.match(_key_word, ws[0])
}

# snprintf(token, ...) / sprintf(s->session_id, ...)
_printf_target(code) := chain if {
	m := regex.find_all_string_submatch_n(`\bs?n?printf\s*\(\s*&?\s*((?:[A-Za-z_]\w*\s*(?:->|\.)\s*)*[A-Za-z_]\w*)`, code, 1)
	count(m) > 0
	chain := m[0][1]
}

_sink_line(code) if _secret_target(_target(code))

_sink_line(code) if _secret_target({"chain": _printf_target(code), "indexed": false})

# A multi-line assignment: `c->token =` alone on the line above.
_continued_sink(lines, i) if {
	i > 0
	prev := lines[i - 1]
	regex.match(`[^=!<>]=\s*$`, prev)
	not helpers.is_comment_line(prev)
	_sink_line(concat("", [_code(prev), " 0"]))
}

# A printf call broken across lines: `snprintf(csrf_token, sizeof csrf_token,`
# on the line above, still open, and the PRNG call among its arguments.
_continued_sink(lines, i) if {
	i > 0
	some k in numbers.range(max([0, i - 4]), i - 1)
	contains(lines[k], "printf")
	not helpers.is_comment_line(lines[k])
	c := _code(lines[k])
	_secret_target({"chain": _printf_target(c), "indexed": false})
	joined := concat(" ", [_code(lines[m]) | some m in numbers.range(k, i - 1)])
	strings.count(joined, "(") > strings.count(joined, ")")
}

# A two-line flow: `long v = lrand48();` then `h->nonce = v ^ k;` within six
# lines. A variable named for a measure (pin_count) is not the secret.
_flows_to_sink(lines, i, code) if {
	t := _target(code)
	not t.indexed
	v := t.chain
	regex.match(`^\w+$`, v)
	not _measure(_words(v))
	end := min([count(lines) - 1, i + 6])
	i + 1 <= end
	some j in numbers.range(i + 1, end)
	l := lines[j]
	contains(l, v)
	not helpers.is_comment_line(l)
	c := _code(l)
	regex.match(concat("", [`=[^=].*\b`, v, `\b|printf\s*\(.*\b`, v, `\b`]), c)
	_sink_line(c)
}

# ── Function context ─────────────────────────────────────────────────────
# The enclosing function is named for the value it makes. Its header is the
# nearest line above, less indented than the PRNG line, that is a C/C++
# function header (at column 0, or indented and ending in `{` as an in-class
# method is) or an Objective-C method, with no closing brace at the header's
# indentation in between. Only the last `::` component counts, so every
# method of a SessionManager is not a session id generator.
_fn_header := `^\s*(?:[A-Za-z_][\w\s\*&:<>,]*?[\s\*&]+)?(?:[A-Za-z_]\w*::)*~?([A-Za-z_]\w*)\s*\([^;{}]*(?:\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:\{\s*)?)?$`

_inline_header := `^\s+(?:[A-Za-z_][\w\s\*&:<>,]*?[\s\*&]+)?(?:[A-Za-z_]\w*::)*~?([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?\{\s*$`

_objc_header := `^[-+]\s*\([^)]*\)\s*([A-Za-z_]\w*)`

_not_header := `^\s*(?:if|for|while|switch|return|else|do|case|typedef|struct|enum|union|class|namespace|template|using|extern|static_assert|catch|sizeof)\b`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_header_name(l) := m[0][1] if {
	not startswith(l, " ")
	not startswith(l, "\t")
	regex.match(`^[A-Za-z_~]`, l)
	not regex.match(_not_header, l)
	m := regex.find_all_string_submatch_n(_fn_header, l, 1)
	count(m) > 0
}

_header_name(l) := m[0][1] if {
	regex.match(`^\s`, l)
	endswith(trim_right(l, " \t\r"), "{")
	not regex.match(_not_header, l)
	m := regex.find_all_string_submatch_n(_inline_header, l, 1)
	count(m) > 0
}

_header_name(l) := m[0][1] if {
	regex.match(`^[-+]`, l)
	not endswith(trim_right(l, " \t\r"), ";")
	m := regex.find_all_string_submatch_n(_objc_header, l, 1)
	count(m) > 0
}

# A one-line function (`unsigned next_nonce() { return rand(); }`) is its
# own context; otherwise the nearest enclosing header above.
_fn_name(lines, i) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`(?:^|[\s\*&])([A-Za-z_]\w*)\s*\([^;{}()]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?\{[^{}]*\}`, lines[i], 1)
	count(m) > 0
	not regex.match(`^(?:if|for|while|switch)$`, m[0][1])
} else := name if {
	i > 0
	ii := _indent(lines[i])
	start := max([0, i - 80])
	hs := [k |
		some k in numbers.range(start, i - 1)
		l := lines[k]
		_maybe_header(l)
		_indent(l) < ii
		_header_name(l)
	]
	count(hs) > 0
	k := max(hs)
	not _closed_between(lines, k, i)
	name := _header_name(lines[k])
}

_maybe_header(l) if {
	contains(l, "(")
	not contains(l, ";")
}

_maybe_header(l) if startswith(l, "-")

_maybe_header(l) if startswith(l, "+")

_closed_between(lines, k, i) if {
	k + 1 <= i - 1
	ik := _indent(lines[k])
	some m in helpers.span(k + 1, i - 1)
	l := lines[m]
	contains(l, "}")
	_indent(l) <= ik
	startswith(trim_left(l, " \t"), "}")
}

# A whole-line comment. `*pin = rand()` (a dereference, no space after the
# star) is code, as the engine's own comment test treats it.
_comment_line(line) if {
	helpers.is_comment_line(line)
	not regex.match(`^\s*\*+[A-Za-z_(]`, line)
}

_security_context(_, _, code) if _sink_line(code)

_security_context(lines, i, _) if _continued_sink(lines, i)

_security_context(lines, i, code) if _flows_to_sink(lines, i, code)

_security_context(lines, i, _) if _maker_name(_fn_name(lines, i))

# A function named for what it makes: a security word and a verb that says
# the function produces it (generate_token, make_nonce, nextNonce, new_otp).
# fuzz_tokens, parse_token and skip_session are not makers.
_maker_verb := `^(?:gen|generate|make|mk|new|next|create|issue|mint|random|rand|rnd|build|produce|fill|init|initialize|setup|refresh|rotate|reset|assign|get|draw|alloc|allocate)$`

_maker_name(name) if {
	_secret_name(name)
	some w in _words(name)
	regex.match(_maker_verb, w)
}

_maker_name(name) if {
	ws := _words(name)
	some w in ws
	regex.match(`^pins?$`, w)
	not _measure(ws)
	some v in ws
	regex.match(_maker_verb, v)
}

findings contains finding if {
	some path, content in input.file_contents
	_c_family(path)
	_has_prng_word(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	engines := _engine_set(content, lines)
	some i in _candidate_lines(content, engines, lines)
	line := lines[i]
	not _comment_line(line)
	code := _code(line)
	_uses_prng(code, engines)
	_security_context(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": "A token, nonce, salt, key, session id or other security value is produced with a non-cryptographic PRNG (rand/random/drand48/mt19937), whose output is predictable; use getrandom(), RAND_bytes(), arc4random_buf() or libsodium randombytes_buf()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
