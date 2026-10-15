# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_335

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-335",
	"name": "Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)",
	"description": "A random generator that produces secrets is seeded with a constant or the clock, so its output can be reproduced by anyone who guesses the seed. Reported: Java/Kotlin new SecureRandom(seed) with any explicit seed (a SHA1PRNG seeded before first use is fully deterministic) and setSeed() with a literal, a string's bytes or System.currentTimeMillis()/nanoTime() on a SecureRandom; java.util.Random created with a literal or clock seed (directly, or through a long/val variable assigned from one in the five lines above) whose output the same file assigns to a token, secret, key, password, salt, session or reset value; Python random.seed(...), a bare seed(...) after from random import seed, and random.Random(...) with a literal or a time.time()/time_ns()/datetime.now() seed, in a file that draws such a secret from that generator (random.choice/randint/getrandbits... on the same line as the security name). Not reported: unseeded generators, a lookup key built from a literal prefix and a random number (key = \"user:\" + rnd.nextInt(1000) in a load generator), SecureRandom.setSeed(generateSeed(...)) or another generator's output (that only adds entropy), fixed seeds for simulations, shuffles and ML reproducibility (numpy, torch, random.seed(42) with no secret drawn), files whose secrets come from the secrets module, comments and test files. Go math/rand seeding is left to VNX-GO-008, which reports any math/rand draw used for a secret.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-335/",
	"languages": ["java", "kotlin", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [335],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["prng", "seed", "cwe-335"],
}

_secret_re := `(?i)(token|secret|passw|pwd|api_?key|secret_?key|\bkey\b|_key\b|[a-z]Key\b|salt|session|csrf|xsrf|reset|invite|auth_?code|credential|cookie|nonce|otp)`

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# A seed anyone can reproduce: a literal, a string's bytes, a constant, or the clock.
_jvm_weak_seed := `^\s*(-?\d[\d_]*[lL]?|"[^"]*"\.(getBytes|toByteArray)\([^)]*\)|"[^"]*"\.encodeToByteArray\(\)|new\s+byte\[\]\s*\{[^}]*\}|byteArrayOf\([^)]*\)|[A-Z][A-Z0-9_]*|System\.(currentTimeMillis|nanoTime)\(\)|(new\s+)?Date\(\)\.getTime\(\)|Instant\.now\(\)\.toEpochMilli\(\))\s*$`

_jvm_exts := {".java", ".kt"}

# ── SecureRandom constructed with a seed ────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	some ext in _jvm_exts
	endswith(path, ext)
	contains(content, "SecureRandom(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "SecureRandom(")
	not helpers.is_comment_line(line)
	regex.match(`\bSecureRandom\(\s*[^)\s]`, line)
	finding := _finding(path, i, line, "SecureRandom constructed with an explicit seed: a seeded SHA1PRNG is deterministic. Use new SecureRandom() or SecureRandom.getInstanceStrong() and never seed it")
}

# ── setSeed with a reproducible value on a SecureRandom ─────────────────

_secure_vars(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`(\w+)\s*(?::\s*SecureRandom\s*)?=\s*(?:new\s+)?SecureRandom(?:\(|\.getInstance)`, content, -1)
} | {m[1] |
	some m in regex.find_all_string_submatch_n(`\bSecureRandom\s+(\w+)\s*=`, content, -1)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _jvm_exts
	endswith(path, ext)
	contains(content, "setSeed(")
	contains(content, "SecureRandom")
	not helpers.is_test_path(path)
	vars := _secure_vars(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "setSeed(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\b(\w+)\.setSeed\((.*)\)\s*;?\s*$`, line, 1)
	count(m) > 0
	m[0][1] in vars
	regex.match(_jvm_weak_seed, m[0][2])
	finding := _finding(path, i, line, "SecureRandom seeded with a constant or the clock; remove the setSeed call (or seed only from generateSeed())")
}

# ── java.util.Random with a reproducible seed producing a secret ────────

findings contains finding if {
	some path, content in input.file_contents
	some ext in _jvm_exts
	endswith(path, ext)
	contains(content, "Random(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Random(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`(\w+)\s*(?::\s*Random\s*)?=\s*(?:new\s+)?(?:java\.util\.)?\bRandom\((.+)\)\s*;?\s*$`, line, 1)
	count(m) > 0
	_jvm_weak_arg(lines, i, m[0][2])
	_draws_secret(lines, m[0][1])
	finding := _finding(path, i, line, "java.util.Random seeded with a constant or the clock generates a secret; use SecureRandom without a seed")
}

_jvm_weak_arg(_, _, arg) if regex.match(_jvm_weak_seed, arg)

# new Random(seed) where seed was assigned from the clock or a literal just above.
_jvm_weak_arg(lines, i, arg) if {
	not regex.match(_jvm_weak_seed, arg)
	v := trim_space(arg)
	regex.match(`^[a-z]\w*$`, v)
	some k in numbers.range(max([0, i - 5]), i - 1)
	not helpers.is_comment_line(lines[k])
	a := regex.find_all_string_submatch_n(concat("", [`^\s*(?:final\s+)?(?:long|int|Long|val|var)\s+`, v, `\s*(?::\s*Long\s*)?=\s*(.+?)\s*;?\s*$`]), lines[k], 1)
	count(a) > 0
	regex.match(_jvm_weak_seed, a[0][1])
}

_draws_secret(lines, v) if {
	re := concat("", [`\b`, v, `\.(next\w*|ints|longs|getrandbits|choice|choices|randint|randrange|random|sample|randbytes)\(`])
	some l in lines
	regex.match(re, l)
	not helpers.is_comment_line(l)
	regex.match(_secret_re, l)
	not _lookup_key(l)
}

# key = "user:" + rnd.nextInt(1000) builds a lookup key (cache, map, shard)
# from a literal prefix; it is an identifier, not key material.
_lookup_key(l) if regex.match(`(?i)\b\w*key\s*=\s*"[^"]*"\s*\+`, l)

# ── Python: random seeded with a constant or the clock ──────────────────

_py_weak_seed := `^\s*(-?\d[\d_]*|'[^']*'|"[^"]*"|[A-Z][A-Z0-9_]*|(int\(\s*)?time\.(time|time_ns|monotonic)\(\)[^,]*|(int\(\s*)?datetime\.(datetime\.)?(now|utcnow)\(\)[^,]*|os\.getpid\(\))\s*$`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "random")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "seed(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^\s*(?:random)\.seed\((.*)\)\s*$`, line, 1)
	count(m) > 0
	regex.match(_py_weak_seed, m[0][1])
	_draws_secret(lines, "random")
	finding := _finding(path, i, line, "random is seeded with a constant or the clock and then generates a secret; use the secrets module (it cannot be seeded)")
}

# from random import seed, choice: seed(...) and the draws are bare calls.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)^\s*from\s+random\s+import\s+[^\n]*\bseed\b`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "seed(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^\s*seed\((.*)\)\s*$`, line, 1)
	count(m) > 0
	regex.match(_py_weak_seed, m[0][1])
	some l in lines
	regex.match(`(^|[^\w.])(choice|choices|randint|randrange|random|sample|getrandbits|randbytes)\(`, l)
	not helpers.is_comment_line(l)
	regex.match(_secret_re, l)
	finding := _finding(path, i, line, "random is seeded with a constant or the clock and then generates a secret; use the secrets module (it cannot be seeded)")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "Random(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Random(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^\s*([\w.]+)\s*=\s*(?:random\.)?Random\((.+)\)\s*$`, line, 1)
	count(m) > 0
	regex.match(_py_weak_seed, m[0][2])
	v := regex.replace(m[0][1], `^self\.`, "")
	_draws_secret(lines, v)
	finding := _finding(path, i, line, "random.Random is seeded with a constant or the clock and then generates a secret; use the secrets module (it cannot be seeded)")
}
