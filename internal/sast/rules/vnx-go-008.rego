package vulnetix.rules.vnx_go_008

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-008",
	"name": "Go weak PRNG for security",
	"description": "A value drawn from math/rand or math/rand/v2 (rand.Read, Int, Intn/IntN, Int31/Int63 and their n variants, Uint32/Uint64, N, Float64, Perm, Shuffle, under the package's import alias, or on a generator created with rand.New in the same file) is used for something a guess must not reproduce: the call's line names a token, password, secret, nonce, salt, OTP/TOTP, PIN, CSRF/XSRF value, session id, API or signing key, password-reset or verification code, invite code or credential, the value assigned on that line flows into such a line within the next four lines (n := rand.Int63(); token := strconv.FormatInt(n, 36)), or the call sits in a function whose name does. OTP and PIN are matched only at a word or camelCase boundary (rootPath, hotPartition and spinner are not secrets), and a bare Reset() is state, not a reset code. math/rand is seeded predictably and its state can be recovered from a few outputs. Not reported: crypto/rand calls (also when math/rand is imported under another alias in the same file), math/rand used for timing (jitter, backoff, Sleep, time.Duration, delay; a timestamp beside the value does not count as timing), sampling, load spreading or shuffling in functions not named for a secret, rand.Seed itself, the import line, _test.go and testdata code, and the call inside a string literal or comment. Random values passed out of an unnamed helper to a security caller elsewhere are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-008/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [338],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["prng", "randomness", "crypto"],
}

# The name the file gives math/rand (or math/rand/v2): its alias, else rand.
_import_re := `(?m)^\s*(?:import\s+)?([A-Za-z_]\w*\s+)?"math/rand(?:/v2)?"`

_alias(content) := a if {
	m := regex.find_all_string_submatch_n(_import_re, content, 1)
	count(m) > 0
	a := _alias_of(trim_space(m[0][1]))
}

_alias_of("") := "rand"

_alias_of(a) := a if a != ""

_methods := `(?:Read|Int|Intn|IntN|Int31|Int31n|Int32|Int32N|Int63|Int63n|Int64|Int64N|Uint|UintN|Uint32|Uint32N|Uint64|Uint64N|N|Float32|Float64|Perm|Shuffle)\(`

# Generators made from the package: rng := rand.New(rand.NewSource(...)).
_generators(content, a) := {m[1] |
	some m in regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\s*(?::=|=|:)\s*`, a, `\.New\(`]), content, -1)
}

_call_re(a, gens) := concat("", [`\b(?:`, concat("|", array.concat([a], [g | some g in gens])), `)\.`, _methods])

# What the value is for.
# OTP and PIN are matched case-sensitively at a word or camelCase boundary,
# so rootPath, hotPartition and spinner do not read as secrets; a bare
# "reset" (Reset(), resetCounters) is state, not a reset code.
_secret := `(?i:token|passw|passphrase|secret|nonce|salt|csrf|xsrf|session_?id|sess_?id|api_?key|signing_?key|private_?key|enc(?:ryption)?_?key|auth_?code|reset_?(?:token|code|link|key|pass)|pass\w*_?reset|verif\w*_?code|confirm\w*_?code|invite_?code|credential)|H?OTP|[HhTt]otp(?:[A-Z_]|\b)|\botp(?:[A-Z_]|\b)|Otp(?:[A-Z_]|\b)|_otp|PIN(?:[A-Z_s]|\b)|Pin(?:[A-Z_]|\b)|\bpin(?:[A-Z_]|\b)|_pin\b`

# Uses that need no unpredictability.
_benign := `(?i)jitter|backoff|\bdelay|sleep|time\.Duration|time\.(?:Sleep|After|Tick|NewTimer|NewTicker)\b|sampl|shuffle|weight|\bport\b`

# String literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `//.*$`, "")

# The name of the enclosing top-level function, at most 80 lines up.
_func_name(lines, i) := n if {
	lo := max([0, i - 80])
	starts := [j | some j in numbers.range(lo, i); startswith(lines[j], "func ")]
	count(starts) > 0
	m := regex.find_all_string_submatch_n(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)`, lines[max(starts)], 1)
	count(m) > 0
	n := m[0][1]
}

_security(_, _, code) if regex.match(_secret, code)

_security(lines, i, _) if regex.match(_secret, _func_name(lines, i))

# n := rand.Int63() and, within the next four lines, n flows into a line
# that names the secret (token := strconv.FormatInt(n, 36)).
_security(lines, i, code) if {
	v := helpers.assigned_first(code)
	v != "_"
	re := concat("", [`\b`, v, `\b`])
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 4]))
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(re, l)
	regex.match(_secret, _code(l))
}

# A continuation line of a call already reported on the line above.
_continues(lines, i, call) if {
	i > 0
	prev := lines[i - 1]
	regex.match(`[(,+]\s*$`, prev)
	regex.match(call, _code(prev))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "\"math/rand")
	not helpers.is_test_path(path)
	a := _alias(content)
	gens := _generators(content, a)
	call := _call_re(a, gens)
	regex.match(call, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".")
	regex.match(call, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	regex.match(call, code)
	not regex.match(_benign, regex.replace(code, call, "("))
	_security(lines, i, code)
	not _continues(lines, i, call)
	finding := {
		"rule_id": metadata.id,
		"message": "math/rand is predictable and this value is used as a secret (token, password, nonce, key or code); generate it with crypto/rand (rand.Read, rand.Int(rand.Reader, ...) or rand.Text)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
