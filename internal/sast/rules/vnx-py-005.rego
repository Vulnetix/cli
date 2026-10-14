package vulnetix.rules.vnx_py_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-005",
	"name": "Weak PRNG for security operations",
	"description": "A value from Python's random module (Mersenne Twister, whose state is recoverable from 624 outputs) is used as a secret: a call to random.choice/choices/randint/randrange/random/getrandbits/sample/uniform/randbytes (through the module, an `import random as r` alias or a name imported with `from random import randint`) whose result is assigned to, passed as a keyword to, or stored under a dict key with a security name (password, token, secret, nonce, salt, otp, session id, api key, csrf, reset/verification/activation/invite code, pin, captcha), including an assignment that opens on the line above; or a choice/choices/randint/randrange/getrandbits/sample/randbytes call returned or assigned inside a function whose name is such a name (generate_api_key, make_reset_token). Not reported: secrets, random.SystemRandom() and os.urandom, numpy and other libraries' random modules, random values with no security name (sampling, shuffling, colours), jitter and probability checks such as time.sleep(random.uniform(...)) inside a token function, test files (throwaway fixture values) and the names in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-005/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [338],
	"capec": ["CAPEC-112"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cryptography", "prng", "randomness"],
}

_fns := {"choice", "choices", "randint", "randrange", "random", "getrandbits", "sample", "uniform", "randbytes"}

# Calls that build a value (not a float for jitter or a probability).
_builders := {"choice", "choices", "randint", "randrange", "getrandbits", "sample", "randbytes"}

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_mods(content) := array.concat(["random"], [m[1] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+random\s+as\s+(\w+)`, content, -1)
])

# `from random import randint, choice as pick` -> {"randint": "randint", "pick": "choice"}
_bare(content) := {alias: ws[0] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+random\s+import\s+\(?([^\n)#]+)`, content, -1)
	some part in split(m[1], ",")
	ws := regex.split(`\s+as\s+`, trim_space(part))
	ws[0] in _fns
	alias := ws[count(ws) - 1]
}

_call_re(content) := re if {
	fns := concat("|", [f | some f in _fns])
	mods := concat("", [`(?:`, concat("|", _mods(content)), `)\.(`, fns, `)`])
	bare := [a | some a, _ in _bare(content)]
	alts := concat("|", array.concat([mods], [concat("", [`(`, b, `)`]) | some b in bare]))
	re := concat("", [`(?:^|[^\w.])(?:`, alts, `)\s*\(`])
}

# The function the match names.
_fn_of(m, bare) := f if {
	some k in numbers.range(1, count(m) - 1)
	m[k] != ""
	f := _resolve(m[k], bare)
}

_resolve(name, _) := name if name in _fns

_resolve(name, bare) := bare[name] if not name in _fns

_sec_re := `(?i:passw|passphrase|token|secret|session_?id|sessid|session_?key|api_?key|apikey|access_?key|private_?key|signing_?key|auth_?key|csrf|xsrf|auth_?code|reset_?code|reset_?key|verif|confirm\w*code|activation|invite_?code|pin_?code|captcha|one_?time|magic_?link|tckt)|(?:^|_)(?i:otp|totp|hotp|pin|pwd|passwd|salt|nonce)(?:$|_|\d|[A-Z])`

_not_sec_re := `(?i)tokeni[sz]|token_?(count|len|num|type)|tokens_|n_?tokens|num_?tokens`

_sec_name(n) if {
	regex.match(_sec_re, n)
	not regex.match(_not_sec_re, n)
}

# Names assigned, passed as keywords, or used as dict keys before the call.
_targets(prefix) := {n |
	some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?[+]?=(?:[^=]|$)`, prefix, -1)
	n := m[1]
}

# Dict keys and subscripts on the call line, read before strings are blanked:
# {"csrf_token": ...} and session["token"] = ...
_keys(line) := {m[1] |
	some m in regex.find_all_string_submatch_n(`["']([A-Za-z_]\w*)["']\s*(?::|\]\s*=[^=])`, line, -1)
}

# The assignment opens on the previous line: `pw = "".join(` / newline / call.
_prefix(lines, i, c, pos) := p if {
	i > 0
	prev := _code(lines[i - 1])
	regex.match(`[(\[{,\\]\s*$`, prev)
	p := concat("\n", [prev, substring(c, 0, pos)])
}

_prefix(lines, i, c, pos) := substring(c, 0, pos) if {
	not _continued(lines, i)
}

_continued(lines, i) if {
	i > 0
	regex.match(`[(\[{,\\]\s*$`, _code(lines[i - 1]))
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The name of the nearest enclosing def, within 40 lines.
_enclosing_def(lines, i) := name if {
	ii := _indent(lines[i])
	cands := [j |
		some j in numbers.range(max([0, i - 40]), i - 1)
		regex.match(`^\s*(?:async\s+)?def\s+\w+`, lines[j])
		_indent(lines[j]) < ii
	]
	count(cands) > 0
	j := max(cands)
	name := regex.find_all_string_submatch_n(`def\s+(\w+)`, lines[j], 1)[0][1]
}

_secret_use(lines, i, c, pos, _) if {
	some n in _targets(_prefix(lines, i, c, pos))
	_sec_name(n)
}

_secret_use(lines, i, _, _, _) if {
	some n in _keys(lines[i])
	_sec_name(n)
}

_secret_use(lines, i, c, pos, fn) if {
	fn in _builders
	regex.match(`^\s*(?:return\b|[\w.\[\]"', ]+\s*[+]?=[^=])`, c)
	_sec_name(_enclosing_def(lines, i))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "random")
	not helpers.is_test_path(path)
	re := _call_re(content)
	regex.match(concat("", ["(?m)", re]), content)
	bare := _bare(content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	c := _code(line)
	m := regex.find_all_string_submatch_n(re, c, 1)
	count(m) > 0
	fn := _fn_of(m[0], bare)
	pos := indexof(c, m[0][0])
	_secret_use(lines, i, c, pos, fn)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("random.%s() is a predictable PRNG; generate passwords, tokens, salts and codes with the secrets module", [fn]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
