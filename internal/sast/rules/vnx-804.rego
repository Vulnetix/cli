# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_804

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-804",
	"name": "Guessable CAPTCHA",
	"description": "Reports home-grown CAPTCHA code in JavaScript/TypeScript and Python that an automated client can solve without solving the challenge: (1) the challenge text or digits come from a predictable generator (Math.random(), or random.choice/choices/randint/randrange/random/sample/getrandbits) on a line that names a captcha, inside a function or class whose name contains captcha, or in a file whose name contains captcha; (2) the expected answer is sent to the client: res.json/res.send/ctx.body/jsonify/JsonResponse with an answer or solution key (including the shorthand { answer }), with a captcha object's .text/.answer/.solution/.code, or with a variable built a few lines above as an object holding an answer/solution key or returned by svgCaptcha.create; (3) verification fails open, so a request naming an unknown CAPTCHA id passes: an accept condition `if (!stored || given === stored.answer)` / `if not stored or ...` / `if stored is None or ... == ...`, or a reject condition that only fires when the stored CAPTCHA exists, `if (stored && stored.answer !== given)` / `if stored is not None and stored.answer != given`. Not reported: fail-closed checks (`if (!stored || stored.answer !== given)` rejecting), crypto.randomInt/randomBytes, secrets, random.SystemRandom, randomness outside captcha code, responses that omit the answer (svgCaptcha's .data), answers stored server side, third-party services (reCAPTCHA, hCaptcha, Turnstile), comments and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-804/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [804],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["captcha-bypass", "cwe-804"],
}

_ext := {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".py"}

_in_scope(path) if {
	some e in _ext
	endswith(path, e)
	not endswith(path, ".min.js")
	not helpers.is_test_path(path)
}

_weak_rng := `\bMath\.random\s*\(|(?:^|[^\w.])random\.(?:choice|choices|randint|randrange|random|sample|getrandbits|shuffle|uniform)\s*\(`

_decl_re := `^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\b|def\s)|^\s*(?:export\s+)?(?:const|let|var)\s+[\w$]+\s*=\s*(?:async\s*)?(?:\(|function\b|[\w$]+\s*=>)|^\s*(?:async\s+)?[\w$]+\s*\([^)]*\)\s*\{`

_cap := `(?i)captcha`

# The nearest function declaration at or above line i (bounded look-behind).
_enclosing(lines, i) := lines[j] if {
	cands := [k |
		some k in numbers.range(max([0, i - 25]), i)
		regex.match(_decl_re, lines[k])
	]
	count(cands) > 0
	j := max(cands)
}

_captcha_context(path, _, _) if regex.match(_cap, path)

_captcha_context(_, lines, i) if regex.match(_cap, lines[i])

_captcha_context(_, lines, i) if regex.match(_cap, _enclosing(lines, i))

# The nearest class declaration above line i names a captcha.
_captcha_context(_, lines, i) if {
	some k in numbers.range(max([0, i - 60]), i)
	regex.match(`^\s*(?:export\s+)?(?:default\s+)?class\s+\w*(?i:captcha)`, lines[k])
	not _class_between(lines, k, i)
}

_class_between(lines, k, i) if {
	some m in numbers.range(k + 1, i)
	regex.match(`^\s*(?:export\s+)?(?:default\s+)?class\s`, lines[m])
}

# Shape 1: predictable generator.
_finding(path, lines, i, line) := "The CAPTCHA challenge is generated with a non-cryptographic random number generator: its output can be predicted and the challenge solved without reading it. Use crypto.randomInt / secrets" if {
	regex.match(_weak_rng, line)
	_captcha_context(path, lines, i)
}

_sink_re := `(?:\b(?:res|response|reply|ctx)\s*\.\s*(?:json|jsonp|send|end)\s*\(|\bctx\.body\s*=|\b(?:jsonify|JsonResponse|make_response)\s*\()`

_answer_key := `(?i)['"]?\b(?:answer|solution|captcha_?answer|captcha_?text|captcha_?code|expected_?answer)['"]?\s*:|[{,]\s*(?:answer|solution|captcha_?answer|expected_?answer)\s*[,}]`

_answer_field := `(?i)\bcaptcha\w*\s*\.\s*(?:text|answer|solution|code|value)\b|(?i)\bcaptcha\w*\s*\[\s*['"](?:text|answer|solution|code)['"]\s*\]`

# Shape 2a: the answer appears inline in the response.
_finding(path, lines, i, line) := "The CAPTCHA answer is sent to the client in the response: a bot reads it instead of solving the challenge" if {
	regex.match(_sink_re, line)
	regex.match(_cap, concat("\n", array.slice(lines, max([0, i - 25]), i + 1)))
	_inline_answer(line)
}

_inline_answer(line) if regex.match(_answer_key, line)

_inline_answer(line) if regex.match(_answer_field, line)

# Shape 2b: a whole object that holds the answer is sent.
_finding(path, lines, i, line) := sprintf("The response sends %q, which holds the CAPTCHA answer: a bot reads it instead of solving the challenge", [v]) if {
	regex.match(_sink_re, line)
	not _inline_answer(line)
	m := regex.find_all_string_submatch_n(`(?:json|jsonp|send|jsonify|JsonResponse)\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]|ctx\.body\s*=\s*([A-Za-z_$][\w$]*)\s*;?\s*$`, line, 1)
	count(m) > 0
	v := concat("", [m[0][1], m[0][2]])
	_holds_answer(lines, i, v)
}

_holds_answer(lines, i, v) if {
	some j in numbers.range(max([0, i - 15]), i - 1)
	regex.match(concat("", [`^\s*(?:const|let|var)?\s*`, v, `\s*(?::\s*[\w<>\[\]]+\s*)?=\s*\{`]), lines[j])
	some k in numbers.range(j, i - 1)
	not helpers.is_comment_line(lines[k])
	regex.match(`(?i)^\s*['"]?(?:answer|solution|captcha_?answer|expected_?answer)['"]?\s*(?::|,|$)`, lines[k])
	regex.match(_cap, concat("\n", array.slice(lines, j, i + 1)))
}

_holds_answer(lines, i, v) if {
	some j in numbers.range(max([0, i - 15]), i - 1)
	regex.match(concat("", [`^\s*(?:const|let|var)?\s*`, v, `\s*=\s*\w*[Cc]aptcha\w*\.create(?:MathExpr)?\s*\(`]), lines[j])
}

# Shape 3: fail-open verification. Either the check accepts when the stored
# CAPTCHA is missing (`!stored || given === stored.answer`), or it rejects
# only when the stored CAPTCHA exists and differs (`stored && stored.answer
# !== given`), so a request naming an unknown id is never rejected.
_fail_open_msg(v) := sprintf("CAPTCHA verification passes when %q is missing: an unknown or reused CAPTCHA id skips the check", [v])

_finding(path, lines, i, line) := _fail_open_msg(v) if {
	m := regex.find_all_string_submatch_n(`\bif\s*\(\s*!\s*([\w$.]+(?:\[\s*\d+\s*\])?)\s*\|\|(.*)$`, line, 1)
	count(m) > 0
	v := m[0][1]
	_compares_answer(m[0][2], v, _eq)
}

_finding(path, lines, i, line) := _fail_open_msg(v) if {
	m := regex.find_all_string_submatch_n(`^\s*(?:el)?if\s+(?:not\s+([\w.]+(?:\[\s*\d+\s*\])?)|([\w.]+(?:\[\s*\d+\s*\])?)\s+is\s+None)\s+or\s+(.*)$`, line, 1)
	count(m) > 0
	v := concat("", [m[0][1], m[0][2]])
	_compares_answer(m[0][3], v, _eq)
}

_finding(path, lines, i, line) := _fail_open_msg(v) if {
	m := regex.find_all_string_submatch_n(`\bif\s*\(\s*([\w$.]+(?:\[\s*\d+\s*\])?)\s*&&(.*)$`, line, 1)
	count(m) > 0
	v := m[0][1]
	_compares_answer(m[0][2], v, _ne)
}

_finding(path, lines, i, line) := _fail_open_msg(v) if {
	m := regex.find_all_string_submatch_n(`^\s*(?:el)?if\s+([\w.]+(?:\[\s*\d+\s*\])?)(?:\s+is\s+not\s+None)?\s+and\s+(.*)$`, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "not"
	_compares_answer(m[0][2], v, _ne)
}

_eq := `(?:^|[^!=<>])===?(?:[^=]|$)`

_ne := `!==?`

_compares_answer(rest, v, op) if {
	regex.match(op, rest)
	contains(rest, concat("", [v, "."]))
	regex.match(`(?i)\.(?:answer|solution|text|code)\b`, rest)
}

_file_gate(path, _) if regex.match(_cap, path)

_file_gate(_, content) if regex.match(_cap, content)

findings contains finding if {
	some path, content in input.file_contents
	_in_scope(path)
	_file_gate(path, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Math\.random|random\.|res|reply|ctx|jsonify|JsonResponse|make_response|if`, line)
	not helpers.is_comment_line(line)
	msg := _finding(path, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
