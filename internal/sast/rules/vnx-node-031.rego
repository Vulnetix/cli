package vulnetix.rules.vnx_node_031

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-031",
	"name": "Logging of sensitive data",
	"description": "Reports a console.log/info/warn/error/debug/trace call, or a logger/log/winston/bunyan/pino (also this.logger, req.log, fastify.log) info/warn/error/debug/trace/fatal/verbose/silly call, or a call to a logger made by the debug package (require('debug')('ns'), or a factory imported or required from 'debug'), whose arguments pass a variable or property named as a credential or payment secret: password/passwd/pass/pwd/passphrase, secret, token (accessToken, sessionToken, refresh_token), apiKey/privateKey/accessKey/secretKey, credential(s), authorization/authHeader/bearer, jwt, otp, pin, ssn, cvv/cvc, cardNumber/creditCard. The value is read inside the call (the call may span lines; template-literal interpolations count). Not reported: the sensitive word inside the message text only ('password changed'), object keys with literal values, derived non-secret values (token.length, a fixed-length prefix such as token.substring(0, 8), !!password, Boolean(x), typeof x, redact()/mask()/hash/sha256() of it), lookalike names (tokens, tokenizer, tokenCount, nextPageTokenUrl, isTokenValid, hasSecret, passwordPolicy, secretName, secretArn, secretsManagerRegion, spinner, mapping), Math.log, comments, strings, minified files and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-031/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [532],
	"capec": ["CAPEC-63"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["logging", "sensitive-data", "information-disclosure"],
}

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".jsx")
_is_js(path) if endswith(path, ".tsx")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

_call_re := `(?:\bconsole\.(?:log|info|warn|error|debug|trace)|\b(?:logger|log|winston|bunyan|pino|_logger|LOGGER)\.(?:info|warn|warning|error|debug|trace|fatal|verbose|silly|log))\s*\(`

# A template literal's interpolations survive; all other literal text goes.
_strip(s) := t if {
	interps := [m[1] | some m in regex.find_all_string_submatch_n(`\$\{([^}]*)\}`, s, -1)]
	plain := regex.replace(
		regex.replace(s, "`[^`]*`", `''`),
		`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`,
		`''`,
	)
	t := _with_interps(plain, interps)
}

_with_interps(plain, interps) := plain if count(interps) == 0

# the interpolated expressions are arguments of the call, appended before
# its closing parenthesis
_with_interps(plain, interps) := concat("", [plain, " , ", concat(" , ", interps)]) if count(interps) > 0

_depth(lines, s, j) := sum([d |
	some k in numbers.range(s, j)
	c := _strip(lines[k])
	d := strings.count(c, "(") - strings.count(c, ")")
])

_call_text(lines, i) := t if {
	hi := min([count(lines) - 1, i + 6])
	ends := [j | some j in numbers.range(i, hi); _depth(lines, i, j) <= 0]
	e := min(array.concat(ends, [hi]))
	t := concat(" ", [l | some k in numbers.range(i, e); l := lines[k]; not helpers.is_comment_line(l)])
}

# Arguments as code: literals gone, derived values and redaction calls gone,
# object keys with explicit values gone.
_arg_code(text, re) := c if {
	m := regex.find_all_string_submatch_n(concat("", ["(?s)", re, `(.*)$`]), _strip(text), 1)
	count(m) > 0
	a := m[0][1]
	a1 := regex.replace(a, `(?i)\b[\w$.]*(?:mask|redact|sanitiz|hash|sha\d*|md5|digest|censor|obfuscat|scrub|truncat|Boolean)[\w$]*\s*\([^()]*\)`, " ")
	a2 := regex.replace(a1, `[\w$]+(?:\.[\w$]+)*\.(?:length|size)\b|[\w$]+(?:\.[\w$]+)*\.(?:substring|substr|slice)\(\s*0\s*,\s*\d+\s*\)|\btypeof\s+[\w$.]+|!!?\s*[\w$.]+`, " ")
	c := regex.replace(a2, `[\w$]+\s*:(?:[^:]|$)`, " ")
}

_sensitive_word_re := `(password|passwd|passphrase|secret|token|apikey|privatekey|accesskey|secretkey|credential|creditcard|cardnumber|authorization|authheader|bearer)`

_sensitive(id) if {
	l := lower(replace(replace(id, "_", ""), "$", ""))
	regex.match(`^(pass|pwd|passwd|pin|ssn|cvv|cvc|otp|jwt)$`, l)
}

_sensitive(id) if {
	l := lower(replace(replace(id, "_", ""), "$", ""))
	regex.match(_sensitive_word_re, l)
	not regex.match(`(count|length|size|type|name|url|uri|endpoint|path|file|field|label|placeholder|expir|ttl|valid|policy|hint|prompt|index|idx|limit|format|pattern|regex|izer|strength|score|complexity|entropy|requirement|^tokens$|ids?$|required|enabled|missing|present|exists|arn$|region|manager)`, l)
	not regex.match(`^(is|has|should|can|show|use|need|no|with|validate|verify|check)[A-Z_]`, id)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	not helpers.is_test_path(path)
	regex.match(`(?i)(pass|pwd|secret|token|key|credential|auth|bearer|jwt|otp|pin|ssn|cvv|cvc|card)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	count(line) < 500
	not helpers.is_comment_line(line)
	regex.match(_call_re, _strip(line))
	hits := _hits(lines, i, _call_re)
	count(hits) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Log call writes a sensitive value (%s) to the log; log the event, not the secret, or redact it first", [concat(", ", sort(hits))]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_hits(lines, i, re) := [id |
	code := _arg_code(_call_text(lines, i), re)
	ids := {m[0] | some m in regex.find_all_string_submatch_n(`[A-Za-z_$][\w$]*`, code, -1)}
	some id in ids
	_sensitive(id)
]

# Loggers made by the debug package: const debug = require('debug')('ns'),
# or const log = createDebug('ns') with createDebug imported from 'debug'.
_debug_factories(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?:import\s+([A-Za-z_$][\w$]*)\s+from|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\()\s*['"]debug['"]`, content, -1)
	some n in [m[1], m[2]]
	n != ""
}

_debug_loggers(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]debug['"]\s*\)\s*\(`, content, -1)
} | {m[1] |
	some f in _debug_factories(content)
	some m in regex.find_all_string_submatch_n(concat("", [`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*`, f, `\s*\(\s*['"\x60]`]), content, -1)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "debug")
	not endswith(path, ".min.js")
	not helpers.is_test_path(path)
	regex.match(`(?m)(require\(\s*|from\s+)['"]debug['"]`, content)
	loggers := _debug_loggers(content)
	count(loggers) > 0
	re := concat("", [`(?:^|[^\w$.])(?:`, concat("|", loggers), `)\s*\(`])
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	count(line) < 500
	not helpers.is_comment_line(line)
	not regex.match(`\brequire\(|(?:const|let|var)\s`, line)
	regex.match(re, _strip(line))
	hits := _hits(lines, i, re)
	count(hits) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Log call writes a sensitive value (%s) to the log; log the event, not the secret, or redact it first", [concat(", ", sort(hits))]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
