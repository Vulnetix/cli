# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_210

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-210",
	"name": "Self-generated Error Message Containing Sensitive Information",
	"description": "An error the program raises itself carries the value of a secret: a password, passphrase, secret, secret key, API key, private key, token, credential, DSN or connection string is concatenated, formatted or interpolated into the message of an error or an error response. Such messages travel to clients, logs, crash reporters and monitoring, so the secret leaks wherever the error does. Reported: Go fmt.Errorf, errors.New/Errorf/Wrap/Wrapf, status.Errorf, http.Error, panic, and gin c.JSON/String/AbortWithStatusJSON with a 4xx/5xx status; Python raise X(...), abort(...) and HTTPException(...); Java throw new X(...), response.sendError(...) and new ResponseStatusException(...); JavaScript/TypeScript new Error/TypeError/...Error(...), createError(...) and res.status(4xx|5xx).send/json/end(...). The secret must be a value outside any string literal (an argument, a concatenation, a %-format or .format() argument, an f-string or template-literal interpolation), named so its name ends in one of those words (password, cfg.Password, apiKey, client_secret, refreshToken, tokenString, config.getPassword()). Calls that span lines are read to their closing parenthesis. Not reported: the secret's name only inside the message text (\"password is required\"), a condition on the secret rather than its value (password ? a : b, !!token, token == null, x && y), metadata about it (password.length, len(password), secret.Name, tokenType, secretName, passwordLen), sentinel errors such as ErrInvalidToken, values passed through a call that is not a getter (hash(password)), logging calls (VNX-SEC-022 and the language logging rules cover those), and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-210/",
	"languages": ["go", "java", "node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [210],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["error-handling", "self-generated", "information-exposure", "cwe-210"],
}

_ext(path, exts) if {
	some e in exts
	endswith(path, e)
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	_ext(path, {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
	not endswith(path, ".min.js")
}

_gate := {
	"go": {"Errorf", "errors.", "http.Error", "panic(", ".JSON(", ".String("},
	"py": {"raise ", "abort(", "HTTPException("},
	"java": {"throw new", "sendError(", "ResponseStatusException("},
	"js": {"Error(", "createError(", ".status("},
}

_status := `(http\.Status(BadRequest|Unauthorized|Forbidden|NotFound|InternalServerError|Conflict|UnprocessableEntity|ServiceUnavailable|TooManyRequests|BadGateway|PreconditionFailed|MethodNotAllowed|NotAcceptable|Gone)|[45]\d\d)\b`

_sink := {
	"go": concat("", [`\b(fmt\.Errorf|errors\.(New|Errorf|Wrapf?|WithMessagef?)|xerrors\.Errorf|status\.Errorf?|http\.Error|panic)\s*\(|\b(c|ctx)\.(JSON|String|AbortWithStatusJSON|IndentedJSON)\s*\(\s*`, _status]),
	"py": `\braise\s+[\w.]+\s*\(|\babort\s*\(|\bHTTPException\s*\(`,
	"java": `\bthrow\s+new\s+[\w.]+\s*\(|\.sendError\s*\(|\bnew\s+ResponseStatusException\s*\(`,
	"js": `\bnew\s+\w*(Error|Exception)\s*\(|\bcreateError\s*\(|\b(res|resp|response|reply)\s*\.\s*(status|code)\s*\(\s*[45]\d\d\s*\)\s*\.\s*(send|json|end)\s*\(`,
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

_pd(l) := count(split(l, "(")) - count(split(l, ")"))

# Line i up to the closing parenthesis of the call it opens (at most 6 lines).
_call_text(lines, i) := txt if {
	last := min([count(lines) - 1, i + 6])
	ends := [j |
		some j in numbers.range(i, last)
		sum([_pd(lines[k]) | some k in numbers.range(i, j)]) <= 0
	]
	e := min(array.concat([last], ends))
	txt := concat("\n", array.slice(lines, i, e + 1))
}

# Interpolated expressions: ${...} in template literals, {...} in f-strings.
_interps(s) := concat(" ; ", array.concat(
	[m[1] | some m in regex.find_all_string_submatch_n(`\$\{([^}]*)\}`, s, -1)],
	[m[1] |
		some fs in regex.find_all_string_submatch_n(`(?:^|[^\w])[fF][rR]?("[^"\n]*"|'[^'\n]*')`, s, -1)
		some m in regex.find_all_string_submatch_n(`\{([^{}!:=]*)[^{}]*\}`, fs[1], -1)
	],
))

# Quoted text removed, so a secret's name inside the message is not its value.
_strip(s) := regex.replace(s, "\"(?:[^\"\\\\\\n]|\\\\.)*\"|'(?:[^'\\\\\\n]|\\\\.)*'|`[^`]*`", `""`)

# Metadata about a secret rather than the secret: len(password), typeof x,
# hash(password).
_unwrap(s) := regex.replace(s, `(?i)\b(len|strlen|count|sizeof|cap|typeof|bool|type|isinstance|mask\w*|redact\w*|hash\w*|sha\d+|md5|bcrypt\.\w+)\s*\(\s*[\w.\[\]]+\s*\)|\btypeof\s+[\w.]+`, "")

# The tail after the name decides whether its value is used: a member access,
# a call, a dict key, or a condition (x ? a : b, x == null, x && y), which
# tests the secret rather than printing it. A name after `!` is a boolean.
_sens_re := `(?i)(?:^|[^\w.!])((?:[a-z_][\w]*(?:\(\))?\.)*(\w*?(password|passwd|passphrase|pwd|secret|secret_?key|secret_access_key|apikey|api_key|privatekey|private_key|token|credentials?|dsn|connstr|connectionstring|connection_string)(str|string|value|raw|bytes|plain|text)?))\b(\s*\.\s*\w+|\s*\(|\s*:[^:]|\s*:$|\s*\?[^.?]|\s*[=!]=|\s*&&|\s*\|\|)?`

_ok_tail := {"value", "string", "raw", "data", "plain", "text", "bytes", "tostring", "getvalue", "get", "encode", "decode", "strip", "trim", "hex", "reveal", "expose", "secret", "password", "token", "unwrap"}

_leaks(text) if {
	some m in regex.find_all_string_submatch_n(_sens_re, text, -1)
	name := m[2]
	not regex.match(`(?i)^err`, name)
	_tail_ok(name, m[5])
}

_tail_ok(_, "") := true

_tail_ok(name, tail) if {
	startswith(trim_space(tail), "(")
	regex.match(`(?i)^get_?`, name)
}

_tail_ok(_, tail) if {
	startswith(trim_space(tail), ".")
	attr := lower(trim_space(trim_left(trim_space(tail), ".")))
	attr in _ok_tail
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _gate[lang])
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _gate[lang])
	count(line) < 400
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_sink[lang], line, 1)
	count(m) > 0
	txt := _call_text(lines, i)
	tail := substring(txt, indexof(txt, m[0][0]), -1)
	_leaks(_unwrap(concat(" ; ", [_strip(tail), _interps(tail)])))
	finding := {
		"rule_id": metadata.id,
		"message": "Error message built from a secret value: the password, token or key travels wherever the error does (clients, logs, crash reports). Name what failed without including the value",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
