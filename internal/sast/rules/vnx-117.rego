# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_117

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-117",
	"name": "Improper Output Neutralization for Logs",
	"description": "Decoded HTTP request data is written into a log message without neutralising CR/LF, so a requester can forge log entries or break log parsers. Reported: a logger call (Java log/logger/LOG/LOGGER .info/warn/error/debug/trace/fatal/severe/warning/fine; Python logger/log/logging/app.logger/current_app.logger/self.logger .debug/info/warning/warn/error/critical/exception/log; Node console.log/info/warn/error/debug and logger/log/winston/bunyan/req.log/fastify.log/this.logger methods) whose arguments contain a request value: Java request.getParameter/getParameterValues/getHeader or a String handler parameter bound with @RequestParam/@PathVariable/@RequestHeader/@CookieValue; Python request.args/form/values/json/get_json/data/cookies/headers/GET/POST/META/query_params; Node req/request query/body/params/headers/cookies or Koa ctx.query/params/request.body; inline, or through a variable assigned from one (or from such a variable) in the 25 lines above. Not reported: values passed through CR/LF replacement (replace/replaceAll of \\r or \\n), an escaping or encoding call (StringEscapeUtils, escape*, encode*, sanitize*, JSON.stringify, OWASP Encode.forJava, repr, %r, !r, %j), a numeric conversion or length (len, .length, .size()), a structured log object whose first argument is an object literal, still-URL-encoded values (getRequestURI, getQueryString, req.url, req.originalUrl, request.path), and loggers in comments. Whether the configured log formatter escapes newlines (JSON layouts do) is not visible to a line rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-117/",
	"languages": ["java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [117],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["log-injection", "crlf", "logging", "cwe-117"],
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_src := {
	"java": `\.getParameter(?:Values)?\s*\(|\.getHeader\s*\(|@(?:RequestParam|PathVariable|RequestHeader|CookieValue)\b`,
	"py": `\brequest\.(?:args|form|values|json|get_json|data|cookies|headers|GET|POST|META|query_params)\b`,
	"js": `\b(?:req|request)\.(?:query|body|params|headers|cookies|signedCookies)\b|\bctx\.(?:query|params|request\.body|request\.query)\b`,
}

_sink := {
	"java": `\b(?:log|logger|LOG|LOGGER|Log|Logger|log4j|LOG4J|logging)\.(?:info|warn|warning|error|debug|trace|fatal|severe|fine|finer|finest)\s*\((.*)$`,
	"py": `\b(?:logger|log|logging|_logger|_log|LOGGER|LOG|self\.logger|self\.log|app\.logger|current_app\.logger)\.(?:debug|info|warning|warn|error|critical|exception|log)\s*\((.*)$`,
	"js": `\b(?:console\.(?:log|info|warn|error|debug)|(?:logger|log|winston|bunyan|req\.log|request\.log|fastify\.log|this\.logger|this\.log)\.(?:info|warn|error|debug|trace|fatal|verbose))\s*\((.*)$`,
}

_gate := {
	"java": `\.(?:info|warn|warning|error|debug|trace|fatal|severe|fine)`,
	"py": `\.(?:debug|info|warning|warn|error|critical|exception|log)`,
	"js": `\.(?:log|info|warn|error|debug|trace|fatal|verbose)`,
}

_sanitised := `(?i)\.replace(?:all)?\s*\([^)]*\\[rn]|stringescapeutils|\bescape\w*\s*\(|\bencode\w*\s*\(|\bsanitiz\w*\s*\(|\bjson\.stringify\s*\(|\brepr\s*\(|%r\b|!r\}|\bnumber\s*\(|\bparseint\s*\(|\bparsefloat\s*\(|\.parse(?:int|long|double)\s*\(|(?:^|[^\w.])(?:int|float)\s*\(|\.valueof\s*\(|\bencode\.for\w+\s*\(|%j\b|\blen\s*\(|\.length\b|\.size\s*\(\s*\)`

_assign_re := `^\s*(?:(?:final|var|let|const|val)\s+)?(?:[A-Za-z_][\w<>\[\]\.?]*\s+)?([A-Za-z_]\w*)\s*(?::\s*[\w<>\[\]\|\. ]+?\s*)?(?:\+=|=)[^=>]`

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
}

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{\s*([A-Za-z_]\w*)`, line, 1)
	count(m) > 0
	v := m[0][1]
}

# Spring handler parameters bound from the request.
_params(line) := {m[1] |
	some m in regex.find_all_string_submatch_n(`@(?:RequestParam|PathVariable|RequestHeader|CookieValue)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?String\s+(\w+)`, line, -1)
}

_t1(lang, lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	regex.match(_src[lang], l)
	not helpers.is_comment_line(l)
	not regex.match(_sanitised, l)
	v := _assigned(l)
} | {v |
	lang == "java"
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	some v in _params(lines[j])
}

_t2(lines, i, n1) := {v |
	i > 0
	count(n1) > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	v := _assigned(l)
	not v in n1
	not regex.match(_sanitised, l)
	some n in n1
	regex.match(concat("", [`=.*\b`, n, `\b`]), l)
	not helpers.is_comment_line(l)
}

_tainted(lang, lines, i, arg, _) if regex.match(_src[lang], arg)

# Names are matched outside literals that cannot interpolate, so the word
# "signature" in a message is not the variable signature.
_tainted(lang, lines, i, arg, code) if {
	not regex.match(_src[lang], arg)
	n1 := _t1(lang, lines, i)
	names := n1 | _t2(lines, i, n1)
	some n in names
	regex.match(concat("", [`\b`, n, `\b`]), code)
}

# Every literal is blanked, and the expressions interpolated into template
# literals and f-strings are appended back as code.
_strip(lang, s) := concat(" ", array.concat([_blank(lang, s)], _interpolated(lang, s)))

_blank("py", s) := regex.replace(s, `(?:\b[rbufRBUF]{1,2})?(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`, `""`)

_blank("js", s) := regex.replace(s, "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|`(?:\\\\.|[^`\\\\])*`", `""`)

_blank("java", s) := regex.replace(s, `"(?:\\.|[^"\\])*"`, `""`)

_interpolated("java", _) := []

_interpolated("js", s) := [m[1] | some m in regex.find_all_string_submatch_n(`\$\{([^}]*)\}`, s, -1)]

_interpolated("py", s) := [m[1] | some m in regex.find_all_string_submatch_n(`\{([^{}]*)\}`, s, -1)]

# The argument list: the rest of the line, joined with the next one when the
# call breaks after its opening parenthesis.
_args(lines, i, rest) := rest if trim_space(rest) != ""

_args(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

# Python's extra={...} fields are not part of the formatted message.
_drop_extra(s) := regex.replace(s, `\bextra\s*=\s*\{.*\}`, "")

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	regex.match(concat("", ["(?m)", _src[lang]]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate[lang], line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_sink[lang], line, 1)
	count(m) > 0
	args := _drop_extra(_args(lines, i, m[0][1]))
	not regex.match(`^\s*\{`, args)
	not regex.match(_sanitised, args)
	_tainted(lang, lines, i, args, _strip(lang, args))
	finding := {
		"rule_id": metadata.id,
		"message": "Log injection: request data is written to the log without neutralising CR/LF; strip or escape \\r and \\n (or log through a structured/JSON encoder) before logging it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
