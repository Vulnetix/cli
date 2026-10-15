# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_532

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-532",
	"name": "Insertion of Sensitive Information into Log File: whole request logged",
	"description": "A log or print call writes a whole HTTP request part (every header, the body, the form, the cookies) or its credential header, so passwords, session cookies, bearer tokens and API keys submitted by every user end up in the log. Reported: Python logging/logger/app.logger/print with request.headers, request.POST, request.form, request.data, request.body, request.json, request.get_json(), request.cookies/COOKIES or request.META as an argument or f-string field, or request.headers['Authorization'|'Cookie'|'X-Api-Key']; JavaScript/TypeScript console.*/logger/winston/pino/request.log with req.headers, req.body, req.cookies (also JSON.stringify of them and object fields) or req.headers.authorization/cookie; Go log/fmt.Print*/slog/zap-style loggers with r.Header, r.Form, r.PostForm, r.MultipartForm, r.Cookies() or r.Header.Get(\"Authorization\"|\"Cookie\"), and the output of httputil.DumpRequest logged with no Authorization redaction in between; Java SLF4J/Log4j/System.out with request.getHeader(\"Authorization\"|\"Cookie\"), getParameterMap(), getCookies(), or a Spring @RequestHeader HttpHeaders/Map parameter. Arguments on up to two continuation lines are read. Not reported: one ordinary header or field (User-Agent, X-Request-Id, request.path), sizes and key lists (len(request.body), request.POST.keys()), a request part passed to a template or response instead of a log, comments and test code. Credential variables named password/token/secret are VNX-SEC-022, VNX-GO-040, VNX-JAVA-021 and VNX-NODE-031.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-532/",
	"languages": ["go", "java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [532],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["log-sensitive", "logging", "cwe-532"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	some e in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, e)
	not endswith(path, ".min.js")
}

_log_re := {
	"py": `\b(?:logging|logger|log|_logger|_log|LOGGER|LOG|\w+_logger|\w+\.logger)\.(?:debug|info|warning|warn|error|exception|critical|fatal|log)\(|(?:^|[^\w.])print\(`,
	"js": `\bconsole\.(?:log|info|warn|error|debug|trace|dir)\(|\b(?:\w*[lL]ogger|log|winston|pino|bunyan)\.(?:info|warn|error|debug|trace|fatal|verbose|silly|log)\(`,
	"go": `\blog\.(?:Print|Printf|Println|Fatal|Fatalf|Fatalln|Panic|Panicf|Panicln)\(|\b\w*(?:[lL]og|[lL]ogger|[sS]ugar)\.(?:Info|Infof|Infow|Debug|Debugf|Debugw|Warn|Warnf|Warnw|Error|Errorf|Errorw|Print|Printf|Println)\(|\bfmt\.(?:Print|Printf|Println)\(|\bslog\.(?:Info|Debug|Warn|Error)\(`,
	"java": `\b(?:log|logger|LOG|LOGGER|\w+Log|\w+Logger)\.(?:trace|debug|info|warn|error|fatal)\(|\bSystem\.(?:out|err)\.print(?:ln|f)?\(`,
}

_gate_re := {
	"py": `request\.`,
	"js": `\b(?:req|request|ctx)\.`,
	"go": `\b(?:r|req|request)\.|DumpRequest`,
	"java": `getHeader|getParameterMap|getCookies|@RequestHeader`,
}

# Whole request parts (and the credential header) per language. A part is
# whole when it is not followed by an accessor: request.headers) or
# {request.headers}, not request.headers.get("User-Agent").
_part_re := {
	"py": `\brequest\.(?:headers|POST|form|data|body|json|cookies|COOKIES|META)\s*(?:[),}\]]|$|!r\}|:)|\brequest\.get_json\(\s*\)|\brequest\.headers(?:\.get\(\s*|\[\s*)['"](?i:authorization|cookie|x-api-key|proxy-authorization)['"]`,
	"js": `\b(?:req|request|ctx\.request|ctx)\.(?:headers|body|cookies|signedCookies)\s*(?:[),}\]]|$)|\b(?:req|request)\.headers(?:\.(?i:authorization|cookie)\b|\[\s*['"](?i:authorization|cookie|x-api-key)['"]\s*\])`,
	"go": `\b(?:r|req|request)\.(?:Header|Form|PostForm|MultipartForm)\s*(?:[),}]|$)|\b(?:r|req|request)\.Cookies\(\)|\b(?:r|req|request)\.Header\.Get\(\s*"(?i:authorization|cookie|x-api-key|proxy-authorization)"\s*\)`,
	"java": `\bgetHeader\(\s*"(?i:authorization|cookie|x-api-key|proxy-authorization)"\s*\)|\bgetParameterMap\(\s*\)|\bgetCookies\(\s*\)`,
}

# Wrappers that log a fact about the part, not its contents.
_derived := `(?:\blen|\blist|\btype|\bbool|\bsorted|\bObject\.keys|\bcount)\(\s*(?:req|request|r)\.|\bin\s+(?:req|request|r)\.|!!\s*(?:req|request)\.|(?:\bGet\(\s*"[^"]*"\s*\)|\[\s*['"][^'"]*['"]\s*\]|\.(?i:authorization|cookie)\b)\s*(?:!==?|===?)`

# The call: the line and up to two continuation lines, while it is open.
_call(lines, i) := txt if {
	last := min([count(lines) - 1, i + 2])
	ends := [j | some j in numbers.range(i, last); regex.match(`\)\s*;?\s*$`, lines[j])]
	end := min(array.concat([last], ends))
	txt := concat(" ", [lines[j] | some j in numbers.range(i, end)])
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "The whole request (headers, body, form or cookies) or its credential header is written to the log, so passwords, session cookies and tokens of every user end up there. Log only the fields you need, with credentials redacted",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate_re[lang], content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_logword(line)
	not helpers.is_comment_line(line)
	regex.match(_log_re[lang], line)
	call := _call(lines, i)
	_logs_part(lang, lines, i, call)
	f := _finding(path, i, line)
}

_logs_part(lang, _, _, call) if {
	regex.match(_part_re[lang], call)
	not regex.match(_derived, call)
}

_logword(line) if contains(line, "og")

_logword(line) if contains(line, "OG")

_logword(line) if contains(line, "rint")

_logword(line) if contains(line, "onsole")

# Go: the bytes of httputil.DumpRequest(Out) logged with no redaction between.
_logs_part("go", lines, i, call) if {
	some j in numbers.range(max([0, i - 6]), i - 1)
	m := regex.find_all_string_submatch_n(`^\s*(\w+)\s*,\s*\w+\s*:?=\s*httputil\.DumpRequest(?:Out)?\(`, lines[j], 1)
	count(m) > 0
	regex.match(concat("", [`\b`, m[0][1], `\b`]), call)
	not _redacted_between(lines, j, i)
}

_redacted_between(lines, j, i) if {
	some k in numbers.range(j + 1, i)
	contains(lines[k], "Authorization")
}

# Java: a Spring @RequestHeader HttpHeaders / Map parameter logged whole.
_logs_part("java", lines, i, call) if {
	some j in numbers.range(max([0, i - 20]), i)
	some m in regex.find_all_string_submatch_n(`@RequestHeader\s+(?:HttpHeaders|(?:Multi(?:Value)?)?Map<[^>]*>)\s+(\w+)`, lines[j], -1)
	regex.match(concat("", [`[(,{]\s*`, m[1], `\s*[),]`]), call)
}
