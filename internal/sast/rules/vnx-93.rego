# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_93

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-93",
	"name": "CRLF Injection into mail or protocol headers",
	"description": "HTTP request data is placed into a CRLF-delimited protocol line or mail header without removing CR/LF, so a requester can end the line and add their own headers or commands (mail header injection, SMTP command injection). Reported, in Go, Java, JavaScript/TypeScript, PHP, Python and Ruby: a line that builds text from a string literal containing an escaped \\r\\n and request data placed before that line terminator, or from a header-name literal (\"From: \", \"To: \", \"Cc: \", \"Bcc: \", \"Reply-To: \", \"Subject: \", \"Sender: \", \"Return-Path: \", \"MAIL FROM:\", \"RCPT TO:\") and request data anywhere on the line or in the next two lines of a call left open (concatenation, interpolation, Sprintf/format, fmt.Fprintf(conn, \"RCPT TO:<%s>\\r\\n\", ...)); PHP mail() and mb_send_mail() whose to, subject, additional-headers or additional-parameters argument (not the body) carries request data, including a call split over several lines; and, in a file using email.mime (MIMEText/MIMEMultipart), message headers (msg['Subject'] = ..., add_header and replace_header with any literal header name; item assignment for To/From/Cc/Bcc/Reply-To/Subject/Sender) assigned request data. Request data is the usual per-language request accessor, inline or through a variable assigned from it (or from such a variable, including a multi-line triple-quoted f-string that interpolates one) in the 25 lines above. Not reported: values passed through CR/LF replacement (including a replacer or helper named for CRLF/newlines), filter_var/FILTER_VALIDATE_EMAIL, an encoding call or a numeric conversion, or validated with preg_match/filter_var/a validator between the read and the use; request data only in a mail body (after the final CRLF, or the body argument of mail()); Python EmailMessage with the default policy, which rejects CR/LF in header values; lines that write the response body or a log (echo/print, res.send/write, fmt.Fprint* to w/os.Stdout/os.Stderr, console, loggers); comments. HTTP response headers are reported by VNX-GO-012, VNX-JAVA-017 and VNX-644, not here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-93/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [93],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["crlf-injection", "header-injection", "smtp", "cwe-93"],
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "rb" if endswith(path, ".rb")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_src := {
	"go": `\.(?:FormValue|PostFormValue)\s*\(|\.URL\.Query\(\)|\.Header\.Get\s*\(|\bc\.(?:Query|Param|PostForm|DefaultQuery|DefaultPostForm|FormValue|QueryParam)\s*\(`,
	"java": `\.getParameter(?:Values)?\s*\(|\.getHeader\s*\(|@(?:RequestParam|PathVariable|RequestHeader|CookieValue)\b`,
	"php": `\$_(?:GET|POST|REQUEST|COOKIE)\b|php://input|\bfilter_input\s*\(|\$request->(?:input|get|query|post)\s*\(`,
	"py": `\brequest\.(?:args|form|values|json|get_json|data|cookies|headers|GET|POST|META|query_params)\b`,
	"rb": `\bparams\b\s*(?:\[|\.(?:fetch|require|permit|dig)\b)|\bcookies\s*\[|\brequest\.(?:body|params|headers|cookies)\b`,
	"js": `\b(?:req|request)\.(?:query|body|params|headers|cookies)\b|\bctx\.(?:query|params|request\.body|request\.query)\b`,
}

_sanitised := `(?i)replace\w*\s*\([^)]*\\[rn]|\bfilter_var\s*\(|\bFILTER_(?:VALIDATE|SANITIZE)_EMAIL\b|\bencode\w*\s*\(|\burlencode\s*\(|\brawurlencode\s*\(|\bquote\s*\(|\bintval\s*\(|\(int\)|\bparseInt\s*\(|\bNumber\s*\(|\bstrconv\.Atoi\s*\(|\bInteger\.parseInt\s*\(|(?:^|[^\w.])int\s*\(|\.to_i\b|\bsanitiz\w*\s*\(|\bformataddr\s*\(|\bAddress\s*\(|\bmail\.ParseAddress\s*\(|\bInternetAddress\s*\(|(?i)\b\w*(?:crlf|cr_lf|newlines?|line_?breaks?)\w*(?:\.Replace)?\s*\(`

_guard_fn := `(?i)\b(?:preg_match|filter_var|ctype_\w+|is_email|validate\w*|isValid\w*|fullmatch|re\.match|match\?|=~|EmailValidator|ParseAddress)\b`

# Response bodies and logs are not protocol lines.
_output_line := `^\s*(?:echo\b|print\b|printf\b|puts\b|fmt\.Print|fmt\.Fprint\w*\s*\(\s*(?:w|rw|os\.Std\w+|resp|res|out)\b|System\.out\.|console\.|log\.|logger\.|logging\.)|\b(?:res|response|ctx|reply)\.(?:send|write|end|json|render|body)\b|\bw\.Write\s*\(|\bio\.WriteString\s*\(\s*w\b|\brender\s|\bResponse\.Write\b`

_crlf := `\r\n`

_header_lit := "[\"'`](?:From|To|Cc|CC|Bcc|BCC|Reply-To|Subject|Sender|Return-Path|MAIL FROM|RCPT TO):"

_assign_re := `^\s*(?:(?:final|var|let|const|val)\s+)?(?:[A-Za-z_][\w<>\[\]\.?]*\s+)?\$?([A-Za-z_]\w*)\s*(?:,\s*\$?[A-Za-z_]\w*\s*)*(?::\s*[\w<>\[\]\|\. ]+?\s*)?(?::=|\.=|\+=|=)[^=~>]`

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

_use_re("php", n) := concat("", [`\$`, n, `\b`])

_use_re(lang, n) := concat("", [`\b`, n, `\b`]) if lang != "php"

_guarded(lines, i, lang, n) if {
	some k in numbers.range(max([0, i - 25]), i - 1)
	l := lines[k]
	regex.match(_guard_fn, l)
	regex.match(_use_re(lang, n), l)
	not helpers.is_comment_line(l)
}

_names(lang, lines, i) := {n |
	n1 := _t1(lang, lines, i)
	some n in n1 | _t2(lines, i, n1)
	not _guarded(lines, i, lang, n)
}

# `code` is the text with non-interpolating literals blanked and
# interpolated expressions kept; `raw` keeps the literals for source tests.
_tainted(lang, names, raw, code) if {
	regex.match(_src[lang], raw)
	not regex.match(_sanitised, raw)
}

_tainted(lang, names, raw, code) if {
	not regex.match(_src[lang], raw)
	some n in names
	regex.match(_use_re(lang, n), code)
}

_code(lang, s) := concat(" ", array.concat([_blank(lang, s)], _interpolated(lang, s)))

_blank("php", s) := regex.replace(s, `'(?:\\.|[^'\\])*'`, `''`)

_blank("py", s) := regex.replace(s, `(?:\b[rbufRBUF]{1,2})?(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`, `""`)

_blank(lang, s) := regex.replace(s, "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|`(?:\\\\.|[^`\\\\])*`", `""`) if lang in {"go", "java", "js", "rb"}

_interpolated("php", _) := []

_interpolated("go", _) := []

_interpolated("java", _) := []

_interpolated("js", s) := [m[1] | some m in regex.find_all_string_submatch_n(`\$\{([^}]*)\}`, s, -1)]

_interpolated("rb", s) := [m[1] | some m in regex.find_all_string_submatch_n(`#\{([^}]*)\}`, s, -1)]

_interpolated("py", s) := [m[1] | some m in regex.find_all_string_submatch_n(`\{([^{}]*)\}`, s, -1)]

# ── Shape 1: protocol line built with a CRLF or header-name literal ──────

_shape_line(lang, lines, i, line, names) if {
	regex.match(_header_lit, line)
	r := _rhs(_continued(lines, i, line))
	_tainted(lang, names, r, _code(lang, r))
}

_shape_line(lang, lines, i, line, names) if {
	idx := indexof_n(line, _crlf)
	count(idx) > 0
	prefix := _rhs(substring(line, 0, max(idx)))
	_tainted(lang, names, prefix, _code(lang, prefix))
}

# The assigned variable itself ($headers .= "...") is not a use.
_rhs(s) := regex.replace(s, `^[^=]*=`, "") if _assigned(s)

_rhs(s) := s if not _assigned(s)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_protocol_text(content)
	regex.match(concat("", ["(?m)", _src[lang]]), content)
	lines := split(content, "\n")
	some i, line in lines
	_has_protocol_text(line)
	not helpers.is_comment_line(line)
	not regex.match(_output_line, line)
	not regex.match(_sanitised, line)
	not _php_mail_call(lang, line)
	names := _names(lang, lines, i)
	_shape_line(lang, lines, i, line, names)
	finding := _finding(path, i, line, "CRLF injection: request data is written into a CRLF-delimited header or protocol line without removing \\r and \\n, so it can end the line and inject further headers or commands; strip CR/LF or validate the value (e.g. as an email address) first")
}

# ── Shape 2: PHP mail() header arguments ─────────────────────────────────

# A mail() call line is judged by shape 2 alone (its body argument may hold
# CR/LF and request data legitimately).
_php_mail_call("php", line) if regex.match(`(?:^|[^\w>$:])(?:mb_send_)?mail\s*\(`, line)

# A line that leaves a call open (Fprintf(conn, "RCPT TO:<%s>\r\n",) takes
# its arguments from the next two lines.
_continued(lines, i, line) := line if _depth(line) <= 0

# A line ending in a concatenation operator continues the same string, and
# the next line is judged on its own.
_continued(lines, i, line) := line if {
	_depth(line) > 0
	endswith(trim_space(line), "+")
}

_continued(lines, i, line) := concat(" ", array.concat([line], array.slice(lines, i + 1, i + 3))) if {
	_depth(line) > 0
	not endswith(trim_space(line), "+")
}

# A call split over several lines is joined (up to 6 more lines) before its
# arguments are cut.
_call_text(lines, i, rest) := rest if _depth(rest) < 0

_call_text(lines, i, rest) := concat(" ", array.concat([rest], array.slice(lines, i + 1, i + 7))) if _depth(rest) >= 0

_depth(s) := ((strings.count(s, "(") + strings.count(s, "[")) + strings.count(s, "{")) - ((strings.count(s, ")") + strings.count(s, "]")) + strings.count(s, "}"))

_mail_args(s) := args if {
	cuts := [k |
		some k in numbers.range(0, count(s) - 1)
		substring(s, k, 1) in {",", ")"}
		_depth(substring(s, 0, k)) == 0
	]
	closes := [k | some k in cuts; substring(s, k, 1) == ")"]
	stop := min(array.concat([count(s)], closes))
	bounds := array.concat(array.concat([-1], [k | some k in cuts; k < stop]), [stop])
	args := [substring(s, bounds[x] + 1, (bounds[x + 1] - bounds[x]) - 1) | some x in numbers.range(0, count(bounds) - 2)]
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "mail(")
	regex.match(concat("", ["(?m)", _src.php]), content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "mail")
	not helpers.is_comment_line(line)
	code := regex.replace(regex.replace(line, `'(?:\\.|[^'\\])*'`, `''`), `"(?:\\.|[^"\\])*"`, `""`)
	regex.match(`(?:^|[^\w>$:])(?:mb_send_)?mail\s*\(`, code)
	m := regex.find_all_string_submatch_n(`(?:^|[^\w>$:])(?:mb_send_)?mail\s*\((.*)$`, line, 1)
	args := _mail_args(_call_text(lines, i, m[0][1]))
	names := _names("php", lines, i)
	some x, arg in args
	x != 2
	not regex.match(_sanitised, arg)
	_tainted("php", names, arg, _blank("php", arg))
	finding := _finding(path, i, line, "Mail header injection: request data reaches the to, subject or headers argument of mail(), where a CR/LF adds Bcc/Cc headers; validate addresses with filter_var(FILTER_VALIDATE_EMAIL) and strip CR/LF from the subject and headers")
}

# ── Shape 3: Python compat32 (email.mime) message headers ────────────────

_py_header := `(?i)\[\s*['"](?:to|from|cc|bcc|reply-to|subject|sender)['"]\s*\]\s*=\s*(.*)$`

_py_add_header := `\.(?:add_header|replace_header)\s*\(\s*['"][\w-]+['"]\s*,(.*)$`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "MIME")
	regex.match(`email\.mime|MIMEText|MIMEMultipart`, content)
	regex.match(concat("", ["(?m)", _src.py]), content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "]")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_py_header, line, 1)
	count(m) > 0
	rhs := m[0][1]
	not regex.match(_sanitised, rhs)
	names := _names("py", lines, i)
	_tainted("py", names, rhs, _code("py", rhs))
	finding := _finding(path, i, line, "Mail header injection: request data is assigned to an email.mime (compat32) message header, which does not reject CR/LF; use EmailMessage with the default policy or strip CR/LF first")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "MIME")
	regex.match(`email\.mime|MIMEText|MIMEMultipart`, content)
	regex.match(concat("", ["(?m)", _src.py]), content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "_header")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_py_add_header, line, 1)
	count(m) > 0
	rhs := m[0][1]
	not regex.match(_sanitised, rhs)
	names := _names("py", lines, i)
	_tainted("py", names, rhs, _code("py", rhs))
	finding := _finding(path, i, line, "Mail header injection: request data is added as an email.mime (compat32) message header, which does not reject CR/LF; use EmailMessage with the default policy or strip CR/LF first")
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_has_protocol_text(s) if contains(s, `\r\n`)

_has_protocol_text(s) if {
	not contains(s, `\r\n`)
	some h in _header_words
	contains(s, h)
	regex.match(_header_lit, s)
}

_header_words := {"From:", "To:", "Cc:", "CC:", "Bcc:", "BCC:", "Reply-To:", "Subject:", "Sender:", "Return-Path:", "MAIL FROM:", "RCPT TO:"}
