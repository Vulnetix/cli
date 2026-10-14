package vulnetix.rules.vnx_sec_022

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-SEC-022",
	"name": "Sensitive data in log statement",
	"description": "Reports a logging or print call whose arguments carry a credential value: a variable, field, getter or map key whose name ends with password/passwd/pwd/passphrase, secret/client_secret/secret_key, api_key/apikey, private_key, token (access/refresh/auth/id/bearer/session/jwt token) or credentials, passed as an argument, concatenated into the message, or interpolated into an f-string, template literal, ${...}/#{...}/$name/\\(name) string, or a subscript such as params['password']. Calls covered: console.log/info/warn/error/debug, logger/log/logging/slog/LOG/_logger receivers with a level method (info, debug, warn, error, printf, LogInformation, d/i/w/e...), print/println/printf/puts/NSLog/error_log, fmt.Print*, System.out/err.print*, Console.Write*, println!/eprintln!. Arguments on up to two continuation lines are read. Not reported: a sensitive word inside the message text alone (\"wrong password\", \"Usage: <password>\"), names that describe rather than hold the value (passwordLength, tokenType, secretName, password_reset, hasPassword, isTokenValid), lexer/pagination/cancellation/CSRF/push tokens, a value passed through mask/redact/hash/sanitize/len, comment lines, test paths, and files outside the covered languages.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-022/",
	"languages": ["python", "javascript", "typescript", "java", "kotlin", "go", "ruby", "php", "csharp", "swift", "rust", "c", "cpp", "scala"],
	"severity": "medium",
	"level": "warning",
	"kind": "secrets",
	"cwe": [532],
	"capec": ["CAPEC-215"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["logging", "secrets", "information-disclosure"],
}

_exts := [".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt", ".kts", ".go", ".rb", ".php", ".cs", ".swift", ".rs", ".c", ".cc", ".cpp", ".cxx", ".h", ".scala", ".m"]

_lang(path) if {
	some e in _exts
	endswith(path, e)
}

_skip(path) if endswith(path, ".min.js")

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(^|/)[A-Za-z]*Test/|(^|/)src/test/`, path)

# The call: a logging receiver with a level method, or a print primitive.
_call_head := `(?i)(?:\bconsole\.(?:log|info|warn|error|debug|trace)|(?:\b|_)(?:log|logger|logging|slog|logrus|log4j|timber|mlogger)\.(?:trace|debug|info|information|warn|warning|error|err|fatal|critical|exception|log|notice|verbose|severe|fine|finer|finest|print|printf|println|d|i|w|e|v|wtf|infof|debugf|warnf|warningf|errorf|fatalf|infow|debugw|warnw|errorw|log(?:information|debug|warning|error|trace|critical))|\b(?:print|println|printf|puts|pp|nslog|error_log|eprintln!|println!|print!|eprint!|trace!|debug!|info!|warn!|error!)|\bfmt\.(?:print|println|printf|fprint|fprintf|fprintln)|\bsystem\.(?:out|err)\.print(?:ln|f)?|\bconsole\.write(?:line)?)`

_gate_re := `(?i)password|passwd|pwd|passphrase|secret|api_?key|private_?key|token|credential`

# A name that holds the value: the last segment ends with the sensitive word.
_sens_re := `(?i)^_*[a-z0-9_]*?(password|passwd|passwort|pwd|passphrase|secret|secretkey|secret_key|apikey|api_key|privatekey|private_key|token|credentials?)s?\d*$`

# Prefixes that make it a description, a check or a different kind of token.
_benign_re := `(?i)^_*(has|is|check|validate|verify|require|requires|should|need|needs|reset|forgot|change|show|toggle|confirm_?|min|max|num|count|mask|masked|redact|redacted|hash|hashed|encrypted|enc|csrf|xsrf|next|page|continuation|cancellation|cancel|lexer|parse|parser|current|cur|prev|peek|start|end|eof|push|fcm|device|apns|expected_?type|on|handle|get_?type)`

_names(text) := {n |
	some m in regex.find_all_string_submatch_n(`[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*(\s*\(\s*\))?`, text, -1)
	m[1] == ""
	segs := split(m[0], ".")
	n := trim_space(segs[count(segs) - 1])
}

# A getter call (getPassword(), user.password()) holds the value too.
_getters(text) := {m[1] | some m in regex.find_all_string_submatch_n(`([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)`, text, -1)}

_strip_literals(t) := regex.replace(t, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\x60[^\x60]*\x60`, " ")

# Names interpolated inside string literals (${x}, #{x}, \(x), {x}, $x).
_interp(t) := {n |
	some m in regex.find_all_string_submatch_n(`(?:\$\{|#\{|\\\(|\{|\$)\s*([A-Za-z_][A-Za-z0-9_.]*)`, t, -1)
	segs := split(m[1], ".")
	n := segs[count(segs) - 1]
}

# Subscript keys: params['password'], form.get("password"), params[:password].
_keys(t) := {n |
	some m in regex.find_all_string_submatch_n(`\[\s*["':]([A-Za-z_][A-Za-z0-9_]*)["']?\s*\]|\.get\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']`, t, -1)
	some n in [m[1], m[2]]
	n != ""
}

_sensitive(n) if {
	regex.match(_sens_re, n)
	not regex.match(_benign_re, n)
	not regex.match(`(?i)(length|len|size|count|policy|field|label|hint|type|name|names|id|ids|url|uri|path|file|header|prompt|regex|pattern|format|expir\w*|valid|enabled|required|set|changed|updated|reset|strength|rules?|input|box|view|text|error|errors|message|attempts|ttl|index|idx|kind|mode|version)$`, n)
	not regex.match(`(?i)^_*tokens?$`, n)
}

_sensitive_args(args) if {
	stripped := _strip_literals(args)
	some n in _names(stripped) | _getters(stripped)
	_sensitive(n)
}

_sensitive_args(args) if {
	some n in _interp(args) | _keys(args)
	_sensitive(n)
}

# The call and up to two continuation lines while its parentheses are open.
_call_text(lines, i) := t if {
	line := lines[i]
	count(indexof_n(line, "(")) <= count(indexof_n(line, ")"))
	t := line
}

_call_text(lines, i) := t if {
	line := lines[i]
	count(indexof_n(line, "(")) > count(indexof_n(line, ")"))
	end := min([count(lines) - 1, i + 2])
	t := concat(" ", [lines[k] | some k in numbers.range(i, end)])
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	not _skip(path)
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	_maybe_call(line)
	call_re := _call_re(path)
	regex.match(call_re, _strip_literals(line))
	not helpers.is_comment_line(line)
	text := _call_text(lines, i)
	regex.match(_gate_re, text)
	parts := regex.split(call_re, text)
	args := concat(" ", array.slice(parts, 1, count(parts)))
	not regex.match(`(?i)\b(mask|redact|sanitize|scrub|obfuscate|hash|encrypt|cipher|sha\d*|md5|bcrypt|len|strlen|length|count|bool|isset|empty|is_none|isnull|isnullorempty)\w*\s*\(`, args)
	_sensitive_args(args)
	finding := {
		"rule_id": metadata.id,
		"message": "Credential value written to a log or console; remove it from the message or log a masked form so passwords, tokens and keys do not reach log files and aggregators",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_gate(content) if {
	some s in ["assw", "ASSW", "pwd", "Pwd", "PWD", "ecret", "ECRET", "oken", "OKEN", "piKey", "pi_key", "PI_KEY", "apikey", "rivate", "RIVATE", "redential", "REDENTIAL", "assphrase"]
	contains(content, s)
}

_maybe_call(line) if {
	some s in ["log", "Log", "LOG", "print", "Print", "puts", "pp(", "onsole", "Write", "!("]
	contains(line, s)
}

# Ruby calls a logger without parentheses (Rails.logger.info "..."); other
# languages need them, or "print the password" in a docstring would count.
_call_re(path) := concat("", [_call_head, `(?:\s*\(|[ \t]+)`]) if endswith(path, ".rb")

_call_re(path) := concat("", [_call_head, `\s*\(`]) if not endswith(path, ".rb")
