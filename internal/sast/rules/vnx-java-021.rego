package vulnetix.rules.vnx_java_021

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-021",
	"name": "Java sensitive data logged (password, token, secret, key)",
	"description": "A logging call passes the value of a password, token, secret, API key, private key or credential as an argument, writing it to log files and whatever ships them. Reported: SLF4J/Log4j/Logback/commons-logging (log, logger, LOG, LOGGER, *Log, *Logger receivers: trace/debug/info/warn/error/fatal), java.util.logging (severe/warning/info/fine/finer/finest/config/log) and android.util.Log (v/d/i/w/e/wtf) calls whose arguments, outside string literals and across continuation lines, name such a variable, field or getter (password, pwd, passphrase, secret, clientSecret, token, accessToken, apiKey, privateKey, credentials, getPassword()), or read a request parameter or header by such a name (request.getParameter(\"password\"), request.getHeader(\"Authorization\")). Not reported: the words only in the message text (\"Password reset requested for {}\"), metadata about the value (token.length(), password != null, tokenExpiry, tokenType, passwordPolicy, secretDirectory, nextPageToken), values passed through mask/redact/hash/digest helpers, non-logger receivers such as catalog.info(), and comments or string literals. Values logged through an intermediate variable with an unrelated name are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-021/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "secrets",
	"cwe": [532],
	"capec": ["CAPEC-215"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["logging", "secrets", "cwe-532", "java"],
}

_logger_call := `(?:\b(?:log|logger|_log|_logger|LOG|LOGGER|Log)|\b[a-z]\w*(?:Log|Logger)|\b[A-Z_]+_(?:LOG|LOGGER))\s*\.\s*(?:trace|debug|info|warn|warning|error|fatal|severe|fine|finer|finest|config|log|v|d|i|w|e|wtf)\s*\((.*)$`

_sensitive := `(?i)(passw(or)?d|passwd|^pwd$|pwd$|passphrase|secret|token|api_?key|auth_?key|access_?key|private_?key|signing_?key|credential)`

# Identifiers that name something about the value, not the value.
_benign := `(?i)((length|len|count|size|type|types|expir\w*|expires\w*|ttl|policy|url|uri|endpoint|name|id|ids|enabled|valid|validity|required|strength|hint|field|header|param|params|dir|directory|path|file|filename|label|prompt|regex|pattern|format|mode|provider|service|manager|store|repository|repo|utils?|helper|factory|config|properties|holder|class|exception|error|status|version|index|limit|timeout|age|generator|validator|encoder|hash|hashed|digest|fingerprint|present|set|exists|match|matches|matched|changed|reset|updated|refreshed|rotated|expired|ok|success|succeeded|failed|failure)$|^(page|next|count|continuation|cancel\w*|sync|resume|lexer|is|has|on)[A-Z_]?\w*$|^(is|has)\w+)`

_masked := `(?i)(mask|redact|obfuscat|sanitiz|hash|digest|fingerprint|truncat|\bsha\d*|\bmd5|bcrypt|argon|scrypt|hmac|\*{3})`

_strip_strings(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`)

# Metadata reads: token.length(), password != null, creds.isEmpty().
_strip_metadata(s) := regex.replace(
	regex.replace(s, `[\w.]+\s*\.\s*(length|size|isEmpty|isBlank|isPresent|hashCode|getClass|getType|getExpiration\w*|getExpires\w*)\s*\(\s*\)`, "0"),
	`[\w.]+\s*[!=]=\s*null|null\s*[!=]=\s*[\w.]+`, "0",
)

_stmt(lines, i) := s if {
	end := min([count(lines) - 1, i + 5])
	ends := [k | some k in numbers.range(i, end); contains(lines[k], ";")]
	last := _first_or(ends, end)
	s := concat(" ", [regex.replace(lines[k], `//[^"]*$`, "") | some k in numbers.range(i, last); not _comment_cont(lines, i, k)])
}

_comment_cont(lines, i, k) if {
	k > i
	helpers.is_comment_line(lines[k])
}

_first_or(arr, _) := arr[0] if count(arr) > 0

_first_or(arr, d) := d if count(arr) == 0

_sensitive_ident(args) if {
	some m in regex.find_all_string_submatch_n(`[A-Za-z_]\w*`, args, -1)
	id := m[0]
	regex.match(_sensitive, id)
	not regex.match(_benign, id)
	_sensitive_words(id)
}

# The identifier's camelCase / snake_case words must include the secret
# itself: refreshToken, DB_PASSWORD, getApiKey, but not tokenizer, secretary
# or countTokens.
_words(id) := [w |
	some w in split(lower(regex.replace(regex.replace(id, `([a-z0-9])([A-Z])`, "${1}_${2}"), `([A-Z]+)([A-Z][a-z])`, "${1}_${2}")), "_")
	w != ""
]

_secret_word := {"password", "passwords", "passwd", "pwd", "passphrase", "secret", "secrets", "token", "tokens", "credential", "credentials", "apikey", "privatekey", "accesskey", "authkey", "signingkey", "secretkey"}

_key_prefix := {"api", "private", "access", "auth", "signing", "secret"}

_sensitive_words(id) if {
	some w in _words(id)
	w in _secret_word
}

_sensitive_words(id) if {
	ws := _words(id)
	some k, w in ws
	w in _key_prefix
	ws[k + 1] == "key"
}

# A request value read by a sensitive name: request.getParameter("password"),
# request.getHeader("Authorization").
_req_read := `\.\s*get(?:Parameter|Header)\s*\(\s*"(?i:[\w-]*(?:passw(?:or)?d|passwd|pwd|passphrase|secret|token|api[-_]?key|authorization|cookie)[\w-]*)"\s*\)`

_leaks(args, _) if _sensitive_ident(_strip_metadata(args))

_leaks(_, raw) if {
	regex.match(_req_read, raw)
	not regex.match(_masked, _strip_strings(raw))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`(?i)passw|pwd|secret|token|api_?key|auth_?key|access_?key|private_?key|signing_?key|credential|passphrase`, content)
	regex.match(`(?i)log`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(lower(line), "log")
	not helpers.is_comment_line(line)
	code := _strip_strings(line)
	regex.match(_logger_call, code)
	stmt := _strip_strings(_stmt(lines, i))
	some m in regex.find_all_string_submatch_n(_logger_call, stmt, 1)
	args := m[1]
	not regex.match(_masked, args)
	_leaks(args, _stmt(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": "Logger call writes a password, token, secret or key value to the log; log that the value was present or a masked form, never the value itself",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
