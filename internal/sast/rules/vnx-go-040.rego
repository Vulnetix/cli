package vulnetix.rules.vnx_go_040

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-040",
	"name": "Logging of sensitive data",
	"description": "A Go logging call writes a secret value into the log: an argument (outside any string literal) whose name says it is a password, passphrase, secret, token (access, refresh, ID, API, bearer), API key, private or secret key, credentials, card number, CVV or SSN (password, req.Password, accessToken, cfg.APIToken, clientSecret), the request's Authorization, Cookie or X-Api-Key header, or a structured field keyed by such a name (zap.String(\"password\", v), slog \"token\", v, logrus WithField/Fields{\"private_key\": v}, zerolog Str(\"secret\", v)). Covers the standard log package, log/slog, zap (and its sugared logger), logrus, zerolog, klog/glog and any logger variable, including calls broken across lines. Not reported: sensitive words only in the message text (\"password reset for %s\"), errors and error variables (ErrInvalidToken), a value passed through a redacting or derived-value call (redact, mask, len, hash, fingerprint), a string-literal value (\"[REDACTED]\"), lookalike names (nextPageToken, tokenCount, tokens, hasPassword, passwordPolicy, secretName, keyID), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-040/",
	"languages": ["go"],
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

# String literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `//.*$`, "")

_log_call := `\b(?:log|slog|logger|logging|logrus|zerolog|klog|glog|sugar|lg|l|\w*[lL]ogger|\w*[lL]og)\.(?:Print|Fatal|Panic|Debug|Info|Warn|Warning|Error|Trace|Log|With)\w*\(`

# The last name of a chain (req.Password -> Password) says it holds a secret.
_sensitive := `^(?i:\w*(?:password|passwd|passphrase|secret|token|apikey|api_key|privatekey|private_key|secretkey|secret_key|credentials|cardnumber|card_number|creditcard|credit_card|cvv|ssn))$`

_not_secret := `^(?:(?i:\w*(?:page_?token|next_?token|continuation_?token|sync_?token|resume_?token|cancel\w*token))|(?:has|is|no|missing|num|max|min|Has|Is|No|Missing|Num|Max|Min|Err|err)[A-Z_]\w*)$`

_sensitive_key := `"(?i:password|passwd|passphrase|secret|client_secret|token|access_token|refresh_token|id_token|api_?key|apikey|private_?key|secret_?key|credentials|authorization|ssn|card_?number|cvv)"\s*[,:]\s*([^\s,)}][^,)}]*)`

_derived := `^(?i:redact\w*|mask\w*|len|hash\w*|sha\d*\w*|fingerprint\w*|obfuscate\w*|truncate\w*|strings\.Repeat|cap)$`

_depth(s) := count(indexof_n(s, "(")) - count(indexof_n(s, ")"))

# The call's text up to where its parentheses close (at most 5 lines on).
_call(lines, i, first) := first if _depth(_code(first)) <= 0

_call(lines, i, first) := txt if {
	_depth(_code(first)) > 0
	end := min([count(lines) - 1, i + 5])
	end >= i + 1
	ks := [k |
		some k in numbers.range(i + 1, end)
		_depth(_code(concat("\n", array.concat([first], [lines[j] | some j in numbers.range(i + 1, k)])))) <= 0
	]
	stop := array.concat(ks, [end])[0]
	txt := concat("\n", array.concat([first], [lines[j] | some j in numbers.range(i + 1, stop)]))
}

# The function called around position p of s, if any (redact(tok) -> redact).
_wrapped(args, ident) if {
	some m in regex.find_all_string_submatch_n(concat("", [`([A-Za-z_][\w\.]*)\(\s*&?`, ident, `\b`]), args, -1)
	parts := split(m[1], ".")
	regex.match(_derived, parts[count(parts) - 1])
}

_wrapped(args, ident) if {
	some m in regex.find_all_string_submatch_n(concat("", [`([A-Za-z_][\w\.]*)\(\s*&?`, ident, `\b`]), args, -1)
	regex.match(_derived, m[1])
}

_secret_args(args) := {ident |
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w\.])([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)(\s*\()?`, args, -1)
	m[2] == ""
	ident := m[1]
	parts := split(ident, ".")
	last := parts[count(parts) - 1]
	regex.match(_sensitive, last)
	not regex.match(_not_secret, last)
	esc := replace(ident, ".", `\.`)
	not _wrapped(args, esc)
	not _compared(args, esc)
}

# apiKey != "" logs whether a secret is set, not the secret.
_compared(args, esc) if regex.match(concat("", [`(?:^|[^\w\.])`, esc, `\s*(?:==|!=|<=|>=|<|>)`]), args)

_compared(args, esc) if regex.match(concat("", [`(?:==|!=)\s*`, esc, `(?:[^\w\.]|$)`]), args)

_header_args(raw) := {"Authorization header" |
	regex.match(`\.Header\.Get\(\s*"(?i:authorization|cookie|x-api-key|proxy-authorization)"\s*\)`, raw)
}

_keyed_secrets(raw) := {v |
	some m in regex.find_all_string_submatch_n(_sensitive_key, raw, -1)
	v := trim_space(m[1])
	not startswith(v, "\"")
	not startswith(v, "`")
	fm := regex.find_all_string_submatch_n(`^([A-Za-z_][\w\.]*)\(`, v, 1)
	not _derived_call(fm)
}

_derived_call(fm) if {
	count(fm) > 0
	parts := split(fm[0][1], ".")
	regex.match(_derived, parts[count(parts) - 1])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`(?i)pass(?:word|wd|phrase)|secret|token|api_?key|private_?key|credentials|card_?number|cvv|ssn|authorization`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`[lL]og|sugar|\bl\.`, line)
	not helpers.is_comment_line(line)
	ms := regex.find_all_string_submatch_n(_log_call, _code(line), 1)
	count(ms) > 0
	raw := _call(lines, i, substring(line, indexof(line, ms[0][0]), -1))
	args := _code(substring(raw, count(ms[0][0]), -1))
	leaks := (_secret_args(args) | _header_args(raw)) | _keyed_secrets(raw)
	count(leaks) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Sensitive value logged (%s): log lines are stored, shipped and read far more widely than the secret should be. Log a redacted form or leave it out", [concat(", ", sort(leaks))]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
