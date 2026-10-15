package vulnetix.rules.vnx_sec_014

import rego.v1

import data.vulnetix.helpers
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-014",
	"name": "Hardcoded password in variable",
	"description": "A literal password is assigned in code or configuration outside tests: a variable, constant, property, field or keyword argument whose name ends in password, passwd, passphrase, secret_key/secretKey or <prefix>_pwd (DB_PASSWORD, adminPassword, self.password, $password, cfg.SecretKey, password=) is given a quoted string literal of at least 6 characters, or an object, dict, hash or JSON key of that name (\"password\": \"...\", password: '...', 'password' => '...') is, or a YAML (including a docker-compose environment list item - NAME=value), .properties, .ini, .conf or .env line of that name has a bare literal value; also a setter called with a literal (ds.setPassword(\"...\"), $m->setPassword(...)), PHP define('DB_PASSWORD', '...'), an XML property or appSettings entry (name=\"password\" value=\"...\") and an XML <password>...</password> element. Not reported: values built from the environment or interpolated (${...}, $VAR, %s, {}, f-strings with braces), empty or short values, values containing spaces (labels and messages), values that are field names, labels or route targets (password_resets#edit, password_confirmation, newPassword, Passwort), placeholders (changeme, your-password, <password>, ****, xxxxxx, example, dummy), comparisons (password == '...'), a literal that is only the start of a concatenation ('--password='.$pw), SQL text (SET password = ...), test, spec, fixture and mock paths (including Gradle androidTest, integrationTest and testFixtures source sets), translation catalogues, config templates (.example, .sample, .template, .dist), lock files and prose files. Shell scripts and .env files are also covered by VNX-BASH-005.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-014/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798, 259],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secrets", "password", "credentials", "hardcoded"],
}

_skip(path) if secrets.skip_path(path)

_skip(path) if helpers.is_test_path(path)

# Swift, C# and Kotlin projects capitalise their test directories.
_skip(path) if regex.match(`(^|/)(Tests?|Specs?|[A-Za-z]+Tests|[A-Za-z.]+\.Tests?)/`, path)

# Gradle source sets for instrumented, integration and fixture tests.
_skip(path) if regex.match(`(^|/)src/(androidTest|integrationTest|testFixtures|functionalTest)\w*/`, path)

_skip(path) if regex.match(`(?i)\.(md|markdown|rst|adoc|txt|sql|po|pot|xlf|xliff|example|sample|template|tmpl|dist)$`, path)

_skip(path) if regex.match(`(?i)(^|/)(locales?|i18n|l10n|lang|langs|translations?)/`, path)

_skip(path) if regex.match(`(?i)(^|/)[^/]*\.(example|sample|template|dist)\.[^/]+$`, path)

# The credential name: the identifier ENDS in the credential word, so
# password_field, passwordLabel and PASSWORD_MIN_LENGTH are other things.
_name := `(?:[A-Za-z0-9_]*(?:[Pp]assword|PASSWORD|[Pp]asswd|PASSWD|[Pp]assphrase|PASSPHRASE|[Ss]ecret_?[Kk]ey|SECRET_?KEY)|[A-Za-z0-9]+_(?:pwd|PWD)|[a-z0-9]+Pwd)`

# Statement form: optional declaration keywords and one type, an optional
# receiver path, the name, an optional type annotation, and = / := and a
# quoted literal ending the statement.
_assign_re := concat("", [
	`^\s*(?:(?:export|const|let|var|val|final|static|private|public|protected|internal|readonly|override|my|our|local|def|lazy)\s+)*`,
	`(?:[A-Za-z_][\w:<>\[\]*&?]*\s+)?[$@]?(?:[A-Za-z_]\w*(?:\.|->|::))*(`, _name, `)`,
	`\s*(?::\s*[\w.<>?\[\]&]+\s*)?(?::=|=)\s*(?:[rbuf]|@)?(["'])([^"'\\]*)["']\s*(?:[;,)]\s*)?(?:(?://|#).*)?$`,
])

# Key form: dict / object / hash / JSON key, or a keyword argument.
_key_re := concat("", [
	`(?:^|[\s{,(\[])(?:["'](`, _name, `)["']\s*(?::|=>)|(`, _name, `)\s*(?::|=>)|(`, _name, `)\s*=)`,
	`\s*(["'])([^"'\\]*)["']\s*(?:[,;)}\]]|$|//|#)`,
])

# Bare config line: YAML, .properties, .ini, .env.
_bare_re := concat("", [`^\s*(?:-\s*["']?)?(?:export\s+)?[\w.\-]*?(`, _name, `)\s*[:=]\s*([^\s"';$%{}<>]+)["']?(?:\s+#.*)?\s*$`])

_config(path) if regex.match(`(?i)(\.(ya?ml|properties|ini|cfg|conf|cnf|env|toml)|(^|/)\.env(\.[\w-]+)?)$`, path)

# Lines that are SQL or comparisons, not assignments.
_not_assignment(line) if regex.match(`(?i)\b(set|where|and|or|update|values|when)\s+[\w.\x60"]*pass\w*\s*=`, line)

_not_assignment(line) if regex.match(`[=!]==?\s*["']`, line)

_placeholder(v) if count(v) < 6

_placeholder(v) if contains(v, " ")

_placeholder(v) if secrets.is_placeholder(v)

_placeholder(v) if regex.match(`^\$|\$\{|\$\(|\{\{|\{[A-Za-z0-9_.]*\}|%[sdv(]|^<.*>$|\*{3,}|^\(|\.\.\.`, v)

# A field name or label: letters and separators only, containing the word.
_placeholder(v) if regex.match(`(?i)^[a-z_.\-\[\]#/:]*(pass|pwd|secret|mot|kennwort|contrase)[a-z_.\-\[\]#/:]*$`, v)

_placeholder(v) if lower(v) in {"changeit", "secret", "secrets", "required", "optional", "hidden", "masked", "invalid", "missing", "nopassword", "no-password", "unset", "null", "undefined"}

_placeholder(v) if regex.match(`(?i)^(your|my|the|enter|insert|add|put|set)[_\-]`, v)

# Values that name an environment variable or a file, not a password.
_placeholder(v) if regex.match(`^[A-Z][A-Z0-9_]{5,}$`, v)

_placeholder(v) if regex.match(`^(/|\./|~/|[A-Za-z]:\\)`, v)

_values(line) := {v |
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	v := m[0][3]
} | {v |
	some m in regex.find_all_string_submatch_n(_key_re, line, -1)
	v := m[5]
} | {v |
	some m in regex.find_all_string_submatch_n(_other_re, line, -1)
	some k in [1, 2, 3, 4]
	m[k] != ""
	v := m[k]
}

# A setter (ds.setPassword("..."), $mailer->setPassword('...')), PHP
# define('DB_PASSWORD', '...'), an XML property / appSettings entry
# (name="password" value="..."), and an XML element <password>...</password>.
_other_re := concat("", [
	`(?:\.|->)set(?:[A-Z]\w*)?(?:Password|Passwd|Passphrase|SecretKey)\(\s*["']([^"'\\]*)["']\s*\)`,
	`|\bdefine\(\s*["']`, _name, `["']\s*,\s*["']([^"'\\]*)["']\s*\)`,
	`|\b(?:name|key)\s*=\s*["'][\w.\-]*?`, _name, `["']\s+value\s*=\s*["']([^"'\\]*)["']`,
	`|<(?:[\w.\-]*?(?:[Pp]assword|PASSWORD|[Pp]asswd|[Pp]assphrase))>([^<\s]+)</`,
])

_bare_values(path, line) := {v |
	_config(path)
	m := regex.find_all_string_submatch_n(_bare_re, line, 1)
	count(m) > 0
	v := m[0][2]
	not lower(v) in {"true", "false", "yes", "no", "on", "off", "none", "null", "required"}
}

findings contains finding if {
	some path, content in input.file_contents
	_gate(content)
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)pass(word|wd|phrase)|secret_?key|pwd`, line)
	not _not_assignment(line)
	vals := [v | some v in _all_values(path, line); not _placeholder(v)]
	count(vals) > 0
	snippet := secrets.redact(replace(line, vals[0], "***REDACTED***"))
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded password found; load it from an environment variable or a secrets manager and rotate the exposed value",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": snippet,
	}
}

_all_values(path, line) := _values(line) | _bare_values(path, line)

# Cheap whole-file gate before the regular expressions.
_gate_words := ["password", "passwd", "passphrase", "secret_key", "secretkey", "pwd"]

_gate(content) if {
	lc := lower(content)
	some w in _gate_words
	contains(lc, w)
}
