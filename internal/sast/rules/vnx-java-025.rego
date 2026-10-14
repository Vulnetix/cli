package vulnetix.rules.vnx_java_025

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-025",
	"name": "Java hardcoded password or credential in source code",
	"description": "A password is written into Java production source as a string literal: a variable, field or constant whose name ends in password, passwd, pwd or passphrase assigned a literal; DriverManager.getConnection() given a literal user and a literal password; setPassword(\"...\") or a builder .password(\"...\"); a Properties put/setProperty of a *password key with a literal value; new PasswordAuthentication/UsernamePasswordCredentials with a literal password; KeyStore load/getKey with \"...\".toCharArray(); and a password variable compared with equals() against a literal (a backdoor check). Not reported: values read from System.getenv/getProperty, @Value or a request, empty strings, placeholders (${...}, ********, changeme), values that are an environment-variable name, a property key, a URL path, a field label or message (letters and separators only, or containing spaces), names that only contain the word (PASSWORD_FIELD, passwordPattern), comments, and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-025/",
	"languages": ["java"],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [259],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["hardcoded-credentials", "secrets", "cwe-259", "java"],
}

_lit := `"((?:[^"\\]|\\.)*)"`

# name = "literal";  (declaration, field, constant, var, or plain assignment)
_assign_re := concat("", [`^\s*(?:(?:private|public|protected|static|final|var|String|char\[\])\s+)*(\w*(?i:password|passwd|pwd|passphrase))\s*=\s*`, _lit, `\s*;`])

# x.setPassword("lit") / builder .password("lit")
_setter_re := concat("", [`\.(?:setPassword|password)\(\s*`, _lit, `\s*\)`])

# props.put("mail.smtp.password", "lit")
_prop_re := concat("", [`\.(?:put|setProperty)\(\s*"[\w.\-]*(?i:password|passwd|pwd)"\s*,\s*`, _lit, `\s*\)`])

# new PasswordAuthentication("u", "lit".toCharArray()) / new UsernamePasswordCredentials("u", "lit")
_cred_ctor_re := concat("", [`new\s+(?:PasswordAuthentication|UsernamePasswordCredentials)\(\s*"[^"]*"\s*,\s*`, _lit, `\s*(?:\.toCharArray\(\)\s*)?\)`])

# ks.load(in, "lit".toCharArray()) / ks.getKey(alias, "lit".toCharArray())
_keystore_re := concat("", [`\.(?:load|getKey|init)\([^;]*,\s*`, _lit, `\.toCharArray\(\)`])

# password.equals("lit") / "lit".equals(password)
_cmp_re1 := concat("", [`\b\w*(?i:password|passwd|pwd)\.equals\(\s*`, _lit, `\s*\)`])

_cmp_re2 := concat("", [_lit, `\.equals\(\s*\w*(?i:password|passwd|pwd)\s*\)`])

_line_res := [_assign_re, _setter_re, _prop_re, _cred_ctor_re, _keystore_re, _cmp_re1, _cmp_re2]

# A literal that is not a credential.
_not_secret(v) if count(v) < 3

_not_secret(v) if regex.match(`\s`, v)

_not_secret(v) if regex.match(`^\$\{|^%|^<.*>$|^\*+$|^[xX.]+$|^/|://`, v)

_not_secret(v) if regex.match(`(?i)^(changeme|change_me|changeit|secret|placeholder|redacted|null|none|todo|dummy|example|your[-_]?password.*)$`, v)

# an environment variable name
_not_secret(v) if regex.match(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$`, v)

# a property key
_not_secret(v) if regex.match(`^[a-z][\w\-]*(\.[\w\-]+)+$`, v)

# a form field name or label: letters and separators around the word
_not_secret(v) if regex.match(`(?i)^[a-z_.\-]*(pass|pwd)[a-z_.\-]*$`, v)

_secret_values(line) := {v |
	some re in _line_res
	some m in regex.find_all_string_submatch_n(re, line, -1)
	v := m[count(m) - 1]
	not _not_secret(v)
}

_password_signal := `(?i)password|passwd|pwd|passphrase|getConnection|toCharArray|Credentials`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(_password_signal, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "\"")
	regex.match(_password_signal, line)
	not helpers.is_comment_line(line)
	count(_secret_values(line)) > 0
	finding := {
		"rule_id": metadata.id,
		"message": "Password hardcoded as a string literal; read it from the environment, a secrets manager or externalised configuration",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# DriverManager.getConnection(url, "user", "password"), possibly over several lines.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "getConnection")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "DriverManager.getConnection")
	not helpers.is_comment_line(line)
	stmt := concat(" ", array.slice(lines, i, min([count(lines), i + 5])))
	m := regex.find_all_string_submatch_n(`DriverManager\.getConnection\(\s*[^,;]+,\s*"[^"]*"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)`, stmt, 1)
	count(m) > 0
	not _not_secret(m[0][1])
	finding := {
		"rule_id": metadata.id,
		"message": "Database password hardcoded in DriverManager.getConnection(); read it from the environment or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
