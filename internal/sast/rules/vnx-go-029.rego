package vulnetix.rules.vnx_go_029

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-029",
	"name": "Hardcoded weak or default password",
	"description": "A well-known weak or default password ('admin', 'password', '123456', 'changeme', 'Passw0rd', 'postgres'...) is written into Go source as a credential: assigned to a password-named variable, constant, field or map key; passed to a password setter (SetPassword(\"admin\")), to req.SetBasicAuth or url.UserPassword; placed in the user:password@ part of a connection string (\"root:root@tcp(...)\", \"postgres://postgres:postgres@...\"); or given as the default of a password-named environment variable, flag (flag.String, cobra StringVar/StringVarP) or viper key. These are the first values tried against any service. Not reported: a field-name constant whose value is the word itself (PasswordField = \"password\", a form key, a label, a struct tag), an empty default, an environment lookup or ${VAR} placeholder, a comparison or deny-list of common passwords, a strong literal (hard-coded secrets in general are other rules' concern), test files, comments and strings that only mention the word.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-029/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [798],
	"capec": ["CAPEC-256"],
	"attack_technique": ["T1078.003"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["hardcoded-password", "weak-password", "credentials"],
}

_weak := {
	"123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
	"111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
	"monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
	"mustang", "superman", "1qaz2wsx", "password1", "admin", "administrator",
	"root", "guest", "changeme", "change_me", "default", "secret", "test",
	"demo", "passw0rd", "p@ssw0rd", "welcome", "toor", "pass", "passwd",
	"password123", "admin123", "admin1", "root123", "qwerty123", "welcome1",
	"changeit", "trustno1", "iloveyou", "000000", "1q2w3e4r", "p4ssw0rd",
	"pa55word", "pa$$w0rd", "pa$$word", "secret123", "test123", "postgres",
	"mysql", "oracle",
}

_q := `["'\x60]`

# name = "literal", name: "literal", "name": "literal". The name holds
# password/passwd/pwd.
_assign := `(?i)\b(\w*(?:password|passwd|pwd)\w*)["']?\s*(?::=|=|:)\s*["'\x60]([^"'\x60]*)["'\x60]`

# SetPassword("admin"), WithPassword("root").
_call := `(?i)\b(\w*(?:password|passwd|pwd)\w*)\(\s*["'\x60]([^"'\x60]*)["'\x60]`

# A name whose literal is the word "password" as a key, label or field name,
# not as a credential.
_meta_name := `(?i)key|field|param|label|name|header|prompt|title|placeholder|env|flag|column|attr|tag|type|query|form|input|msg|message|text|hint|polic|regex|pattern|err|label|prefix|suffix|path|file|url|id$`

_weak_value(v) if lower(v) in _weak

# The literal names the field itself: PasswordField = "password".
_is_word(v) if lower(v) in {"password", "passwd", "pwd", "pass"}

_hit(line) if {
	some h in regex.find_all_string_submatch_n(_assign, line, 10)
	_weak_value(h[2])
	not _meta(h[1], h[2])
}

_hit(line) if {
	some h in regex.find_all_string_submatch_n(_call, line, 10)
	_weak_value(h[2])
	not _meta(h[1], h[2])
}

_meta(name, v) if {
	_is_word(v)
	regex.match(_meta_name, name)
}

# req.SetBasicAuth("user", "admin"), url.UserPassword("user", "admin").
_hit(line) if {
	some h in regex.find_all_string_submatch_n(`\b(?:SetBasicAuth|UserPassword)\(\s*"[^"]*"\s*,\s*"([^"]*)"`, line, 3)
	_weak_value(h[1])
}

# "scheme://user:admin@host", "root:root@tcp(host)".
_hit(line) if {
	some h in regex.find_all_string_submatch_n(`"[a-z][a-z0-9+.\-]*://[^:/@"\s]+:([^@"\s/]+)@`, line, 3)
	_weak_value(h[1])
}

_hit(line) if {
	some h in regex.find_all_string_submatch_n(`"[^:@"\s/]+:([^@"\s/]+)@(?:tcp|unix)\(`, line, 3)
	_weak_value(h[1])
}

# A default for a password-named key: getenv("DB_PASSWORD", "admin"),
# flag.String("password", "admin", ...), viper.SetDefault("db.password", ...).
_hit(line) if {
	some h in regex.find_all_string_submatch_n(`\(\s*(?:&[\w\.]+\s*,\s*)?"([^"]*)"\s*,\s*"([^"]*)"\s*[,)]`, line, 3)
	regex.match(`(?i)passw|passwd|pwd|_pass\b|^pass$`, h[1])
	_weak_value(h[2])
}

# cobra/pflag StringVarP(&v, "password", "p", "admin", "usage").
_hit(line) if {
	some h in regex.find_all_string_submatch_n(`\.StringVarP?\(\s*&[\w\.]+\s*,\s*"([^"]*)"\s*,\s*"[^"]*"\s*,\s*"([^"]*)"`, line, 3)
	regex.match(`(?i)passw|passwd|pwd`, h[1])
	_weak_value(h[2])
}

_hit(line) if {
	some h in regex.find_all_string_submatch_n(`\.StringP\(\s*"([^"]*)"\s*,\s*"[^"]*"\s*,\s*"([^"]*)"`, line, 3)
	regex.match(`(?i)passw|passwd|pwd`, h[1])
	_weak_value(h[2])
}

# user -> password tables for basic auth: gin.Accounts{"admin": "admin"},
# chi middleware.BasicAuth("realm", map[string]string{"admin": "secret"}).
_hit(line) if {
	regex.match(`\bAccounts\{|BasicAuth\(.*map\[string\]string\{`, line)
	some h in regex.find_all_string_submatch_n(`"[^"]*"\s*:\s*"([^"]*)"`, line, 10)
	_weak_value(h[1])
}

# A raw-string or text constant that only mentions a password.
_in_raw_string(line) if regex.match(`^\s*(?:const|var)?\s*\w*\s*=?\s*\x60`, line)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`(?i)pass|pwd|basicauth|accounts\{|:[^@"\s/]+@`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)pass|pwd|basicauth|accounts\{|@`, line)
	not helpers.is_comment_line(line)
	_hit(line)
	not _in_raw_string(line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded weak or default password: this is among the first values tried against any service. Load the credential from the environment or a secret store, and require a strong one at setup",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
