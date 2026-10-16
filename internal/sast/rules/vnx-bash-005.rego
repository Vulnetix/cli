package vulnetix.rules.vnx_bash_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-BASH-005",
	"name": "Hardcoded secret or password in shell script",
	"description": "Reports a literal credential written into a shell script or .env file: an assignment (NAME=value, export/local/readonly/declare NAME=value, quoted or bare) or a command-prefix assignment (PGPASSWORD='...' psql) whose name ends in PASSWORD, PASSWD, _PASS, _PWD, SECRET, SECRET_KEY, TOKEN, API_KEY, APIKEY, PRIVATE_KEY or ACCESS_KEY (any case); a literal passed to a credential flag (--password, --passwd, --token, --api-key, --client-secret, mysql -pVALUE, sshpass -p, curl -u user:VALUE, docker/podman/helm login -p, redis-cli -a); a literal token in an Authorization: Bearer/token/Basic, X-Api-Key, Api-Key, Private-Token or X-Auth-Token header; and a user:password@ pair inside a connection URL. The reported snippet has the value masked. Not reported: values that reference a variable, command substitution or backtick, empty values, values shorter than 16 characters drawn from a single character class (postgres, efficacy: local defaults rather than provisioned secrets), placeholders (changeme, your-..., <...>, xxxx, REPLACE_ME, dummy, example, test, password, secret), file paths and URLs held in the variable, values naming an environment variable, numbers and booleans, names that only contain a keyword (PASSWORD_FILE, TOKEN_URL, MAX_TOKENS), --password-stdin, comments, echo/printf text, here-document bodies, test paths, and .env.example/.sample/.template files. Shell files are .sh, .bash, .bats, .ksh, .zsh, extensionless files with a shell shebang, and .env, .envrc and .env.production/staging/local/dev files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-005/",
	"languages": ["bash", "shell", "generic"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [798, 259],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["bash", "hardcoded-secret", "credentials", "password"],
}

_shell_exts := [".sh", ".bash", ".bats", ".ksh", ".zsh"]

_is_shell(path, _) if {
	some ext in _shell_exts
	endswith(path, ext)
}

_is_shell(path, _) if regex.match(`(^|/)\.env(rc)?$`, path)

_is_shell(path, _) if regex.match(`(^|/)\.env\.(production|prod|staging|local|dev|development)$`, path)

_is_shell(path, content) if {
	startswith(content, "#!")
	regex.match(`(^|/)[^/.]+$`, path)
	regex.match(`^#![ \t]*(\S*/)?(env[ \t]+(-\S+[ \t]+)*)?(ba|da|k|z|mk)?sh(\s|$)`, content)
}

_comment(line) if startswith(trim_space(line), "#")

# ── Shapes ──────────────────────────────────────────────────────────────

_name_kw := `(?:[A-Za-z0-9_]*(?:PASSWORD|PASSWD|_PASS|_PWD|SECRET|SECRET_KEY|SECRET_ACCESS_KEY|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY)|PASS)`

# NAME=value at the start of a statement; the value quoted or bare.
_assign_re := concat("", [
	`^\s*(?:(?:export|local|readonly|typeset|declare(?:\s+-\w+)*)\s+)?(?i:`, _name_kw,
	`)=("[^"]*"|'[^']*'|[^\s;#'"]+)\s*(?:;|#|$)`,
])

# A literal after a credential flag.
_flag_re := `(?i)(?:^|\s)--(?:password|passwd|token|api-key|apikey|client-secret|secret)(?:=|\s+)("[^"]*"|'[^']*'|[^\s;'"-][^\s;]*)`

_mysql_re := `\bmysql(?:dump|admin|import)?\b.*\s-p("[^"]*"|'[^']*'|[^\s;'"]+)`

_sshpass_re := `\bsshpass\s+-p\s*("[^"]*"|'[^']*'|[^\s;'"-][^\s;]*)`

_curl_user_re := `\bcurl\b.*\s(?:-u|--user)(?:\s+|=)["']?[^\s:"'$]+:([^\s"'@]+)["']?(?:\s|$)`

_url_re := `[a-z][a-z0-9+.-]*://[^:/\s@"'$]+:([^@\s"'/]+)@`

# NAME=value as a command prefix: PGPASSWORD='...' psql, env MYSQL_PWD=... mysql.
_prefix_re := concat("", [
	`^\s*(?:env\s+(?:-\S+\s+)*)?(?:[A-Za-z_]\w*=\S*\s+)*(?i:`, _name_kw,
	`)=("[^"]*"|'[^']*'|[^\s;#'"]+)\s+[A-Za-z./]`,
])

# A literal token in an HTTP authentication header.
_auth_re := `(?i)\b(?:authorization:\s*(?:bearer|token|basic)|x-api-key:|api-key:|private-token:|x-auth-token:)\s*([^\s"'$\\]+)`

# docker/podman/helm login -p VALUE, redis-cli -a VALUE.
_login_re := `\b(?:docker|podman|nerdctl|buildah|helm(?:\s+registry)?|oras)\s+login\b.*\s-p(?:\s+|=)("[^"]*"|'[^']*'|[^\s;'"-][^\s;]*)`

_redis_re := `\bredis-cli\b.*\s-a\s+("[^"]*"|'[^']*'|[^\s;'"-][^\s;]*)`

_value(line, re) := v if {
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	v := m[0][1]
}

_all_res := [_assign_re, _flag_re, _mysql_re, _sshpass_re, _curl_user_re, _url_re, _prefix_re, _auth_re, _login_re, _redis_re]

_cands(line) := {v |
	some re in _all_res
	_applies(re, line)
	regex.match(re, line)
	v := _value(line, re)
}

_applies(re, _) if re == _assign_re

_applies(re, line) if {
	re != _assign_re
	not _printing(line)
}

_printing(line) if regex.match(`^\s*(echo|printf|log\w*|info|warn\w*|die|usage|cat)\b`, line)

# ── Is the value a literal secret ───────────────────────────────────────

_unquote(v) := trim(v, `"'`)

_literal_secret(raw) if {
	not _dynamic(raw)
	v := _unquote(raw)
	count(v) >= 6
	not _placeholder(v)
	not _not_a_secret(v)
	_secret_shaped(v)
}

# A single lowercase word (postgres, efficacy, letmein) is a local default,
# not a provisioned secret: require 16+ characters or two character classes.
_secret_shaped(v) if count(v) >= 16

_secret_shaped(v) if {
	classes := [c |
		some c in [`[a-z]`, `[A-Z]`, `[0-9]`, `[^A-Za-z0-9]`]
		regex.match(c, v)
	]
	count(classes) >= 2
}

# A double-quoted or bare value expanding a variable or command.
_dynamic(raw) if {
	not startswith(raw, "'")
	regex.match("[$`]", raw)
}

_placeholder(v) if regex.match(`(?i)(change.?me|your[-_ ]|^<.*>$|[<>{}]|x{4,}|\*{3,}|\.\.\.|replace|placeholder|dummy|example|sample|redacted|insert|enter[-_ ]|^test|fake|todo|fixme|^none$|^null$|^undefined$|^default$|^(my)?(password|passwd|secret|token|pass)$|^(api[-_]?)?key$)`, v)

# Paths, URLs, environment-variable names, numbers and booleans.
_not_a_secret(v) if regex.match(`^(/|\./|\.\./|~/)`, v)

_not_a_secret(v) if regex.match(`^[a-z][a-z0-9+.-]*://`, v)

_not_a_secret(v) if regex.match(`^[A-Z][A-Z0-9_]*$`, v)

_not_a_secret(v) if regex.match(`^[0-9]+$`, v)

_not_a_secret(v) if regex.match(`(?i)^(true|false|yes|no|on|off|enabled|disabled|stdin)$`, v)

_not_a_secret(v) if regex.match(`(?i)\.(txt|pem|key|crt|json|ya?ml|env|conf|cfg|gpg|asc|p12|pfx|jks)$`, v)

# ── Here-documents ──────────────────────────────────────────────────────

_heredocs(lines) := [[s, e] |
	some s, l in lines
	contains(l, "<<")
	not _comment(l)
	m := regex.find_all_string_submatch_n(`(?:^|[^<])<<-?\s*(?:'([A-Za-z_][\w-]*)'|"([A-Za-z_][\w-]*)"|\\?([A-Za-z_][\w-]*))`, l, 1)
	count(m) > 0
	delim := concat("", [m[0][1], m[0][2], m[0][3]])
	ends := [j |
		some j in numbers.range(s + 1, min([s + 2000, count(lines) - 1]))
		trim_space(lines[j]) == delim
	]
	count(ends) > 0
	e := ends[0]
]

_in_heredoc(docs, i) if {
	some d in docs
	d[0] < i
	i < d[1]
}

_docs(content, lines) := _heredocs(lines) if contains(content, "<<")

_docs(content, _) := [] if not contains(content, "<<")

_prefilter := `(?i)pass|_pwd|authorization:|api-key:|private-token:|auth-token:|\slogin\s.*\s-p|redis-cli|mysql|curl\b.*\s(-u|--user)|secret|token|api_?key|private_key|access_key|sshpass|://[^:/\s@]+:[^@\s]+@`

findings contains finding if {
	some path, content in input.file_contents
	_is_shell(path, content)
	not helpers.is_test_path(path)
	regex.match(_prefilter, content)
	lines := split(content, "\n")
	docs := _docs(content, lines)
	some i, line in lines
	regex.match(_prefilter, line)
	not _comment(line)
	some raw in _cands(line)
	_literal_secret(raw)
	not _in_heredoc(docs, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded credential in a shell script; read it at runtime from the environment, a mounted secret file or a secrets manager, and rotate the exposed value",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": replace(line, _unquote(raw), "****"),
	}
}
