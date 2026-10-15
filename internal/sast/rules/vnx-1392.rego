# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1392

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1392",
	"name": "Use of Default Credentials: default account with a default password",
	"description": "A default account name is configured together with a default or trivially guessable password, the pair credential-stuffing tools try first (admin/admin, root/root, root with an empty password, sa with an empty password, guest/guest, postgres/postgres, elastic/changeme, pi/raspberry, tomcat/tomcat). The account names are admin, administrator, root, sa, guest, postgres, elastic, tomcat, pi, oracle, system and mysql; the password must equal the account name, be a vendor default (password, admin, root, toor, changeme, changeit, default, guest, secret, postgres, mysql, oracle, manager, tomcat, raspberry), be a wordlist-weak value (123456, qwerty, password123, admin123, p@ssw0rd, ...), or be empty for root and sa. Reported: a URL with that pair in its user-info (postgres://postgres:postgres@db, amqp://guest:guest@mq, mysql://root:@localhost); two adjacent string arguments of an authentication or connection call (HTTPBasicAuth(\"admin\", \"admin\"), auth=(\"admin\", \"admin\"), SetBasicAuth(\"admin\", \"admin\"), mysqli_connect(\"localhost\", \"root\", \"root\")); a Go MySQL driver DSN (\"root:root@tcp(db:3306)/app\"); an ADO.NET/ODBC connection string naming the account and password (User Id=sa;Password=sa;); and a password-named key (variable, keyword argument, object/JSON/YAML/.env/.properties key, XML attribute, Dockerfile ENV) holding the password while a user-named key (user, username, login, email, account, *_USER, the name attribute of an XML <user>) holding the account sits on the same line or within three lines, or the key itself names root (MYSQL_ROOT_PASSWORD=root). The password line, or the URL/call line, is reported. Not reported: a non-default account (app, ops), a strong password, environment and secret references, comparisons, text inside a longer string or a comment, test, spec, fixture and docs paths, and config templates (.example, .sample, .template, .dist). A default password on its own is VNX-1393, a weak one VNX-1391, and hard-coded passwords in general VNX-SEC-014 and VNX-259.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1392/",
	"languages": ["python", "node", "go", "java", "php", "ruby", "csharp", "docker"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1392],
	"capec": ["CAPEC-70"],
	"attack_technique": ["T1078.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["use-of-default-credentials", "credentials", "cwe-1392"],
}

_users := {"admin", "administrator", "root", "sa", "guest", "postgres", "elastic", "tomcat", "pi", "oracle", "system", "mysql"}

_defaults := {
	"password", "admin", "administrator", "root", "toor", "changeme", "changeit", "change_me",
	"default", "guest", "secret", "postgres", "mysql", "oracle", "manager", "tomcat", "raspberry",
}

_weak_re := `(?i)^(?:[0-9]{4,}|(?:password|passw0rd|p@ssw0rd|p@ssword|pass|admin|root|test|user|guest|demo|qwerty|welcome|letmein|changeme|secret|master)[0-9!@#$.]{1,4}|qwerty(?:uiop)?|asdf(?:gh(?:jkl)?)?|zxcvbnm?|abc123|abcd1234|123abc|1q2w3e(?:4r)?|1qaz2wsx|123qwe|qwe123|letmein|welcome|iloveyou|monkey|dragon|sunshine|trustno1|football|baseball|master|abcdef|aaaaaa|s3cret|passw0rd|p@ssw0rd|p@ssword)$`

_pw_ok(_, p) if p in _defaults

_pw_ok(_, p) if regex.match(_weak_re, p)

_pw_ok(u, p) if {
	p != ""
	lower(p) == u
}

_pw_ok(u, "") if u in {"root", "sa"}

# ── Files ──────────────────────────────────────────────────────────────────

_code_re := `\.(?:py|js|jsx|mjs|cjs|ts|tsx|go|java|php|rb|cs|config|xml|json)$`

_cfg_re := `(?:\.(?:ya?ml|env|properties|ini|conf|cfg|toml)|(?:^|/)\.env)$`

_docker_re := `(?i)(?:^|/)[^/]*(?:dockerfile|containerfile)[^/]*$`

_kind(path) := "code" if regex.match(_code_re, path)

_kind(path) := "cfg" if {
	not regex.match(_code_re, path)
	regex.match(_cfg_re, path)
}

_kind(path) := "docker" if {
	not regex.match(_code_re, path)
	not regex.match(_cfg_re, path)
	regex.match(_docker_re, path)
}

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(?i)(?:^|/)(?:docs?|locales?|i18n|lang|translations?)/`, path)

_skip(path) if regex.match(`(?i)\.(?:example|sample|template|tmpl|dist|min\.js|lock)$`, path)

_skip(path) if regex.match(`(?i)(?:^|/)package(?:-lock)?\.json$`, path)

# ── Keys ───────────────────────────────────────────────────────────────────

_pw_key(key) if {
	k := lower(key)
	regex.match(`(?:password|passwd|pwd|passphrase)$|(?:^|[_.\->])pass$`, k)
	not regex.match(`(?:field|param|column|attr|label|input|selector|placeholder|hint|title|text|msg|message|error|route|path|url|name|type|policy|reset|forgot)[_.\-]?(?:password|passwd|pwd|pass)$`, k)
}

_user_key(key) if regex.match(`(?i)(?:^|[_.\->])(?:user|username|user_name|login|email|account|uid)$|(?:^|[a-z])(?:User|Username|UserName|Login)$`, key)

# key ['"]? op 'value' (+)?
_kv_re := `([A-Za-z_$][\w$.\->]*)['"]?\]?\s*(===|!==|==|!=|=>|:=|=|:)\s*(?:"([^"\n]{0,64})"|'([^'\n]{0,64})')(\s*\+)?`

_cfg_kv_re := `^\s*(?:-\s*)?(?:export\s+)?['"]?([\w.\-]+)['"]?\s*[:=]\s*([^\s'"#,;{}\[\]]*)\s*(?:[#;].*)?$`

_docker_kv_re := `^\s*(?:ENV|ARG)\s+(\w+)(?:\s*=\s*|\s+)["']?([^\s'"]*)["']?\s*$`

_outside_string(line, whole) if {
	idx := indexof(line, whole)
	idx >= 0
	prefix := trim_right(substring(line, 0, idx), `'"[`)
	count(indexof_n(prefix, `"`)) % 2 == 0
	count(indexof_n(prefix, "'")) % 2 == 0
}

# Every credential-shaped (key, value) pair the line assigns: only password and
# user keys are kept, and the string-position check runs last.
_pairs(line, _) := {[m[1], concat("", [m[3], m[4]])] |
	some m in regex.find_all_string_submatch_n(_kv_re, line, -1)
	_cred_key(m[1])
	not m[2] in {"===", "!==", "==", "!="}
	m[5] == ""
	_outside_string(line, m[0])
}

_cred_key(k) if _pw_key(k)

_cred_key(k) if _user_key(k)

_cfg_pairs(line, "cfg") := {[m[1], m[2]] | some m in regex.find_all_string_submatch_n(_cfg_kv_re, line, 1)}

_cfg_pairs(line, "docker") := {[m[1], m[2]] | some m in regex.find_all_string_submatch_n(_docker_kv_re, line, 1)}

_cfg_pairs(_, "code") := set()

_all_pairs(line, kind) := _pairs(line, kind) | _cfg_pairs(line, kind)

_user_vals(line, kind) := {lower(v) |
	some p in _all_pairs(line, kind)
	_user_key(p[0])
	v := p[1]
	lower(v) in _users
}

# <user name="admin" password="admin" />: the element is its own unit.
_xml_user_vals(line) := {lower(m[1]) |
	contains(line, "<user")
	some m in regex.find_all_string_submatch_n(`<user\b[^>]*\bname\s*=\s*"([^"]*)"`, line, 1)
	lower(m[1]) in _users
}

# A neighbouring line that sets its own password (User(username="admin",
# password=random()) above User(username="operator", password="password123"))
# belongs to another account.
_own_password(l) if regex.match(`(?i)(?:password|passwd|pwd|_pass)['"]?\]?\s*(?:=>|:=|=|:)`, l)

_own_password(l) if contains(l, "<user")

_near_users(lines, i, kind) := _user_vals(lines[i], kind) | _xml_user_vals(lines[i]) | {u |
	some j in numbers.range(max([0, i - 3]), min([count(lines) - 1, i + 3]))
	j != i
	l := lines[j]
	not helpers.is_comment_line(l)
	not _own_password(l)
	some u in _user_vals(l, kind)
}

# ── Hits ───────────────────────────────────────────────────────────────────

# A URL with default credentials in its user-info.
_hit(_, _, line, _) if {
	contains(line, "://")
	contains(line, "@")
	some m in regex.find_all_string_submatch_n(`\b[a-zA-Z][\w+.\-]*://([^:/@\s'"]+):([^@/\s'"]*)@`, line, -1)
	u := lower(m[1])
	u in _users
	_pw_ok(u, m[2])
}

# A Go MySQL driver DSN, which has no scheme: "root:root@tcp(db:3306)/app".
_hit(_, _, line, "code") if {
	contains(line, "@")
	some m in regex.find_all_string_submatch_n(`["'\x60]([^:/@\s'"\x60]+):([^@/\s'"\x60]*)@(?:tcp|unix)\(`, line, -1)
	u := lower(m[1])
	u in _users
	_pw_ok(u, m[2])
}

# An ADO.NET / ODBC connection string: "Server=x;User Id=sa;Password=sa;".
_hit(_, _, line, _) if {
	contains(line, ";")
	some um in regex.find_all_string_submatch_n(`(?i)(?:^|[;"'\s])(?:user\s?id|uid|user|username)\s*=\s*([^;"'\s]+)\s*;`, line, 1)
	u := lower(um[1])
	u in _users
	some pm in regex.find_all_string_submatch_n(`(?i)(?:^|[;"'\s])(?:password|pwd)\s*=\s*([^;"'\s]*)\s*(?:;|["']|$)`, line, 1)
	_pw_ok(u, pm[1])
}

_call_auth_re :=`(?i)auth|login|logon|sign_?in|connect|cred|basic|bind|session|client|token`

# Two adjacent string arguments of an authentication or connection call:
# ("admin", "admin") or (host, "root", "root").
_hit(_, _, line, "code") if {
	regex.match(`["']\s*,\s*["']`, line)
	regex.match(_call_auth_re, line)
	some m in regex.find_all_string_submatch_n(`[(,]\s*(?:auth\s*=\s*\(\s*)?["']([^"'\n]+)["']\s*,\s*["']([^"'\n]+)["']`, line, -1)
	_default_pair(line, m[0], m[1], m[2])
}

_hit(_, _, line, "code") if {
	regex.match(`["']\s*,\s*["'][^"'\n]+["']\s*,\s*["']`, line)
	regex.match(_call_auth_re, line)
	some m in regex.find_all_string_submatch_n(`[(,]\s*["'][^"'\n]+["']\s*,\s*["']([^"'\n]+)["']\s*,\s*["']([^"'\n]+)["']`, line, -1)
	_default_pair(line, m[0], m[1], m[2])
}

_default_pair(line, whole, user, pw) if {
	u := lower(user)
	u in _users
	_pw_ok(u, pw)
	_outside_string(line, whole)
}

# A value that could complete a default pair, checked before neighbours are read.
_pw_maybe(p) if p in _defaults

_pw_maybe("")

_pw_maybe(p) if lower(p) in _users

_pw_maybe(p) if regex.match(_weak_re, p)

_pw_pairs(line, kind) := {p |
	some p in _all_pairs(line, kind)
	_pw_key(p[0])
	_pw_maybe(p[1])
}

# A password key whose account sits beside it.
_hit(lines, i, line, kind) if {
	regex.match(`(?i)pass|pwd`, line)
	some p in _pw_pairs(line, kind)
	some u in _near_users(lines, i, kind)
	_pw_ok(u, p[1])
}

# The key itself names the root account: MYSQL_ROOT_PASSWORD=root.
_hit(_, _, line, kind) if {
	regex.match(`(?i)root[_.\-]?(?:password|passwd|pwd|pass)`, line)
	some p in _pw_pairs(line, kind)
	regex.match(`(?i)root[_.\-]?(?:password|passwd|pwd|pass)$`, p[0])
	p[1] != ""
	_pw_ok("root", p[1])
}

_comment(line) if helpers.is_comment_line(line)

_comment(line) if startswith(trim_space(line), "<!--")

_comment(line) if startswith(trim_space(line), ";")

# ── Evaluation ─────────────────────────────────────────────────────────────
# Per-line builtins over every line of every file cost more than the rule's
# whole budget, so a file is split only when it writes a default account name
# where a value goes (plain substring tests, no regex over the content).
_user_needles := [
	`"admin"`, `'admin'`, `=admin`, `: admin`, `"root"`, `'root'`, `=root`, `: root`,
	`"sa"`, `'sa'`, `=sa`, `: sa`, `"guest"`, `'guest'`, `=guest`, `: guest`,
	`"postgres"`, `'postgres'`, `=postgres`, `: postgres`, `"elastic"`, `'elastic'`, `: elastic`,
	`"tomcat"`, `'tomcat'`, `"pi"`, `'pi'`, `"oracle"`, `'oracle'`, `"system"`, `'system'`,
	`"mysql"`, `'mysql'`, `//admin:`, `//root:`, `//guest:`, `//postgres:`, `//sa:`, `//elastic:`,
	`"administrator"`, `'administrator'`, `ROOT_PASS`, `root_pass`, `RootPass`, `rootPass`,
	`"Admin"`, `"ADMIN"`, `"Root"`, `"root:`, `"admin:`, `"postgres:`, `'root:`,
]

_has_user(content) if {
	some n in _user_needles
	contains(content, n)
}

findings contains finding if {
	some path, content in input.file_contents
	kind := _kind(path)
	_has_user(content)
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`pass|Pass|PASS|pwd|PWD|://|["']\s*,\s*["']`, line)
	count(line) < 2000
	not _comment(line)
	_hit(lines, i, line, kind)
	finding := {
		"rule_id": metadata.id,
		"message": "Default account configured with a default or guessable password (admin/admin, root/root, guest/guest, sa with no password): it is the first pair an attacker tries. Rename or disable the default account and give it a unique generated secret from a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
