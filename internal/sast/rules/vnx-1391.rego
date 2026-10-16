# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1391

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1391",
	"name": "Use of Weak Credentials: trivially guessable password literal",
	"description": "A password is set to a value from the top of every password-guessing wordlist: an all-digit string of four or more digits (123456, 0000, 12345678), a keyboard walk (qwerty, qwertyuiop, asdf, asdfghjkl, zxcvbn, 1q2w3e4r, 1qaz2wsx, 123qwe), a common word list entry (letmein, welcome, iloveyou, monkey, dragon, sunshine, trustno1, football, baseball, master, abc123, abcd1234, abcdef, aaaaaa), or a default word with a short digit/symbol suffix (password1, password123, passw0rd, p@ssw0rd, admin123, admin321, root1, test123, guest1, demo1, changeme1, secret1), matched case-insensitively. Reported when the value is assigned to a name that ends in password, passwd, pwd, passphrase or _pass, or their _confirmation form (a variable, constant, field, keyword argument, object/dict/hash/JSON key, XML attribute or C# property initialiser) in Python, JavaScript/TypeScript, Go, Java, PHP, Ruby and C#; when it is a bare value of such a key in YAML, docker-compose, .env, .properties, .ini, .conf, .cfg and .toml files or a Dockerfile ENV/ARG; and when it is the fallback of an environment or configuration lookup of a password name (os.environ.get(\"DB_PASSWORD\", \"123456\"), process.env.X_PASSWORD || \"qwerty\", ${DB_PASSWORD:-password1}). Not reported: the bare vendor defaults (password, admin, root, changeme, ... are VNX-1393), a weak password set for a default account (email: admin above password: admin123, MYSQL_ROOT_PASSWORD=admin321, User Id=sa;Password=123456), which is reported by VNX-1392 as a default credential pair so the line is reported once, any other literal, comparisons (password == \"123456\"), labels and field names, the literal as the start of a concatenation, the text inside a longer string or a comment, test, spec, fixture and docs paths, translation catalogues, and config templates (.example, .sample, .template, .dist). Password-length policies are VNX-521; hard-coded passwords in general are VNX-SEC-014 and VNX-259.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1391/",
	"languages": ["python", "node", "go", "java", "php", "ruby", "csharp", "docker"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1391],
	"capec": ["CAPEC-16"],
	"attack_technique": ["T1110.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["weak-credential", "credentials", "cwe-1391"],
}

_weak_re := `(?i)^(?:[0-9]{4,}|(?:password|passw0rd|p@ssw0rd|p@ssword|pass|admin|root|test|user|guest|demo|qwerty|welcome|letmein|changeme|secret|master)[0-9!@#$.]{1,4}|qwerty(?:uiop)?|asdf(?:gh(?:jkl)?)?|zxcvbnm?|abc123|abcd1234|123abc|1q2w3e(?:4r)?|1qaz2wsx|123qwe|qwe123|letmein|welcome|iloveyou|monkey|dragon|sunshine|trustno1|football|baseball|master|abcdef|aaaaaa|passw0rd|p@ssw0rd|p@ssword)$`

_bad_value(v) if regex.match(_weak_re, v)


# ── Files ──────────────────────────────────────────────────────────────────

_code_re := `\.(?:py|js|jsx|mjs|cjs|ts|tsx|go|java|php|rb|cs|config|xml|json)$`

_cfg_re := `(?:\.(?:ya?ml|env|properties|ini|conf|cfg|toml)|(?:^|/)\.env)$`

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(?i)(?:^|/)(?:docs?|locales?|i18n|lang|translations?)/`, path)

_skip(path) if regex.match(`(?i)\.(?:example|sample|template|tmpl|dist|min\.js|lock)$`, path)

_skip(path) if regex.match(`(?i)(?:^|/)package(?:-lock)?\.json$`, path)

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

_docker_re := `(?i)(?:^|/)[^/]*(?:dockerfile|containerfile)[^/]*$`

# ── Password-named keys ────────────────────────────────────────────────────

_pw_key(key) if {
	k := lower(key)
	regex.match(`(?:password|passwd|pwd|passphrase)(?:[_.\-]?confirm(?:ation)?)?$|(?:^|[_.\->])pass$`, k)
	not regex.match(`(?:field|param|column|attr|label|input|selector|placeholder|hint|title|text|msg|message|error|route|path|url|name|type|policy|reset|forgot)[_.\-]?(?:password|passwd|pwd|pass)$`, k)
}

# key ['"]? op 'value' (+)? ; op is captured so comparisons can be rejected.
_kv_re := `([A-Za-z_$][\w$.\->]*)['"]?\s*\]?\s*(===|!==|==|!=|=>|:=|=|:)\s*(?:"([^"\n]{0,64})"|'([^'\n]{0,64})')(\s*\+)?`

# C# auto-property initialiser: public string AdminPassword { get; set; } = "admin";
_cs_prop_re := `\b(\w+)\s*\{[^}]*\}\s*=\s*"([^"\n]{0,64})"\s*;`

# Environment / configuration lookups with a fallback value.
_env_re := `(?:getenv|environ\.get|\benv|fetch|\bget)\(\s*['"]([\w.\-]+)['"]\s*,\s*['"]([^'"\n]*)['"]\s*\)`

_js_env_re := `process\.env(?:\.(\w+)|\[\s*['"](\w+)['"]\s*\])\s*(?:\|\||\?\?)\s*['"]([^'"\n]*)['"]`

_sh_default_re := `\$\{([\w.\-]+)(?::-?|-)([^}\s]*)\}`

# Unquoted config value: KEY: value / KEY=value / - KEY=value / export KEY=value.
_cfg_kv_re := `^\s*(?:-\s*)?(?:export\s+)?['"]?([\w.\-]+)['"]?\s*[:=]\s*([^\s'"#,;{}\[\]]+)\s*(?:[#;].*)?$`

# A key inside a longer string literal ("never set password = 'admin'") is
# prose. Count the quotes before the key, ignoring the key's own opening quote.
_outside_string(line, whole) if {
	idx := indexof(line, whole)
	idx >= 0
	prefix := trim_right(substring(line, 0, idx), `'"[`)
	count(indexof_n(prefix, `"`)) % 2 == 0
	count(indexof_n(prefix, "'")) % 2 == 0
}

_hit(line, _) if {
	some m in regex.find_all_string_submatch_n(_kv_re, line, -1)
	not m[2] in {"===", "!==", "==", "!="}
	m[5] == ""
	_pw_key(m[1])
	_bad_value(concat("", [m[3], m[4]]))
	_outside_string(line, m[0])
}

_hit(line, _) if {
	some m in regex.find_all_string_submatch_n(_cs_prop_re, line, -1)
	_pw_key(m[1])
	_bad_value(m[2])
}

_hit(line, _) if {
	some m in regex.find_all_string_submatch_n(_env_re, line, -1)
	_pw_key(m[1])
	_bad_value(m[2])
}

_hit(line, _) if {
	some m in regex.find_all_string_submatch_n(_js_env_re, line, -1)
	_pw_key(concat("", [m[1], m[2]]))
	_bad_value(m[3])
}

_hit(line, _) if {
	some m in regex.find_all_string_submatch_n(_sh_default_re, line, -1)
	_pw_key(m[1])
	_bad_value(m[2])
}

_hit(line, "cfg") if {
	some m in regex.find_all_string_submatch_n(_cfg_kv_re, line, 1)
	_pw_key(m[1])
	_bad_value(m[2])
}

# Dockerfile: ENV KEY=value / ENV KEY value / ARG KEY=value
_hit(line, "docker") if {
	some m in regex.find_all_string_submatch_n(`^\s*(?:ENV|ARG)\s+(\w+)(?:\s*=\s*|\s+)["']?([^\s'"]+)["']?\s*$`, line, 1)
	_pw_key(m[1])
	_bad_value(m[2])
}

_cheap(content) if contains(content, "ass")

_cheap(content) if contains(content, "ASS")

_cheap(content) if contains(content, "wd")

_cheap(content) if contains(content, "WD")

_comment(line) if helpers.is_comment_line(line)

_comment(line) if startswith(trim_space(line), "<!--")

_comment(line) if startswith(trim_space(line), ";")

# File gate: one regex per key spelling, each with a literal prefix so the
# regexp engine skips straight to the candidates (a (?i) alternation has no
# prefix and costs several times more). The value must start after a
# delimiter, as it does in every shape _hit accepts.
_tail_re := `[^\n]*[ \t=:(,"'\x60>-][ \t]*(?i:[0-9]{4}|qwe|asdf|zxcv|abc|123|1q|letmein|welcome|iloveyou|monkey|dragon|sunshine|trustno|football|baseball|master|aaaa|passw0rd|p@ss|(?:password|pass|admin|root|test|user|guest|demo|changeme|secret)[0-9!@#$.])`

_file_gate_res := [concat("", ["(?m)", k, _tail_re]) | some k in ["pass", "Pass", "PASS", "pwd", "Pwd", "PWD"]]

_file_gate(content) if {
	some re in _file_gate_res
	regex.match(re, content)
}

_line_gate_re := concat("", [`(?m)^[^\n]*(?i:pass|pwd)`, _tail_re, `[^\n]*$`])

# The gated lines with their 0-based numbers, found by one multi-line regex
# over the file rather than a regex per line.
_gated_lines(content) := {[line, i] |
	_file_gate(content)
	some line in {m[0] | some m in regex.find_all_string_submatch_n(_line_gate_re, content, -1)}
	some idx in indexof_n(content, line)
	_line_start(content, idx)
	i := count(indexof_n(substring(content, 0, idx), "\n"))
}

_line_start(_, 0)

_line_start(content, idx) if {
	idx > 0
	substring(content, idx - 1, 1) == "\n"
}

# ── Lines VNX-1392 reports ─────────────────────────────────────────────────
# A password next to the default account it unlocks (admin/admin, an admin
# account with admin123, MYSQL_ROOT_PASSWORD=root) is one defect, a default
# credential pair, and VNX-1392 reports that line. These are VNX-1392's own
# conditions (its file and line gates, keyed pairs, root-named keys, URL
# user-info and connection strings), copied so the line is reported once and
# only ever skipped here when VNX-1392 does report it. Keep them in step.

_p_users := {"admin", "administrator", "root", "sa", "guest", "postgres", "elastic", "tomcat", "pi", "oracle", "system", "mysql"}

_p_defaults := {
	"password", "admin", "administrator", "root", "toor", "changeme", "changeit", "change_me",
	"default", "guest", "secret", "postgres", "mysql", "oracle", "manager", "tomcat", "raspberry",
}

_p_weak_re := `(?i)^(?:[0-9]{4,}|(?:password|passw0rd|p@ssw0rd|p@ssword|pass|admin|root|test|user|guest|demo|qwerty|welcome|letmein|changeme|secret|master)[0-9!@#$.]{1,4}|qwerty(?:uiop)?|asdf(?:gh(?:jkl)?)?|zxcvbnm?|abc123|abcd1234|123abc|1q2w3e(?:4r)?|1qaz2wsx|123qwe|qwe123|letmein|welcome|iloveyou|monkey|dragon|sunshine|trustno1|football|baseball|master|abcdef|aaaaaa|s3cret|passw0rd|p@ssw0rd|p@ssword)$`

_p_pw_ok(_, p) if p in _p_defaults

_p_pw_ok(_, p) if regex.match(_p_weak_re, p)

_p_pw_ok(u, p) if {
	p != ""
	lower(p) == u
}

_p_pw_ok(u, "") if u in {"root", "sa"}

_p_pw_key(key) if {
	k := lower(key)
	regex.match(`(?:password|passwd|pwd|passphrase)$|(?:^|[_.\->])pass$`, k)
	not regex.match(`(?:field|param|column|attr|label|input|selector|placeholder|hint|title|text|msg|message|error|route|path|url|name|type|policy|reset|forgot)[_.\-]?(?:password|passwd|pwd|pass)$`, k)
}

_p_user_key(key) if regex.match(`(?i)(?:^|[_.\->])(?:user|username|user_name|login|email|account|uid)$|(?:^|[a-z])(?:User|Username|UserName|Login)$`, key)

_p_cred_key(k) if _p_pw_key(k)

_p_cred_key(k) if _p_user_key(k)

_p_kv_re := `([A-Za-z_$][\w$.\->]*)['"]?\]?\s*(===|!==|==|!=|=>|:=|=|:)\s*(?:"([^"\n]{0,64})"|'([^'\n]{0,64})')(\s*\+)?`

_p_cfg_kv_re := `^\s*(?:-\s*)?(?:export\s+)?['"]?([\w.\-]+)['"]?\s*[:=]\s*([^\s'"#,;{}\[\]]*)\s*(?:[#;].*)?$`

_p_docker_kv_re := `^\s*(?:ENV|ARG)\s+(\w+)(?:\s*=\s*|\s+)["']?([^\s'"]*)["']?\s*$`

_p_pairs(line) := {[m[1], concat("", [m[3], m[4]])] |
	some m in regex.find_all_string_submatch_n(_p_kv_re, line, -1)
	_p_cred_key(m[1])
	not m[2] in {"===", "!==", "==", "!="}
	m[5] == ""
	_outside_string(line, m[0])
}

_p_cfg_pairs(line, "cfg") := {[m[1], m[2]] | some m in regex.find_all_string_submatch_n(_p_cfg_kv_re, line, 1)}

_p_cfg_pairs(line, "docker") := {[m[1], m[2]] | some m in regex.find_all_string_submatch_n(_p_docker_kv_re, line, 1)}

_p_cfg_pairs(_, "code") := set()

_p_all_pairs(line, kind) := _p_pairs(line) | _p_cfg_pairs(line, kind)

_p_user_vals(line, kind) := {lower(v) |
	some p in _p_all_pairs(line, kind)
	_p_user_key(p[0])
	v := p[1]
	lower(v) in _p_users
}

_p_xml_user_vals(line) := {lower(m[1]) |
	contains(line, "<user")
	some m in regex.find_all_string_submatch_n(`<user\b[^>]*\bname\s*=\s*"([^"]*)"`, line, 1)
	lower(m[1]) in _p_users
}

_p_own_password(l) if regex.match(`(?i)(?:password|passwd|pwd|_pass)['"]?\]?\s*(?:=>|:=|=|:)`, l)

_p_own_password(l) if contains(l, "<user")

_p_near_users(lines, i, kind) := _p_user_vals(lines[i], kind) | _p_xml_user_vals(lines[i]) | {u |
	some j in numbers.range(max([0, i - 3]), min([count(lines) - 1, i + 3]))
	j != i
	l := lines[j]
	not helpers.is_comment_line(l)
	not _p_own_password(l)
	some u in _p_user_vals(l, kind)
}

_p_pw_maybe(p) if p in _p_defaults

_p_pw_maybe("")

_p_pw_maybe(p) if lower(p) in _p_users

_p_pw_maybe(p) if regex.match(_p_weak_re, p)

_p_pw_pairs(line, kind) := {p |
	some p in _p_all_pairs(line, kind)
	_p_pw_key(p[0])
	_p_pw_maybe(p[1])
}

_p_hit(_, _, line, _) if {
	contains(line, "://")
	contains(line, "@")
	some m in regex.find_all_string_submatch_n(`\b[a-zA-Z][\w+.\-]*://([^:/@\s'"]+):([^@/\s'"]*)@`, line, -1)
	u := lower(m[1])
	u in _p_users
	_p_pw_ok(u, m[2])
}

_p_hit(_, _, line, _) if {
	contains(line, ";")
	some um in regex.find_all_string_submatch_n(`(?i)(?:^|[;"'\s])(?:user\s?id|uid|user|username)\s*=\s*([^;"'\s]+)\s*;`, line, 1)
	u := lower(um[1])
	u in _p_users
	some pm in regex.find_all_string_submatch_n(`(?i)(?:^|[;"'\s])(?:password|pwd)\s*=\s*([^;"'\s]*)\s*(?:;|["']|$)`, line, 1)
	_p_pw_ok(u, pm[1])
}

_p_hit(lines, i, line, kind) if {
	regex.match(`(?i)pass|pwd`, line)
	some p in _p_pw_pairs(line, kind)
	some u in _p_near_users(lines, i, kind)
	_p_pw_ok(u, p[1])
}

_p_hit(_, _, line, kind) if {
	regex.match(`(?i)root[_.\-]?(?:password|passwd|pwd|pass)`, line)
	some p in _p_pw_pairs(line, kind)
	regex.match(`(?i)root[_.\-]?(?:password|passwd|pwd|pass)$`, p[0])
	p[1] != ""
	_p_pw_ok("root", p[1])
}

_p_user_needles := [
	`"admin"`, `'admin'`, `=admin`, `: admin`, `"root"`, `'root'`, `=root`, `: root`,
	`"sa"`, `'sa'`, `=sa`, `: sa`, `"guest"`, `'guest'`, `=guest`, `: guest`,
	`"postgres"`, `'postgres'`, `=postgres`, `: postgres`, `"elastic"`, `'elastic'`, `: elastic`,
	`"tomcat"`, `'tomcat'`, `"pi"`, `'pi'`, `"oracle"`, `'oracle'`, `"system"`, `'system'`,
	`"mysql"`, `'mysql'`, `//admin:`, `//root:`, `//guest:`, `//postgres:`, `//sa:`, `//elastic:`,
	`"administrator"`, `'administrator'`, `ROOT_PASS`, `root_pass`, `RootPass`, `rootPass`,
	`"Admin"`, `"ADMIN"`, `"Root"`, `"root:`, `"admin:`, `"postgres:`, `'root:`,
]

_p_has_user(content) if {
	some n in _p_user_needles
	contains(content, n)
}

_reported_by_1392(content, i, line, kind) if {
	_p_has_user(content)
	regex.match(`pass|Pass|PASS|pwd|PWD|://|["']\s*,\s*["']`, line)
	count(line) < 2000
	_p_hit(split(content, "\n"), i, line, kind)
}

findings contains finding if {
	some path, content in input.file_contents
	kind := _kind(path)
	_cheap(content)
	not _skip(path)
	some gl in _gated_lines(content)
	line := gl[0]
	i := gl[1]
	not _comment(line)
	_hit(line, kind)
	not _reported_by_1392(content, i, line, kind)
	finding := {
		"rule_id": metadata.id,
		"message": "Password set to a trivially guessable value from the top of every password wordlist. Generate a long random secret per deployment and load it from a secrets manager or the environment",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Call shapes that set a password without an assignment ──────────────────

# Setter: cfg.setPassword("postgres"), ds.setKeyStorePassword("changeit").
_hit(line, "code") if {
	some m in regex.find_all_string_submatch_n(`\bset\w*(?:Password|Passwd|Pwd|Passphrase)\s*\(\s*["']([^"'\n]{0,64})["']\s*\)`, line, -1)
	_bad_value(m[1])
	_outside_string(line, m[0])
}

# Keyed call: props.setProperty("password", "x"), define('DB_PASSWORD', 'x'),
# os.environ.setdefault("DB_PASSWORD", "x"), localStorage.setItem(...).
_hit(line, "code") if {
	some m in regex.find_all_string_submatch_n(`\b(?:setProperty|put|setenv|putenv|define|setdefault|setItem)\s*\(\s*["']([\w.\-]+)["']\s*,\s*["']([^"'\n]{0,64})["']\s*\)`, line, -1)
	_pw_key(m[1])
	_bad_value(m[2])
	_outside_string(line, m[0])
}

# Command-line flag defaults: argparse/click/optparse and Go flag/pflag.
_hit(line, "code") if {
	some m in regex.find_all_string_submatch_n(`\b(?:add_argument|option|add_option)\(\s*(?:["']-[\w-]*["']\s*,\s*)?["']-{1,2}([\w-]+)["'][^)\n]*?\bdefault\s*=\s*["']([^"'\n]{0,64})["']`, line, -1)
	_pw_key(m[1])
	_bad_value(m[2])
}

_hit(line, "code") if {
	some m in regex.find_all_string_submatch_n(`\.String(?:Var)?\((?:&[\w.]+\s*,\s*)?"([\w.\-]+)"\s*,\s*"([^"\n]{0,64})"`, line, -1)
	_pw_key(m[1])
	_bad_value(m[2])
}

_hit(line, "code") if {
	some m in regex.find_all_string_submatch_n(`\.String(?:Var)?P\((?:&[\w.]+\s*,\s*)?"([\w.\-]+)"\s*,\s*"\w?"\s*,\s*"([^"\n]{0,64})"`, line, -1)
	_pw_key(m[1])
	_bad_value(m[2])
}

# Connection string: "Host=db;Username=app;Password=changeme;".
_hit(line, _) if {
	regex.match(`(?i)(?:^|[;"'])\s*(?:server|host|data source|database|initial catalog|user id|uid|username|user)\s*=`, line)
	some m in regex.find_all_string_submatch_n(`(?i)(?:^|[;"'])\s*(?:password|pwd)\s*=\s*([^;"'\s]{0,64})\s*(?:;|["']|$)`, line, -1)
	_bad_value(m[1])
}
