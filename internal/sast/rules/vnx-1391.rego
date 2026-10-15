# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1391

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1391",
	"name": "Use of Weak Credentials: trivially guessable password literal",
	"description": "A password is set to a value from the top of every password-guessing wordlist: an all-digit string of four or more digits (123456, 0000, 12345678), a keyboard walk (qwerty, qwertyuiop, asdf, asdfghjkl, zxcvbn, 1q2w3e4r, 1qaz2wsx, 123qwe), a common word list entry (letmein, welcome, iloveyou, monkey, dragon, sunshine, trustno1, football, baseball, master, abc123, abcd1234, abcdef, aaaaaa), or a default word with a short digit/symbol suffix (password1, password123, passw0rd, p@ssw0rd, admin123, admin321, root1, test123, guest1, demo1, changeme1, secret1), matched case-insensitively. Reported when the value is assigned to a name that ends in password, passwd, pwd, passphrase or _pass, or their _confirmation form (a variable, constant, field, keyword argument, object/dict/hash/JSON key, XML attribute or C# property initialiser) in Python, JavaScript/TypeScript, Go, Java, PHP, Ruby and C#; when it is a bare value of such a key in YAML, docker-compose, .env, .properties, .ini, .conf, .cfg and .toml files or a Dockerfile ENV/ARG; and when it is the fallback of an environment or configuration lookup of a password name (os.environ.get(\"DB_PASSWORD\", \"123456\"), process.env.X_PASSWORD || \"qwerty\", ${DB_PASSWORD:-password1}). Not reported: the bare vendor defaults (password, admin, root, changeme, ... are VNX-1393; default user/password pairs are VNX-1392), any other literal, comparisons (password == \"123456\"), labels and field names, the literal as the start of a concatenation, the text inside a longer string or a comment, test, spec, fixture and docs paths, translation catalogues, and config templates (.example, .sample, .template, .dist). Password-length policies are VNX-521; hard-coded passwords in general are VNX-SEC-014 and VNX-259.",
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
