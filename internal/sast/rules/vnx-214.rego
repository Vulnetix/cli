# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_214

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-214",
	"name": "Invocation of Process Using Visible Sensitive Information",
	"description": "A password, token or secret is passed to a child process on its command line, where every local user can read it (ps, /proc/<pid>/cmdline, process accounting, audit logs and crash reports). Reported in Python (subprocess.run/call/check_call/check_output/Popen, os.system/popen, pexpect.spawn, asyncio subprocesses), JavaScript/TypeScript (child_process exec/execSync/execFile/spawn/fork, execa), Go (exec.Command/CommandContext) and Java (ProcessBuilder, Runtime.exec): a credential flag (--password, --passwd, --pass, --secret, --token, --api-key, --client-secret, --access-token, --auth-token, also --db-password and similar) whose value is a variable, by concatenation, interpolation (f-string, template literal, %s, .format) or as the next list element; mysql/mysqldump/mysqladmin/mariadb -p<value> built from a variable; and sshpass -p <variable>; also mysql -p<value> on a line whose binary is named up to four lines above (ProcessStartInfo FileName = \"mysqldump\" / Arguments = ...), and, inside the exec call, redis-cli -a <variable>, openssl pass:<value>, npm :_authToken=<value>, and a URL argument carrying the password (postgresql://{user}:{password}@host). The command may be built on a line above and passed by name. In shell scripts, Makefiles and Dockerfiles: mysql-family -p\"$VAR\", --password=\"$VAR\" and the other credential flags with a $ value, sshpass -p \"$VAR\", docker login -p/--password \"$VAR\", curl -u user:$VAR, openssl -pass/-passin/-passout pass:$VAR, redis-cli -a $VAR, npm config set ...:_authToken=$VAR, kubectl create secret --from-literal=password=$VAR (any key naming a password, secret, token or key), aws configure set aws_secret_access_key/aws_session_token $VAR, htpasswd -b <file> <user> $VAR, and psql/pg_dump/mongo/redis-cli/mysql/git/curl/wget given a URL with $VAR as its password. Not reported: a connection URL built for a library driver rather than a command, credentials passed through the environment (MYSQL_PWD, PGPASSWORD, env=, openssl pass env:/file:), stdin (--password-stdin, input=), a file (--password-file, --defaults-extra-file, sshpass -f/-e), a bare -p that prompts, -p meaning port or parents (docker run -p, ssh -p, mkdir -p), literal credentials in shell scripts (VNX-BASH-005 reports those), comments and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-214/",
	"languages": ["node", "python", "go", "java", "php", "csharp", "bash", "docker"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [214],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["visible-sensitive-info", "command-line", "process-arguments", "cwe-214"],
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Credential passed on a process command line: any local user can read it from ps or /proc/<pid>/cmdline, and it lands in audit logs. Pass it through the environment (MYSQL_PWD, PGPASSWORD), stdin (--password-stdin) or a protected file instead",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_ext(path, exts) if {
	some e in exts
	endswith(path, e)
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

_base(path) := lower(regex.replace(path, `^.*/`, ""))

# ── Credential arguments built in program code ───────────────────────────

_flag := `--(?:[\w]+-)?(?:password|passwd|pass|secret|token|api-key|apikey|client-secret|access-token|auth-token)`

# A value that is not a literal: interpolation ({x}, ${x}, $x, {0}),
# concatenation (" + x, '. $x), or a format verb.
_val := "(?:\\{[^}]|[\"']?\\$\\{|[\"'`]\\s*\\+|[\"']\\s*\\.\\s*\\$|%s|%v|%\\(|\\{\\})"

# PHP double-quoted strings interpolate $name too.
_val_php := "(?:\\{[^}]|[\"']?\\$[\\w{]|[\"'`]\\s*\\+|[\"']\\s*\\.\\s*\\$|%s|%v|%\\(|\\{\\})"

_valre("php") := _val_php

_valre(lang) := _val if lang != "php"

_mysql := `\b(mysql|mysqldump|mysqladmin|mariadb|mariadb-dump|mysqlimport|mysqlshow|mysqlcheck)\b`

_code_gate := `--(?:[\w]+-)?(?:password|passwd|pass|secret|token|api-key|apikey|client-secret|access-token|auth-token)|sshpass|mysql|mariadb`

# A credential flag and its dynamic value on one line: the line that builds
# the command is the finding, wherever it is later executed.
_line_cred(l, lang) if regex.match(concat("", [_flag, `(?:=|\s*)`, _valre(lang)]), l)

_line_cred(l, lang) if {
	regex.match(_mysql, l)
	regex.match(concat("", ["(?:\\s|[\"'`])-p", _valre(lang)]), l)
}

_line_cred(l, lang) if {
	contains(l, "sshpass")
	regex.match(concat("", ["\\s-p\\s*", _valre(lang)]), l)
}

# Inside an exec call, also a credential flag followed by a variable as the
# next list element: ["--token", tok], ("sshpass", "-p", pw).
_cred_arg_core(txt, lang) if _line_cred(txt, lang)

_cred_arg_core(txt, _) if regex.match(concat("", ["[\"'`]", _flag, "[\"'`]\\s*,\\s*[A-Za-z_$]"]), txt)

_cred_arg_core(txt, _) if {
	contains(txt, "sshpass")
	regex.match("[\"'`]-p[\"'`]\\s*,\\s*[A-Za-z_$]", txt)
}

# redis-cli -a <password>, as a list element or in a command string.
_cred_arg_core(txt, lang) if {
	contains(txt, "redis-cli")
	regex.match(concat("", ["[\"'`]-a[\"'`]\\s*,\\s*[A-Za-z_$]|\\s-a\\s+", _valre(lang)]), txt)
}

# openssl -pass/-passin/-passout pass:<value>.
_cred_arg_core(txt, lang) if {
	contains(txt, "pass:")
	regex.match(concat("", ["\\bpass:", _valre(lang)]), txt)
}

# npm's //registry/:_authToken=<value> passed as an argument.
_cred_arg_core(txt, lang) if {
	contains(txt, "_auth")
	regex.match(concat("", [":_(authToken|auth|password)=", _valre(lang)]), txt)
}

_cred_arg(txt, lang) if _cred_arg_core(txt, lang)

# Credentials inside a URL argument: postgresql://{user}:{password}@host.
_url_cred(txt) if {
	contains(txt, "://")
	regex.match("://[^\\s/:@\"'`]*:(\\{[^}\\s]+\\}|\\$\\{[^}\\s]+\\}|\\$\\w+|%s|%\\(\\w+\\)s|[\"'`]\\s*\\+\\s*[\\w.]+\\s*\\+\\s*[\"'`])@", txt)
}

_cred_arg(txt, _) if _url_cred(txt)

# mysql -p<value> on a line whose binary is named on a nearby line
# (FileName = "mysqldump"; Arguments = $"-u{u} -p{p}").
_split_mysql(lines, i, lang) if {
	regex.match(concat("", ["(?:\\s|[\"'`])-p", _valre(lang)]), lines[i])
	some k in numbers.range(max([0, i - 4]), min([count(lines) - 1, i + 2]))
	regex.match(concat("", ["[\"'`]", _mysql]), lines[k])
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	_ext(path, {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
	not endswith(path, ".min.js")
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "cs" if endswith(path, ".cs")

_exec := {
	"py": `\b(subprocess|sp)\.(run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(|\bos\.(system|popen|spawn\w*|exec\w*)\s*\(|\bpexpect\.(spawn|run)\s*\(|\bcreate_subprocess_(exec|shell)\s*\(|(^|[^\w.])(check_output|check_call|Popen)\s*\(`,
	"js": `(^|[^\w.]|\bchild_process\.|\bcp\.|\)\.)(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork|execa|execaSync|execaCommand)\s*\(`,
	"go": `\bexec\.Command(Context)?\s*\(`,
	"java": `\bnew\s+ProcessBuilder\s*\(|\.exec\s*\(|\.command\s*\(`,
	"php": `(^|[^\w>:$])(exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec)\s*\(|\bnew\s+Process\s*\(|\bProcess::fromShellCommandline\s*\(`,
	"cs": `\bProcess\.Start\s*\(|\bnew\s+ProcessStartInfo\s*\(|\.Arguments\s*=|\.ArgumentList\.Add\s*\(`,
}

_pd(l) := count(split(l, "(")) - count(split(l, ")")) + count(split(l, "[")) - count(split(l, "]"))

# Lines i..end of the call opened on line i (at most 8), comments dropped.
_call_lines(lines, i) := ls if {
	last := min([count(lines) - 1, i + 8])
	ends := [j |
		some j in numbers.range(i, last)
		sum([_pd(lines[k]) | some k in numbers.range(i, j)]) <= 0
	]
	e := min(array.concat([last], ends))
	ls := [l | some k in numbers.range(i, e); l := lines[k]; not helpers.is_comment_line(l)]
}

# A line that prints, logs or raises a message: "continue with --page-token %s"
# tells a person what to type next, it is not a command line being built.
# (fmt.Sprintf is not here: it is how a Go command string is built.)
_message_line(line) if regex.match(`\bFprint\w*\(\s*os\.Std(?:err|out)\b|\bfmt\.(?:Print\w*|Errorf)\(|\b(?:log|logger|logging|slog)\.\w+\(|\bconsole\.(?:log|error|warn|info|debug)\(|(?:^|[^\w.])print\(|\berrors\.New\(|\braise\s+\w+\(|\bthrow\s+new\s+\w+\(|\bSystem\.(?:out|err)\.print`, line)

_any_line_cred(ls, lang) if {
	some l in ls
	_line_cred(l, lang)
}

findings contains f if {
	some path, content in input.file_contents
	_lang(path)
	_has_any(content, {"--", "sshpass", "mysql", "mariadb"})
	regex.match(_code_gate, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "-")
	_maybe_cred(line)
	not helpers.is_comment_line(line)
	_line_cred(line, _lang(path))
	not _message_line(line)
	f := _finding(path, i, line)
}

findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, {"mysql", "mariadb"})
	_has_any(content, _exec_file[lang])
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "-p")
	not helpers.is_comment_line(line)
	not _line_cred(line, lang)
	_split_mysql(lines, i, lang)
	f := _finding(path, i, line)
}

findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _exec_file[lang])
	_has_any(content, {"--", "sshpass", "mysql", "mariadb", "redis-cli", "pass:", "_auth", "://"})
	regex.match(concat("|", [_code_gate, `redis-cli|\bpass:|:_auth|://[^\s/:@"']*:[^\s@]*@`]), content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _exec_needles[lang])
	not helpers.is_comment_line(line)
	regex.match(_exec[lang], line)
	ls := _call_lines(lines, i)
	not _any_line_cred(ls, lang)
	_reported(lines, i, concat("\n", ls), lang)
	f := _finding(path, i, line)
}

_reported(_, _, txt, lang) if _cred_arg(txt, lang)

# args = [..., "--token", tok] on a line above, passed to the call by name.
_reported(lines, i, txt, lang) if {
	not _cred_arg(txt, lang)
	some a in numbers.range(max([0, i - 6]), i - 1)
	al := lines[a]
	not helpers.is_comment_line(al)
	v := helpers.assigned_first(al)
	als := _call_lines(lines, a)
	not _any_line_cred(als, lang)
	_cred_arg_core(concat("\n", als), lang)
	regex.match(concat("", [`(^|[^\w.])`, v, `\b`]), txt)
}


# ── Shell scripts, Makefiles and Dockerfiles ─────────────────────────────

_shell(path) if _ext(lower(path), {".sh", ".bash", ".zsh", ".ksh", ".mk"})

_shell(path) if _base(path) in {"makefile", "gnumakefile"}

_shell(path) if regex.match(`^(dockerfile|containerfile)([._-].*)?$|\.(dockerfile|containerfile)$`, _base(path))

_sh_var := "[\"']?\\$"

_sh_cred(line) if regex.match(concat("", [_mysql, `[^|;&#\n]*\s-p`, _sh_var]), line)

_sh_cred(line) if regex.match(concat("", [_flag, `(?:=|\s+)`, _sh_var]), line)

_sh_cred(line) if regex.match(concat("", [`\bsshpass\s+(-\w+\s+)*-p\s*`, _sh_var]), line)

_sh_cred(line) if regex.match(concat("", [`\bdocker\s+login\b[^|;&#\n]*\s(-p|--password)(=|\s+)`, _sh_var]), line)

_sh_cred(line) if regex.match(`\bcurl\b[^|;&#\n]*\s(-u|--user)(=|\s+)["']?[^\s"':]*:\$`, line)

_sh_cred(line) if regex.match(concat("", [`\bopenssl\b[^|;&#\n]*\s-pass(in|out)?\s+["']?pass:`, _sh_var]), line)

_sh_cred(line) if regex.match(concat("", [`\bredis-cli\b[^|;&#\n]*\s-a\s+`, _sh_var]), line)

_sh_cred(line) if regex.match(concat("", [`\bnpm\s+config\s+set\s+\S*:_(authToken|auth|password)=`, _sh_var]), line)

# A client given a URL with the password in it: psql "postgresql://u:$PW@h/db".
_sh_cred(line) if regex.match(`\b(psql|pg_dump|pg_dumpall|pg_restore|pg_basebackup|mongo|mongosh|mongodump|mongorestore|mongoimport|mongoexport|redis-cli|mysql|mysqldump|mariadb|amqp-\w+|git|curl|wget)\s[^|;&#\n]*://[^\s/:@"']*:["']?\$\{?\w+\}?["']?@`, line)

# kubectl create secret ... --from-literal=password=$VAR.
_sh_cred(line) if regex.match(`\bkubectl\s+create\s+secret\b[^|;&#\n]*--from-literal[= ]["']?[\w.-]*(?i:pass|pwd|secret|token|key|credential)[\w.-]*=["']?\$`, line)

# aws configure set aws_secret_access_key $VAR (or aws_session_token).
_sh_cred(line) if regex.match(`\baws\s+configure\s+set\s+[\w.]*(secret_access_key|session_token)\s+["']?\$`, line)

# htpasswd -b<flags> <file> <user> $VAR: batch mode takes the password as an argument.
_sh_cred(line) if regex.match(`\bhtpasswd\s+-[a-zA-Z]*b[a-zA-Z]*\s+\S+\s+\S+\s+["']?\$`, line)

findings contains f if {
	some path, content in input.file_contents
	_shell(path)
	contains(content, "$")
	_has_any(content, {"-p", "--", "-u", "-a", "pass:", "_auth", "://", "configure set", "htpasswd"})
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "$")
	_maybe_sh(line)
	not helpers.is_comment_line(line)
	_sh_cred(line)
	f := _finding(path, i, line)
}

# Cheap per-line prefilters, so the regular expressions run on few lines.
_maybe_cred(line) if {
	contains(line, "--")
	_has_any(line, {"pass", "Pass", "PASS", "secret", "Secret", "token", "Token", "key", "Key"})
}

_maybe_cred(line) if {
	contains(line, "-p")
	_has_any(line, {"mysql", "mariadb", "sshpass"})
}

_exec_needles := {
	"py": {"subprocess", "os.", "sp.", "pexpect", "Popen", "check_"},
	"js": {"exec", "spawn", "fork"},
	"go": {"exec.Command"},
	"java": {"ProcessBuilder", "exec(", ".command("},
	"php": {"exec", "system", "passthru", "popen", "Process"},
	"cs": {"Process", "Arguments"},
}

_maybe_sh(line) if _maybe_cred(line)

_maybe_sh(line) if {
	contains(line, "-p")
	contains(line, "docker")
}

_maybe_sh(line) if {
	contains(line, "curl")
	_has_any(line, {"-u", "--user"})
}

_exec_file := {
	"py": {"subprocess", "os.system", "os.popen", "os.spawn", "os.exec", "pexpect", "create_subprocess"},
	"js": {"child_process", "execa"},
	"go": {"os/exec"},
	"java": {"ProcessBuilder", "Runtime"},
	"php": {"exec(", "system(", "passthru(", "popen(", "proc_open(", "Process"},
	"cs": {"System.Diagnostics", "Process"},
}

_maybe_sh(line) if contains(line, "pass:")

_maybe_sh(line) if {
	contains(line, "redis-cli")
	contains(line, "-a")
}

_maybe_sh(line) if contains(line, ":_auth")

_maybe_sh(line) if contains(line, "--from-literal")

_maybe_sh(line) if contains(line, "configure set")

_maybe_sh(line) if contains(line, "htpasswd")

_maybe_sh(line) if {
	contains(line, "://")
	contains(line, "@")
}

# cmd = [..., f"--dbname=postgresql://{user}:{password}@host/db"] on a line above,
# passed to the call by name: the line that builds the URL is the finding.
findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _exec_file[lang])
	contains(content, "://")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _exec_needles[lang])
	not helpers.is_comment_line(line)
	regex.match(_exec[lang], line)
	txt := concat("\n", _call_lines(lines, i))
	not _url_cred(txt)
	some a in numbers.range(max([0, i - 8]), i - 1)
	al := lines[a]
	not helpers.is_comment_line(al)
	v := helpers.assigned_first(al)
	als := _call_lines(lines, a)
	regex.match(concat("", [`(^|[^\w.])`, v, `\b`]), txt)
	some b, bl in als
	_url_cred(bl)
	f := _finding(path, a + b, bl)
}
