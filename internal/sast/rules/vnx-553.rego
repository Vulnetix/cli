# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_553

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-553",
	"name": "Command Shell in Externally Accessible Directory",
	"description": "A command shell is reachable over HTTP. Three shapes are reported. A deployment step (Dockerfile, shell script, YAML pipeline, Makefile, Vagrantfile, PowerShell) that copies, links or installs a shell interpreter (/bin/sh, bash, dash, zsh, ksh, csh, cmd.exe, powershell.exe) into a web-served directory (cgi-bin, /var/www, htdocs, public_html, wwwroot, inetpub, nginx/html, webapps). An Apache ScriptAlias that maps a URL onto /bin, /usr/bin, /sbin or a shell binary. And a CGI program that runs its request as a command, which is a web shell: a shell script that evals, sh -c's or executes $QUERY_STRING (or a variable assigned from it), a Perl CGI that passes param() or $ENV{QUERY_STRING} to system/exec/qx/backticks/a piped open, and a Python CGI that passes cgi.FieldStorage values, parse_qs results or QUERY_STRING to os.system, os.popen, eval/exec or subprocess with a string command or shell=True. Not reported: copying a CGI script (not a shell) into cgi-bin, linking a shell outside the web root, CGI programs that only compare the query string against fixed cases or print it, subprocess calls with a fixed argument list, reading the SHELL environment variable, comments and quoted prose.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-553/",
	"languages": ["bash", "docker", "perl", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [553],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["web-shell", "cgi", "cwe-553"],
}

# ── Shape 1: a shell interpreter copied into the web root ────────────────

_deploy_file(path) if {
	base := lower(regex.replace(path, `^.*/`, ""))
	regex.match(`(dockerfile|containerfile|vagrantfile|makefile|\.sh$|\.bash$|\.ya?ml$|\.ps1$|\.bat$|\.cmd$|\.mk$|\.rb$)`, base)
}

_shell_bin := `/(?:usr/(?:local/)?)?s?bin/(?:ba|da|z|k|c|tc|a|fi|mk)?sh\b`

_web_dir := `(?i)(?:cgi-bin|/var/www|htdocs|public_html|wwwroot|inetpub|nginx/html|/webapps/|/srv/www)`

_copy_re := concat("", [
	`(?:^|[\s;&|])(?:cp|ln|install|mv|rsync|COPY|ADD)\s+(?:--?[\w-]+(?:=\S+)?\s+(?:[0-7]{3,4}\s+)?)*`,
	_shell_bin,
	`\s+(?:--?[\w-]+\s+)*\S*`,
	_web_dir,
])

_win_copy_re := `(?i)(?:copy|xcopy|copy-item|move-item|robocopy)\s+.*\\(?:cmd|powershell|pwsh)\.exe\b.*(?:inetpub|wwwroot|cgi-bin)`

findings contains finding if {
	some path, content in input.file_contents
	_deploy_file(path)
	regex.match(`(?i)cgi-bin|/var/www|htdocs|public_html|wwwroot|inetpub|nginx/html|webapps|/srv/www`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`sh\b|\.exe`, line)
	not helpers.is_comment_line(line)
	_copies_shell(line)
	finding := _finding(path, i, line, "A shell interpreter is placed in a web-served directory, where any visitor can run it as a CGI program. Remove it; serve only the scripts the site needs")
}

_copies_shell(line) if regex.match(_copy_re, line)

_copies_shell(line) if regex.match(_win_copy_re, line)

# Ansible/Salt style copy: src=/bin/bash dest=/usr/lib/cgi-bin/x on one line.
_copies_shell(line) if regex.match(_kv_copy_re, line)

_kv_copy_re := concat("", [
	`\bsrc\s*[=:]\s*["']?`, _shell_bin, `["']?\s.*\bdest\s*[=:]\s*["']?\S*`, _web_dir,
])

# The same module written as a YAML mapping, src: and dest: on nearby lines.
findings contains finding if {
	some path, content in input.file_contents
	regex.match(`\.ya?ml$`, path)
	regex.match(`(?m)^\s*src\s*:\s*["']?/(?:usr/(?:local/)?)?s?bin/(?:ba|da|z|k|c|tc|a|fi|mk)?sh["']?\s*$`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(concat("", [`^\s*src\s*:\s*["']?`, _shell_bin, `["']?\s*$`]), line)
	some j in numbers.range(max([0, i - 4]), min([count(lines) - 1, i + 4]))
	regex.match(concat("", [`^\s*dest\s*:\s*["']?\S*`, _web_dir]), lines[j])
	finding := _finding(path, i, line, "A shell interpreter is placed in a web-served directory, where any visitor can run it as a CGI program. Remove it; serve only the scripts the site needs")
}

# ── Shape 2: ScriptAlias onto a binary directory ─────────────────────────

_server_conf(path) if endswith(path, ".conf")

_server_conf(path) if endswith(path, ".htaccess")

findings contains finding if {
	some path, content in input.file_contents
	_server_conf(path)
	contains(content, "ScriptAlias")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ScriptAlias")
	regex.match(`^\s*ScriptAlias(?:Match)?\s+\S+\s+"?/(?:usr/(?:local/)?)?s?bin(?:/(?:(?:ba|da|z|k)?sh)?)?"?\s*$`, line)
	finding := _finding(path, i, line, "ScriptAlias maps a URL onto a directory of system binaries, exposing a command shell over HTTP")
}

# ── Shape 3: a CGI program that runs its request (a web shell) ───────────

_shell_script(path) if regex.match(`\.(sh|bash|cgi)$`, path)

_shell_script(path) if {
	regex.match(`(^|/)cgi-bin/[^/.]+$`, path)
}

_sh_taint(lines, i) := {v |
	some j in numbers.range(max([0, i - 30]), i - 1)
	contains(lines[j], "QUERY_STRING")
	m := regex.find_all_string_submatch_n(`^\s*(?:export\s+|local\s+|readonly\s+)?([A-Za-z_]\w*)=`, lines[j], 1)
	count(m) > 0
	v := m[0][1]
}

_cmd_pos := `(?:^\s*|[;&|]\s*|\$\(\s*|\bthen\s+|\bdo\s+)`

_sh_sink(line, _) if {
	regex.match(concat("", [_cmd_pos, `(?:eval\s|(?:ba|da|z|k)?sh\s+-c\s)[^#]*\$\{?QUERY_STRING`]), line)
}

_sh_sink(line, _) if regex.match(`^\s*"?\$\{?QUERY_STRING\b`, line)

_sh_sink(line, tainted) if {
	some v in tainted
	regex.match(concat("", [_cmd_pos, `(?:eval\s|(?:ba|da|z|k)?sh\s+-c\s)[^#]*\$\{?`, v, `\b`]), line)
}

_sh_sink(line, tainted) if {
	some v in tainted
	regex.match(concat("", [`^\s*"?\$\{?`, v, `\b`]), line)
	not regex.match(concat("", [`^\s*"?\$\{?`, v, `\}?"?\s*=`]), line)
}

_sh_sink(line, tainted) if {
	some v in tainted
	regex.match(concat("", ["`\\s*\"?\\$\\{?", v, `\b`]), line)
}

findings contains finding if {
	some path, content in input.file_contents
	_shell_script(path)
	contains(content, "QUERY_STRING")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\$|eval|sh\s+-c`, line)
	not helpers.is_comment_line(line)
	_sh_sink(line, _sh_taint(lines, i))
	finding := _finding(path, i, line, "CGI script executes its query string as a command: this is a web shell reachable by any visitor")
}

# Perl CGI.
_perl(path) if regex.match(`\.(cgi|pl|pm)$`, path)

_perl_src := `\$ENV\{\s*['"]?QUERY_STRING|\bparam\s*\(|->\s*param\s*\(|->\s*url_param\s*\(`

_perl_sink := "\\bsystem\\s*\\(|\\bsystem\\s+[\"'$]|\\bexec\\s*\\(|\\bqx\\s*[\\(\\{/|]|`|\\bopen\\s*\\([^)]*\\|"

_perl_taint(lines, i) := {v |
	some j in numbers.range(max([0, i - 30]), i - 1)
	regex.match(_perl_src, lines[j])
	m := regex.find_all_string_submatch_n(`^\s*(?:my\s+|our\s+|local\s+)?\$(\w+)\s*=`, lines[j], 1)
	count(m) > 0
	v := m[0][1]
}

_perl_hit(line, _) if regex.match(_perl_src, line)

_perl_hit(line, tainted) if {
	some v in tainted
	regex.match(concat("", [`\$`, v, `\b`]), line)
}

findings contains finding if {
	some path, content in input.file_contents
	_perl(path)
	regex.match(_perl_src, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_perl_sink, line)
	not helpers.is_comment_line(line)
	_perl_hit(line, _perl_taint(lines, i))
	finding := _finding(path, i, line, "CGI program passes request input to a shell command: this is a web shell reachable by any visitor")
}

# Python CGI.
_py_src := `\.getvalue\s*\(|\.getfirst\s*\(|\.getlist\s*\(|\bform\s*\[|QUERY_STRING|parse_qs\w*\s*\(`

_py_sink := `\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output|check_call|getoutput|getstatusoutput)|commands\.getoutput|eval|exec)\s*\(`

_py_cgi(path, content) if {
	endswith(path, ".py")
	regex.match(`cgi\.FieldStorage|QUERY_STRING`, content)
}

_py_cgi(path, _) if endswith(path, ".cgi")

_py_shell_form(line) if not regex.match(`\(\s*\[`, line)

_py_shell_form(line) if regex.match(`shell\s*=\s*True`, line)

_py_hit(line, _) if regex.match(_py_src, line)

_py_hit(line, tainted) if {
	some v in tainted
	regex.match(concat("", [`\(\s*[^)]*\b`, v, `\b`]), line)
}

findings contains finding if {
	some path, content in input.file_contents
	_py_cgi(path, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_py_sink, line)
	not helpers.is_comment_line(line)
	_py_shell_form(line)
	_py_hit(line, helpers.tainted_names(lines, i, 30, _py_src))
	finding := _finding(path, i, line, "CGI program passes request input to a shell command: this is a web shell reachable by any visitor")
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
