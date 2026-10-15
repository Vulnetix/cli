package vulnetix.rules.vnx_bash_002

import rego.v1

metadata := {
	"id": "VNX-BASH-002",
	"name": "Downloaded script executed without an integrity check",
	"description": "Reports a shell script that runs code it has just downloaded with curl or wget without verifying it: the download piped into an interpreter (curl ... | bash, | sudo -E bash -s --, | VAR=x sh -, | /bin/sh, | python3 -, | perl, | ruby, | node, | php, | sudo -u user bash), through intermediate filters (| tee log | sh, | base64 -d | sh), including a pipeline continued over several lines; passed to one as a command or process substitution (bash -c \"$(curl ...)\", bash <(curl ...), source <(wget -qO- ...), eval \"$(curl ...)\"); or saved to a file (-o, -O or a > redirect) that the next lines run (bash file, sh file, ./file) with no sha256sum/shasum/gpg/cosign/minisign/openssl dgst check in between. Not reported: a download piped to a non-interpreter (tar, jq, gpg --dearmor, sha256sum, tee, grep, shellcheck, shfmt), a download that is verified before it runs, a binary or archive that is downloaded but not executed here, local files or generated output piped to a shell, the command inside a string, assignment, echo/printf, comment or usage here-document. Shell files are .sh, .bash, .bats, .ksh, .zsh and extensionless files with a sh/bash/dash/ksh/zsh shebang; Dockerfile RUN lines and CI workflow files are not covered by this rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-002/",
	"languages": ["bash", "shell"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [494, 829],
	"capec": ["CAPEC-310"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["curl", "wget", "pipe-to-shell", "bash", "supply-chain"],
}

# ── Which files are shell scripts ───────────────────────────────────────

_shell_exts := [".sh", ".bash", ".bats", ".ksh", ".zsh"]

_is_shell(path, _) if {
	some ext in _shell_exts
	endswith(path, ext)
}

_is_shell(path, content) if {
	regex.match(`(^|/)[^/.]+$`, path)
	not regex.match(`(^|/)(gradlew|mvnw)$`, path)
	regex.match(`^#![ \t]*(\S*/)?(env[ \t]+(-\S+[ \t]+)*)?(ba|da|k|z|mk)?sh(\s|$)`, content)
}

_comment(line) if startswith(trim_space(line), "#")

# Quoted strings holding no command substitution are text: the pipeline
# inside INSTALL_HINT="curl ... | bash" or echo "curl ... | sh" never runs.
_strip_re := `"(?:[^"\\$]|\\.|\$[^("])*\$?"|'[^']*'`

# A line that prints rather than runs.
_prose(line) if regex.match(`^\s*(echo|printf|log\w*|info|warn\w*|error|die|usage|msg|say)\b`, line)

_fetch_re := `(?:^|[\s;&|({!])(?:command\s+|sudo\s+(?:-\S+\s+)*)?(?:\S*/)?(curl|wget)\s`

_interp := `(?:\S*/)?(?:bash|sh|zsh|ksh|dash|ash|python[0-9.]*|perl|ruby|node|php)(?:\s|$)`

# curl/wget output piped into an interpreter, optionally through sudo, env
# and VAR=value prefixes.
_pipe_re := concat("", [`\b(curl|wget)\s[^|;]*(?:\|[^|;&]+)*?\|\s*(?:sudo(?:\s+(?:-[ugCDhRT]\s+[^-\s]\S*|-\S+))*\s+)?(?:env(?:\s+-\S+)*\s+)?(?:\w+=\S*\s+)*`, _interp])

# The download is the code an interpreter runs: -c "$(curl ...)", <(curl ...),
# eval "$(curl ...)".
_subst_re := concat("", [
	`\b(?:bash|sh|zsh|ksh|dash)\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*c\s+"?\$\(\s*(?:command\s+)?(?:curl|wget)\s`,
	`|(?:\b(?:bash|sh|zsh|ksh|dash|source|python[0-9.]*|perl|ruby)|(?:^|[;&|]\s*)\.)\s+(?:-\S+\s+)*<\(\s*(?:command\s+)?(?:curl|wget)\s`,
	`|\beval\s+"?\$\(\s*(?:command\s+)?(?:curl|wget)\s`,
])

# ── The statement a line starts ─────────────────────────────────────────

_continues(l) if regex.match(`(\\|\||&&)\s*$`, l)

_statement(lines, i) := concat(" ", [regex.replace(l, `\\\s*$`, "") |
	some l in array.slice(lines, i, _stmt_end(lines, i) + 1)
])

# The statement ends on the first line (at most five on) that does not
# continue onto the next one.
_stmt_end(lines, i) := e if {
	last := min([count(lines) - 1, i + 5])
	stops := [k | some k in numbers.range(i, last); not _joins(lines, k)]
	e := min(array.concat(stops, [last]))
}

_joins(lines, m) if _continues(lines[m])

_joins(lines, m) if {
	m + 1 < count(lines)
	regex.match(`^\s*\|`, lines[m + 1])
}

# ── Download to a file, then run that file ──────────────────────────────

_tok_re := `"(?:[^"\\]|\\.)*"|'[^']*'|[;&|]+|[^\s;&|"']+`

_unquote(t) := trim(t, "\"'")

_tokens(line) := [_unquote(m[0]) | some m in regex.find_all_string_submatch_n(_tok_re, line, -1)]

_url_name(line) := n if {
	m := regex.find_all_string_submatch_n(`https?://[^\s"'?#]+`, line, 1)
	count(m) > 0
	parts := split(trim_right(m[0][0], "/"), "/")
	n := parts[count(parts) - 1]
	count(parts) > 3
}

# The file a download line writes.
_saved_flag(line) := f if {
	regex.match(`\bcurl\s`, line)
	m := regex.find_all_string_submatch_n(`\s(?:-[A-Za-z]*o|--output)(?:\s+|=)("[^"]+"|'[^']+'|[^\s;&|]+)`, line, 1)
	count(m) > 0
	f := _unquote(m[0][1])
}

_saved_flag(line) := f if {
	regex.match(`\bcurl\s`, line)
	not regex.match(`\s(?:-[A-Za-z]*o|--output)(?:\s+|=)`, line)
	regex.match(`\s(?:-[A-Za-z]*O|--remote-name)(\s|$)`, line)
	f := _url_name(line)
}

_saved_flag(line) := f if {
	regex.match(`\bwget\s`, line)
	m := regex.find_all_string_submatch_n(`\s(?:-[A-Za-z]*O|--output-document)(?:\s*=?\s*)("[^"]+"|'[^']+'|[^\s;&|]+)`, line, 1)
	count(m) > 0
	f := _unquote(m[0][1])
}

_saved_flag(line) := f if {
	regex.match(`\bwget\s`, line)
	not regex.match(`\s(?:-[A-Za-z]*O|--output-document)`, line)
	f := _url_name(line)
}

# The file a download line writes: a shell redirect wins over a flag (wget
# -qO- URL > file writes the file, not stdout).
_saved(line) := f if {
	f := _saved_redirect(line)
} else := g if {
	g := _saved_flag(line)
}

# curl URL > file, wget -qO- URL > file
_saved_redirect(line) := f if {
	regex.match(`\b(curl|wget)\s`, line)
	m := regex.find_all_string_submatch_n(`\b(?:curl|wget)\s[^|;&>]*\s>\s*("[^"]+"|'[^']+'|[^\s;&|]+)`, line, 1)
	count(m) > 0
	f := _unquote(m[0][1])
}

_same_file(t, f) if t == f

_same_file(t, f) if t == concat("", ["./", f])

_same_file(t, f) if f == concat("", ["./", t])

_is_interp(t) if regex.match(`^(\S*/)?(bash|sh|zsh|ksh|dash|python[0-9.]*|perl|ruby|node|php|source|\.)$`, t)

# Line tokens run file f: an interpreter given f, or f in command position.
_runs(ts, f) if {
	some k, t in ts
	_is_interp(t)
	_dot_is_command(ts, k, t)
	some m, a in ts
	m > k
	m <= k + 4
	_same_file(a, f)
	every q in array.slice(ts, k + 1, m) {
		startswith(q, "-")
	}
}

# `.` sources a file only as a command word; elsewhere (jq . out.json, find .)
# it is an argument.
_dot_is_command(_, _, t) if t != "."

_dot_is_command(ts, k, ".") if _command_position(ts, k)

_runs(ts, f) if {
	some k, t in ts
	_same_file(t, f)
	_command_position(ts, k)
}

_command_position(_, 0)

_command_position(ts, k) if {
	k > 0
	regex.match(`^([;&|]+|sudo|then|do|exec)$`, ts[k - 1])
}

_verify_re := `\b(sha(1|224|256|384|512)sum|shasum|md5sum|b2sum|gpg2?|gpgv|cosign|minisign|signify|slsa-verifier|sigstore\S*|rpm\s+-K)\b|\bopenssl\s+dgst\b`

_runs_unverified(lines, i, f) := j if {
	f != "-"
	f != ""
	some j in numbers.range(i, min([count(lines) - 1, i + 12]))
	l := lines[j]
	not _comment(l)
	contains(l, _base(f))
	ts := _after_download(l, i, j)
	_runs(ts, f)
	not _verified_between(lines, i, j)
}

_base(f) := b if {
	parts := split(f, "/")
	b := parts[count(parts) - 1]
}

# On the download line itself only what follows the download can run it.
_after_download(l, i, j) := array.slice(ts, k + 1, count(ts)) if {
	i == j
	ts := _tokens(l)
	k := min([q | some q, t in ts; regex.match(`^[;&|]+$`, t)])
}

_after_download(l, i, j) := _tokens(l) if j != i

_verified_between(lines, i, j) if {
	some k in numbers.range(i, j)
	not _comment(lines[k])
	regex.match(_verify_re, lines[k])
}

# ── Here-documents shown as text ────────────────────────────────────────

_heredocs(lines) := [[s, e] |
	some s, l in lines
	contains(l, "<<")
	not _comment(l)
	m := regex.find_all_string_submatch_n(`(?:^|[^<])<<-?\s*(?:'([A-Za-z_][\w-]*)'|"([A-Za-z_][\w-]*)"|\\?([A-Za-z_][\w-]*))`, l, 1)
	count(m) > 0
	not regex.match(`\b(bash|sh|zsh|ksh|dash|ssh|su|sudo|exec|eval|source)\b`, regex.replace(l, _strip_re, ""))
	delim := concat("", [m[0][1], m[0][2], m[0][3]])
	ends := [j |
		some j in numbers.range(s + 1, min([s + 2000, count(lines) - 1]))
		trim_space(lines[j]) == delim
	]
	count(ends) > 0
	e := ends[0]
]

_in_text_heredoc(docs, i) if {
	some d in docs
	d[0] < i
	i < d[1]
}

_docs(content, lines) := _heredocs(lines) if contains(content, "<<")

_docs(content, _) := [] if not contains(content, "<<")

# ── Findings ────────────────────────────────────────────────────────────

_message := "Code downloaded with curl/wget is executed without an integrity check, so whoever controls the server, DNS or network path runs commands here; download to a file, verify a pinned checksum or signature (sha256sum -c, gpg --verify, cosign verify-blob), then run it"

_candidate(lines, docs, i, line) if {
	regex.match(`(curl|wget)\s`, line)
	not _comment(line)
	not _prose(line)
	not _in_text_heredoc(docs, i)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_shell(path, content)
	regex.match(`(curl|wget)\s`, content)
	lines := split(content, "\n")
	docs := _docs(content, lines)
	some i, line in lines
	_candidate(lines, docs, i, line)
	j := _report_line(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}

# piped into an interpreter (the pipeline may continue on later lines)
_report_line(lines, i, _) := i if {
	stmt := regex.replace(_statement(lines, i), _strip_re, "\"\"")
	regex.match(_fetch_re, stmt)
	regex.match(_pipe_re, stmt)
}

# run as a command or process substitution
_report_line(_, i, line) := i if {
	regex.match(_subst_re, regex.replace(line, _strip_re, "\"\""))
}

# saved to a file that is then run unverified
_report_line(lines, i, line) := j if {
	regex.match(_fetch_re, regex.replace(line, _strip_re, "\"\""))
	f := _saved(line)
	j := _runs_unverified(lines, i, f)
}
