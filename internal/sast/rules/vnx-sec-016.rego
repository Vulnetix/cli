package vulnetix.rules.vnx_sec_016

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-SEC-016",
	"name": "TLS verification disabled in shell command",
	"description": "A command or tool configuration turns off TLS certificate verification, so a man-in-the-middle can serve anything over the connection. Reported, in shell scripts (by extension or shebang), Dockerfiles, Makefiles, justfiles and YAML (CI pipelines): a curl command with -k, --insecure or a short-flag cluster containing k (-sSLk, -fsk), and a wget command with --no-check-certificate, including a command continued over several lines with a trailing backslash, behind sudo/env/VAR= prefixes, in $(...) and after &&, ; or |, a quoted shell step (Jenkins sh 'curl -k ...', YAML run: \"curl --insecure ...\", bash -c \"...\") and the Dockerfile exec form RUN [\"curl\", \"-k\", ...]; git config http.sslVerify false and git -c http.sslVerify=false; GIT_SSL_NO_VERIFY=1/true, NODE_TLS_REJECT_UNAUTHORIZED=0 and PYTHONHTTPSVERIFY=0 (export, ENV, YAML env); npm/yarn/pnpm config set strict-ssl false; pip --trusted-host; kubectl/helm/oc --insecure-skip-tls-verify; kubeconfig and APIService insecure-skip-tls-verify / insecureSkipTLSVerify: true and Ansible validate_certs: no/false in YAML; PowerShell Invoke-WebRequest/Invoke-RestMethod -SkipCertificateCheck and curl.exe -k in .ps1 scripts. Also .wgetrc check_certificate = off, .curlrc insecure, .npmrc/.yarnrc strict-ssl=false, pip.conf / requirements.txt trusted-host and .gitconfig sslVerify = false; and, in application code, a string literal that is a curl or wget command line carrying those flags, or an argv list [\"curl\", \"-k\", ...] (subprocess, os.system, execSync). Not reported: wget -k (--convert-links), -k belonging to another command in the pipeline (sort -k 2), curl -K (config file) and --key, --cacert, verification set back to true, a flag held in a variable or matched in a case statement, echo/printf text, test scripts, comments and documentation.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-016/",
	"languages": [],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["tls", "curl", "wget", "shell"],
}

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(?i)\.min\.js$|(^|/)(node_modules|vendor)/|\.(md|markdown|rst|adoc)$`, path)

# ── File classes ────────────────────────────────────────────────────────
_shellish(path, _) if regex.match(`(?i)\.(sh|bash|zsh|ksh|mk|ya?ml|dockerfile|containerfile|ps1|psm1)$|(^|/)(Dockerfile|Containerfile)[^/]*$|(^|/)(GNUmakefile|[Mm]akefile|[Jj]ustfile|\.justfile|Jenkinsfile)$`, path)

_shellish(path, content) if {
	not regex.match(`\.[A-Za-z0-9]+$`, path)
	regex.match(`^#!\s*\S*(/|env\s+)(ba|z|k|da)?sh\b`, content)
}

_code(path) if regex.match(`\.(py|js|jsx|mjs|cjs|ts|tsx|rb|go|java|kt|php|cs|pl|groovy)$`, path)

_gate_words := ["curl", "wget", "sslverify", "ssl_no_verify", "tls_reject_unauthorized", "httpsverify", "strict-ssl", "trusted-host", "insecure-skip-tls-verify", "check_certificate", "insecure", "validate_certs", "skipcertificatecheck"]

_gate(content) if {
	lc := lower(content)
	some w in _gate_words
	contains(lc, w)
}

# ── curl / wget commands ────────────────────────────────────────────────
_cmd_re := `^\s*(?:(?:RUN|run:|script:|-|!|if|then|do|else|elif|while|until|\{|\(|@|exec|sudo|command|time|nohup|env|xargs)\s+(?:-\S+\s+)*)*(?:[A-Za-z_]\w*=\S*\s+)*(?:\S*/)?(curl|wget)(?:\.exe)?(?:\s|$)`

_insecure_flag_re := `(?:^|\s)(?:--insecure(?:\s|$)|-[A-Za-z]*k[A-Za-z]*(?:\s|$)|--no-check-certificate(?:\s|$))`

# The statement line i ends: earlier lines joined while they end with a backslash.
_stmt_start(lines, i) := min([j |
	some j in numbers.range(max([0, i - 8]), i)
	not _broken(lines, j, i)
])

# Some line in j..i-1 does not end with a backslash, so j is not part of
# the statement that line i ends.
_broken(lines, j, i) if {
	j < i
	some k in numbers.range(j, i - 1)
	not regex.match(`\\\s*$`, lines[k])
}

_statement(lines, i) := concat(" ", [regex.replace(l, `\\\s*$`, "") |
	some k in numbers.range(_stmt_start(lines, i), i)
	l := lines[k]
])

_unquote(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'[^']*'`, `""`)

_curl_insecure(lines, i, line) if {
	regex.match(_insecure_flag_re, _unquote(line))
	stmt := _unquote(_statement(lines, i))
	some seg in regex.split(`\|\|?|;|&&|\$\(|\x60|\)`, stmt)
	m := regex.find_all_string_submatch_n(_cmd_re, seg, 1)
	count(m) > 0
	regex.match(_tool_flag_re[m[0][1]], seg)
}

# wget -k is --convert-links, not an insecure switch: only curl's short k counts.
_tool_flag_re := {
	"curl": `(?:^|\s)(?:--insecure(?:\s|$)|-[A-Za-z]*k[A-Za-z]*(?:\s|$))`,
	"wget": `(?:^|\s)--no-check-certificate(?:\s|$)`,
}

# A curl/wget command inside a quoted shell step: Jenkins sh '...', a quoted
# YAML run: "...", bash -c "...".
_q_prefix := `^\s*(?:-\s+)?(?:(?:ba)?sh\s+-c\s+|(?:sh|bash|bat)\b\s*\(?\s*(?:script:\s*)?|run:\s*|script:\s*|-\s+)?["']\s*(?:sudo\s+)?(?:\S*/)?`

_quoted_cmd(line) if regex.match(concat("", [_q_prefix, `curl(?:\.exe)?(?:\s[^"']*?)?\s(?:--insecure|-[A-Za-z]*k[A-Za-z]*)(?:\s|["']|$)`]), line)

_quoted_cmd(line) if regex.match(concat("", [_q_prefix, `wget(?:\s[^"']*?)?\s--no-check-certificate(?:\s|["']|$)`]), line)

# Exec-form argv: RUN ["curl", "-k", ...], ["wget", "--no-check-certificate"].
_argv(line) if regex.match(`["'](?:\S*/)?curl["']\s*,(?:\s*["'][^"']*["']\s*,)*?\s*["'](?:-[A-Za-z]*k[A-Za-z]*|--insecure)["']`, line)

_argv(line) if regex.match(`["'](?:\S*/)?wget["']\s*,(?:\s*["'][^"']*["']\s*,)*?\s*["']--no-check-certificate["']`, line)

# YAML: kubeconfig / APIService skip-verify, Ansible validate_certs off.
_yaml_other(path, line) if {
	regex.match(`(?i)\.ya?ml$`, path)
	regex.match(`^\s*-?\s*(?:insecure-skip-tls-verify|insecureSkipTLSVerify)\s*:\s*["']?true["']?\s*$`, line)
}

_yaml_other(path, line) if {
	regex.match(`(?i)\.ya?ml$`, path)
	regex.match(`(?:^\s*-?\s*validate_certs\s*:\s*["']?(?:no|false|False|FALSE|n|0)["']?\s*$)|\svalidate_certs=(?:no|false|False)(?:\s|$)`, line)
}

# PowerShell -SkipCertificateCheck on Invoke-WebRequest / Invoke-RestMethod.
_ps_other(path, line) if {
	regex.match(`(?i)\.ps[md]?1$`, path)
	regex.match(`(?i)\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^#\n]*\s-SkipCertificateCheck(?::\$true)?(?:\s|$)`, _unquote(line))
}

# ── Other tools and environment ─────────────────────────────────────────
_shell_other(line) if regex.match(`(?i)\bgit\b[^#\n]*\bhttp\.sslverify\s*[= ]\s*["']?false\b`, line)

_shell_other(line) if regex.match(`(?:^|[\s;&|{])(?:export\s+|ENV\s+)?GIT_SSL_NO_VERIFY["']?\s*[=:\s]\s*["']?(?:1|true|yes|TRUE|True)["']?(?:\s|$|;)`, line)

_shell_other(line) if regex.match(`(?:^|[\s;&|{])(?:export\s+|ENV\s+)?NODE_TLS_REJECT_UNAUTHORIZED["']?\s*[=:\s]\s*["']?0["']?(?:\s|$|;)`, line)

_shell_other(line) if regex.match(`(?:^|[\s;&|{])(?:export\s+|ENV\s+)?PYTHONHTTPSVERIFY["']?\s*[=:\s]\s*["']?0["']?(?:\s|$|;)`, line)

_shell_other(line) if regex.match(`\b(?:npm|yarn|pnpm)\s+config\s+set\s+strict-ssl\s+false\b`, line)

_shell_other(line) if regex.match(`(?:^|[\s;&|(])(?:\S*/)?(?:pip3?|python3?\s+-m\s+pip|uv\s+pip)\s[^#\n]*--trusted-host[\s=]`, line)

_shell_other(line) if regex.match(`\bpip3?\s+config\s+set\s+\S*trusted-host\b`, line)

_shell_other(line) if regex.match(`(?:^|[\s;&|(])(?:\S*/)?(?:kubectl|helm|oc)\s[^#\n]*--(?:kube-)?insecure-skip-tls-verify(?:=true)?(?:\s|$)`, line)

_rc_file(path, line) if {
	regex.match(`(^|/)\.?wgetrc$`, path)
	regex.match(`(?i)^\s*check_certificate\s*=\s*(off|0|no|false)\s*$`, line)
}

_rc_file(path, line) if {
	regex.match(`(^|/)[._]?curlrc$`, path)
	regex.match(`^\s*(?:--)?(?:insecure|-k|k)\s*$`, line)
}

_rc_file(path, line) if {
	regex.match(`(^|/)\.(npmrc|yarnrc)$`, path)
	regex.match(`(?i)^\s*strict-ssl\s*[=:\s]\s*["']?false["']?\s*$`, line)
}

_rc_file(path, line) if {
	regex.match(`(?i)(^|/)pip\.(conf|ini)$`, path)
	regex.match(`(?i)^\s*trusted-host\s*=\s*\S`, line)
}

_rc_file(path, line) if {
	regex.match(`(?i)(^|/)[^/]*requirements[^/]*\.(txt|in)$|(^|/)constraints[^/]*\.txt$`, path)
	regex.match(`^\s*--trusted-host[\s=]\s*\S`, line)
}

_rc_file(path, line) if {
	regex.match(`(^|/)\.gitconfig$|(^|/)\.git/config$`, path)
	regex.match(`(?i)^\s*sslverify\s*=\s*false\s*$`, line)
}

# ── A curl / wget command line in an application string ────────────────
_exec_string(line) if regex.match(`["'\x60](?:\S*/)?curl(?:\s[^"'\x60]*?)?(?:--insecure\b|\s-[A-Za-z]*k[A-Za-z]*(?:\s|["'\x60]))`, line)

_exec_string(line) if regex.match(`["'\x60](?:\S*/)?wget(?:\s[^"'\x60]*?)?--no-check-certificate\b`, line)

_reported("shell", _, lines, i, line) if _curl_insecure(lines, i, line)

_reported("shell", _, _, _, line) if _shell_other(line)

_reported("shell", _, _, _, line) if _quoted_cmd(line)

_reported("shell", _, _, _, line) if _argv(line)

_reported("shell", path, _, _, line) if _yaml_other(path, line)

_reported("shell", path, _, _, line) if _ps_other(path, line)

_reported("rc", path, _, _, line) if _rc_file(path, line)

_reported("code", _, _, _, line) if _exec_string(line)

_rc_path(path) if regex.match(`(?i)(^|/)(\.?wgetrc|[._]?curlrc|\.npmrc|\.yarnrc|pip\.(conf|ini)|[^/]*requirements[^/]*\.(txt|in)|constraints[^/]*\.txt|\.gitconfig|\.git/config)$`, path)

# One class per file, decided once.
_class(path, content) := "rc" if {
	_rc_path(path)
} else := "shell" if {
	_shellish(path, content)
} else := "code" if {
	_code(path)
	_mentions_downloader(content)
}

findings contains finding if {
	some path, content in input.file_contents
	cls := _class(path, content)
	not _skip(path)
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	_line_candidate(line)
	not _comment(cls, line)
	not _print_line(cls, line)
	_reported(cls, path, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "TLS certificate verification disabled; remove -k/--insecure/--no-check-certificate (or the equivalent setting) and trust the server's CA with --cacert or the system store instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A shell line starting with -- is an option of a continued command, not a
# SQL comment.
_comment(cls, line) if {
	cls != "code"
	regex.match(`^\s*[#;]`, line)
}

_comment("code", line) if helpers.is_comment_line(line)

# echo/printf only print text; a setting named inside is prose, not a command.
_print_line("shell", line) if {
	regex.match(`^\s*(?:echo|printf)\s`, line)
	not regex.match(`[|;&]\s*(?:sudo\s+)?(?:curl|wget|git|npm|pip|kubectl)\b`, line)
}

_mentions_downloader(content) if contains(content, "curl ")

_mentions_downloader(content) if contains(content, "wget ")

_line_candidate(line) if regex.match(`(?i)curl|wget|insecure|\s-[a-z]*k|ssl|tls|trusted|check_certificate|httpsverify|validate_certs|skipcertificatecheck|\\\s*$`, line)

# The argv-list form: ["curl", "-sS", "-k", url].
_exec_string(line) if _argv(line)
