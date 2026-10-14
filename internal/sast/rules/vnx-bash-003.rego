package vulnetix.rules.vnx_bash_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-BASH-003",
	"name": "Failure ignored in a script without set -e / set -u",
	"description": "In an executable shell script (one with a sh/bash/dash/ksh/zsh shebang) that does not enable errexit (set -e, set -o errexit, a -e shebang flag or an ERR trap), reports the three places where a silently ignored failure does damage: a bare cd or pushd that is not checked (no || exit, &&, if, or $? test) followed within ten lines by a delete that uses a relative path (rm ./*, rm -rf build, find . -delete, git clean -f, git reset --hard), so the delete runs in the wrong directory when the cd fails; an integrity check (sha256sum/shasum/md5sum -c, gpg --verify, gpgv, cosign verify, minisign -V, openssl dgst -verify) run as a bare statement whose result nothing reads, so a failed check still installs the artifact; and, when nounset (set -u) is also off, rm -r of \"$VAR/...\" where VAR can be empty (a positional parameter with no $# check, an environment variable the script never sets, or a command-substitution result) with no ${VAR:?}, default or -z/-n test, which deletes from / instead. Not reported: scripts that enable errexit (and nounset, for the rm case), checked cd and checks, cd followed by non-destructive commands or absolute paths, a check that is the last command or a function's return value, sourced libraries without a shebang, test paths and .bats files. The mere absence of set -euo pipefail is not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-bash-003/",
	"languages": ["bash", "shell"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [755],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["bash", "error-handling", "set-e", "best-practice"],
}

# ── Executable shell scripts ────────────────────────────────────────────

_shebang_re := `^#![ \t]*(\S*/)?(env[ \t]+(-\S+[ \t]+)*)?(ba|da|k|z|mk)?sh(\s|$)`

_shell_path(path) if {
	some ext in [".sh", ".bash", ".ksh", ".zsh"]
	endswith(path, ext)
}

_shell_path(path) if {
	regex.match(`(^|/)[^/.]+$`, path)
	not regex.match(`(^|/)(gradlew|mvnw)$`, path)
}

_set_flags := `(?m)^[ \t]*set[ \t]+(?:[-+][A-Za-z]+[ \t]+|[-+]o[ \t]+\w+[ \t]+)*`

_errexit(content) if regex.match(concat("", [_set_flags, `(?:-[A-Za-z]*e[A-Za-z]*|-o[ \t]+errexit)\b`]), content)

_errexit(content) if regex.match(`^#![^\n]*[ \t]-[A-Za-z]*e[A-Za-z]*(\s|$)`, content)

_errexit(content) if regex.match(`(?m)^[ \t]*(trap[ \t].*\bERR\b|shopt[ \t]+-s[ \t]+-o[ \t]+errexit)`, content)

_nounset(content) if regex.match(concat("", [_set_flags, `(?:-[A-Za-z]*u[A-Za-z]*|-o[ \t]+nounset)\b`]), content)

_nounset(content) if regex.match(`^#![^\n]*[ \t]-[A-Za-z]*u[A-Za-z]*(\s|$)`, content)

_comment(line) if startswith(trim_space(line), "#")

_code(line) if {
	trim_space(line) != ""
	not _comment(line)
}

# The next code line within three, if any.
_next(lines, i) := lines[j] if {
	cands := [k | some k in numbers.range(i + 1, min([count(lines) - 1, i + 3])); _code(lines[k])]
	count(cands) > 0
	j := cands[0]
}

# The status of line i is read: by a || / && continuation, a $? test, or
# because it is the function's (or the script's) last command.
_status_read(lines, i) if regex.match(`(\|\||&&|\$\?)`, _next(lines, i))

_status_read(lines, i) if regex.match(`^\s*(\}|fi\b|done\b|esac\b)`, _next(lines, i))

_status_read(lines, i) if {
	rest := [k | some k in numbers.range(i + 1, count(lines) - 1); _code(lines[k])]
	count(rest) == 0
}

_status_read(lines, i) if i == count(lines) - 1

_status_read(lines, i) if regex.match(`\\\s*$`, lines[i])

# ── 1. A cd whose failure is ignored, then a relative delete ────────────

_cd_re := `^\s*\(?\s*(?:builtin\s+)?(?:cd|pushd)(?:\s+[^;&|()]*)?(;|$)`

_cd_like(line) if regex.match(`(^|[;&|(]\s*|\bthen\s+|\bdo\s+)(cd|pushd|popd)(\s|;|$)`, line)

_rm_args(line) := [t |
	m := regex.find_all_string_submatch_n(`(?:^\s*|[;&|(]\s*|\bthen\s+|\bdo\s+)(?:sudo\s+|command\s+)?rm\s+([^;&|]*)`, line, -1)
	some mm in m
	some t in split(trim_space(mm[1]), " ")
	t != ""
	not startswith(t, "-")
]

_relative(t) if {
	u := trim(t, "\"'")
	u != ""
	not regex.match(`^[/~$]`, u)
	not regex.match(`^[0-9]*[<>]`, u)
}

_destructive(line) if {
	some t in _rm_args(line)
	_relative(t)
}

_destructive(line) if regex.match(`(^|[;&|(]\s*)find\s+\.(/\S*)?\s.*(-delete\b|-exec\s+rm\b)`, line)

_destructive(line) if regex.match(`\bgit\s+(clean\s+(-\S+\s+)*-[A-Za-z]*f|reset\s+(\S+\s+)*--hard\b)`, line)

# The delete shares the cd's line (cd dir; rm -rf *) ...
_deletes_after(lines, i, line) if {
	parts := split(line, ";")
	count(parts) > 1
	_destructive(concat(";", array.slice(parts, 1, count(parts))))
}

# ... or follows within ten lines, before any other directory change.
_deletes_after(lines, i, _) if {
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 10]))
	_code(lines[k])
	_destructive(lines[k])
	not _cd_between(lines, i, k)
}

_cd_between(lines, i, k) if {
	k - 1 >= i + 1
	some q in numbers.range(i + 1, k - 1)
	_code(lines[q])
	_cd_like(lines[q])
}

_unchecked_cd(lines, i, line) if {
	regex.match(`\b(cd|pushd)\b`, line)
	regex.match(_cd_re, line)
	not _cd_checked(lines, i)
	_deletes_after(lines, i, line)
}

# The cd's status is read on the next line (|| exit, && ..., $?).
_cd_checked(lines, i) if regex.match(`(\|\||&&|\$\?)`, _next(lines, i))

_cd_checked(lines, i) if regex.match(`\\\s*$`, lines[i])

# ── 2. An integrity check whose result is ignored ───────────────────────

_verify_re := `(?:^|\|\s*)(?:sudo\s+)?(?:(?:sha(?:1|224|256|384|512)sum|md5sum|b2sum|shasum)\s+(?:\S+\s+)*?(?:-c|--check)\b|gpg2?\s+(?:\S+\s+)*?--verify\b|gpgv\s|cosign\s+verify|minisign\s+(?:\S+\s+)*?-V\b|openssl\s+dgst\s.*-verify\b)`

_ignored_check(lines, i, line) if {
	regex.match(`(sum|sha|gpg|cosign|minisign|openssl)`, line)
	t := regex.replace(line, `^\s*(then|else|do)\s+`, "")
	regex.match(_verify_re, trim_space(t))
	not regex.match(`^\s*(if|elif|while|until|!|\[|test)\b`, t)
	not regex.match(`(\|\||&&)`, line)
	not regex.match(`^\s*\w+=`, t)
	not _status_read(lines, i)
}

# ── 3. rm -r of a path built on a variable that may be empty ────────────

_rm_var_re := `\brm\s+((?:-\S+\s+)+)(?:--\s+)?"?\$(?:\{([A-Za-z_]\w*|[1-9])(?::-)?\}|([A-Za-z_]\w*|[1-9]))"?/`

_rm_var(line) := v if {
	m := regex.find_all_string_submatch_n(_rm_var_re, line, 1)
	count(m) > 0
	regex.match(`(^|\s)(-[A-Za-z]*[rR][A-Za-z]*|--recursive)\s`, concat("", [" ", m[0][1]]))
	v := concat("", [m[0][2], m[0][3]])
}

_always_set := {"HOME", "PWD", "OLDPWD", "USER", "SHELL", "PATH"}

_guarded(content, v) if regex.match(concat("", [`\$\{`, v, `:?[?=]`]), content)

_guarded(content, v) if regex.match(concat("", [`-[zndef]\s+"?\$\{?`, v, `\b`]), content)

_guarded(content, v) if regex.match(concat("", [`\$\{?`, v, `\}?"?\s*!?==?\s*""|""\s*!?==?\s*"?\$\{?`, v, `\b`]), content)

_assign_re(v) := concat("", [`(?:^|[\s;(])(?:local\s+|export\s+|readonly\s+|(?:declare|typeset)\s+(?:-\w+\s+)*)?`, v, `\+?=(.*)$`])

_assigned_values(lines, v) := [m[0][1] |
	re := _assign_re(v)
	some l in lines
	contains(l, v)
	_code(l)
	m := regex.find_all_string_submatch_n(re, l, 1)
	count(m) > 0
]

_bound_elsewhere(lines, v) if {
	some l in lines
	contains(l, v)
	_code(l)
	regex.match(concat("", [`\b(read\b[^;|&]*|for\s+|getopts\s+\S+\s+|(local|declare|typeset|readonly)\s+(-\w+\s+)*)`, v, `\b`]), l)
}

# `mode` carries the file's errexit (ee) and nounset (nu) settings, computed
# once per file.

# A positional parameter: unset when the script is run without it.
_may_be_empty(mode, content, _, v) if {
	regex.match(`^[1-9]$`, v)
	mode.nu == false
	not contains(content, "$#")
}

# An environment variable the script never sets.
_may_be_empty(mode, _, lines, v) if {
	not regex.match(`^[1-9]$`, v)
	not _always_set[v]
	mode.nu == false
	count(_assigned_values(lines, v)) == 0
	not _bound_elsewhere(lines, v)
}

# Assigned only from command output (empty when that command fails), or only
# from a positional parameter.
_may_be_empty(mode, _, lines, v) if {
	mode.ee == false
	vals := _assigned_values(lines, v)
	count(vals) > 0
	every val in vals {
		regex.match(concat("", [`^["']?(\$\(|`, "`", `)`]), val)
	}
}

_may_be_empty(mode, content, lines, v) if {
	mode.nu == false
	not contains(content, "$#")
	vals := _assigned_values(lines, v)
	count(vals) > 0
	every val in vals {
		regex.match(`^["']?\$\{?[1-9]\}?["']?\s*$`, val)
	}
}

_unset_path_rm(mode, content, lines, line) if {
	contains(line, "rm")
	v := _rm_var(line)
	not _guarded(content, v)
	_may_be_empty(mode, content, lines, v)
}

# ── Findings ────────────────────────────────────────────────────────────

_message := "This script does not enable errexit/nounset, so a failure here is ignored and the next command runs anyway: check the command (cd dir || exit 1, sha256sum -c sums || exit 1), guard the path (${VAR:?}), or add set -euo pipefail after the shebang"

findings contains finding if {
	some path, content in input.file_contents
	_shell_path(path)
	regex.match(_shebang_re, content)
	not helpers.is_test_path(path)
	mode := {"ee": _flag_ee(content), "nu": _flag_nu(content)}
	not _all_on(mode)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(cd|pushd|rm|sum|gpg|cosign|minisign|openssl)`, line)
	_code(line)
	_reported(mode, content, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_flag_ee(content) := true if _errexit(content)

else := false

_flag_nu(content) := true if _nounset(content)

else := false

_all_on(mode) if {
	mode.ee == true
	mode.nu == true
}

_reported(mode, _, lines, i, line) if {
	mode.ee == false
	_unchecked_cd(lines, i, line)
}

_reported(mode, _, lines, i, line) if {
	mode.ee == false
	_ignored_check(lines, i, line)
}

_reported(mode, content, lines, _, line) if _unset_path_rm(mode, content, lines, line)
