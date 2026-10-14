# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_279

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-279",
	"name": "Incorrect Execution-Assigned Permissions",
	"description": "While it runs, a program (or its install step) sets the setuid bit on a file, so whoever executes that file afterwards does so with the file owner's identity, usually root. This is the most concrete form of permissions assigned at run time that nobody asked for, and it is what this rule reports: chmod/fchmod/fchmodat/lchmod and std::filesystem::permissions with a 04xxx-07xxx mode, S_ISUID or perms::set_uid in C and C++; os.chmod/os.fchmod/Path.chmod with 0o4xxx or stat.S_ISUID in Python; os.Chmod/File.Chmod with os.ModeSetuid and syscall/unix Chmod with a setuid mode in Go; `chmod u+s`/`+s`/`4755`, `install -m 4755` and `COPY --chmod=4755` in shell scripts and Dockerfiles; and the same chmod command run through system/exec/subprocess. A mode held in a variable assigned such a literal just above counts. Not reported: setgid alone (g+s, 02775), which on a directory is the normal way to share a group; clearing the bit (& ~S_ISUID, &^ os.ModeSetuid, u-s, a-s); testing for it; sticky or ordinary modes; Go os.Chmod with a 0o4755 literal, which does not set the bit (os.ModeSetuid does); test code; and the pattern in comments or strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-279/",
	"languages": ["c", "cpp", "python", "go", "bash", "docker"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [279],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["exec-assigned-permissions", "setuid", "chmod", "file-permissions", "cwe-279"],
}

_msg := "This sets the setuid bit: anyone who runs the file runs it as its owner (usually root), so any flaw in it becomes a privilege escalation. Grant the specific capability or use a privileged helper with an explicit policy (sudoers, polkit, file capabilities) instead of a setuid file"

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# Test code is not the surface: the shared test-path convention, plus shell
# test scripts (test.sh, run_test.sh, *.bats) that live beside the code.
_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)tests?([_.-][^/]*)?\.(sh|bash)$|_tests?\.(sh|bash)$|\.bats$`, path)

# ── Languages ────────────────────────────────────────────────────────────

_lang(path) := "c" if {
	some ext in {".c", ".cc", ".cpp", ".cxx"}
	endswith(path, ext)
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "go" if endswith(path, ".go")

_shell(path) if {
	some ext in {".sh", ".bash", ".zsh", ".ksh", ".bats"}
	endswith(path, ext)
}

_shell(path) if {
	lp := lower(path)
	_has_any(lp, {"dockerfile", "containerfile"})
	base := regex.replace(lp, `^.*/`, "")
	regex.match(`^(dockerfile|containerfile)([._-].*)?$|\.(dockerfile|containerfile)$`, base)
}

# Makefile recipes and package build scripts are shell: an install target is
# where a setuid helper is usually given its bit.
_shell(path) if {
	base := lower(regex.replace(path, `^.*/`, ""))
	_make_or_pkg(base)
}

_make_or_pkg(base) if base in {"makefile", "gnumakefile", "makefile.am", "makefile.in", "pkgbuild", "apkbuild"}

_make_or_pkg(base) if endswith(base, ".mk")

# ── chmod calls in a program ─────────────────────────────────────────────

_suid_octal := `(^|[^\w.])0[oO]?[4-7][0-7]{3}\b`

# [call, setuid token] pairs per language.
_checks := {
	"c": {[`(^|[^\w.>])(::)?(chmod|fchmod|lchmod|fchmodat)\s*\(|(^|[^\w.>])(\w+::)*permissions\s*\(`, concat("|", [_suid_octal, `\bS_ISUID\b|\bperms::set_uid\b`])]},
	"py": {[`\.chmod\s*\(|\bos\.(fchmod|lchmod)\s*\(`, concat("|", [_suid_octal, `\bS_ISUID\b`])]},
	"go": {
		[`\.Chmod\s*\(`, `\b(os|fs)\.ModeSetuid\b`],
		[`\b(syscall|unix)\.(Chmod|Fchmod|Fchmodat)\s*\(`, concat("|", [_suid_octal, `\b(syscall|unix)\.S_ISUID\b`])],
	},
}

# Substring gates, per file and per line: cheaper than a regular expression.
_needles := {"c": {"chmod", "permissions"}, "py": {"chmod"}, "go": {"Chmod", "chmod"}}

# The bit is being cleared, not set.
_clears(args) if regex.match(`~\s*\(?[^)]*S_ISUID|&\^\s*\(?\s*[^)]*ModeSetuid|perm_options::remove`, args)

_strip(line) := regex.replace(line, `"(\\.|[^"\\])*"|'(\\.|[^'\\])*'`, `""`)

_suid_assign := `=\s*0[oO]?[4-7][0-7]{3}\s*;?\s*(#.*|//.*)?$`

# Names declared once for the file with a setuid literal and used far from
# it: `#define HELPER_MODE 04755`, `const SUID_MODE = 0o4755`,
# `static const mode_t kMode = 04755;`, an ALL_CAPS module constant.
_suid_lit := `0[oO]?[4-7][0-7]{3}`

_tail := `\s*;?\s*(#.*|//.*|/\*.*)?$`

_suid_const_res := [
	concat("", [`^\s*#\s*define\s+([A-Za-z_]\w*)\s+\(?\s*`, _suid_lit, `\s*\)?`, _tail]),
	concat("", [`^\s*(?:export\s+)?(?:pub\s+)?(?:const|let|var|static)\s+([A-Za-z_]\w*)\s*(?::\s*[\w.:]+\s*|[\w.]+\s*)?=\s*`, _suid_lit, _tail]),
	concat("", [`^\s*(?:(?:static|const|constexpr|final|inline)\s+)+[\w:<>*]+\s+\*?([A-Za-z_]\w*)\s*=\s*`, _suid_lit, _tail]),
	concat("", [`^\s*([A-Z][A-Z0-9_]*)\s*=\s*`, _suid_lit, _tail]),
]

_suid_const_names(lines) := {m[1] |
	some l in lines
	contains(l, "0")
	some re in _suid_const_res
	some m in regex.find_all_string_submatch_n(re, l, 1)
}

_sets_suid(args, token, _, _, _) if regex.match(token, args)

# A variable or constant holding an octal mode counts only where an octal
# literal would: Go's os.Chmod ignores 0o4755 (it needs os.ModeSetuid).
_octal_counts(token) if regex.match(token, " 04755")

_sets_suid(args, token, lines, i, _) if {
	_octal_counts(token)
	some v in helpers.tainted_names(lines, i, 15, _suid_assign)
	regex.match(concat("", [`(^|[^\w.])`, v, `\b`]), args)
}

_sets_suid(args, token, _, _, consts) if {
	_octal_counts(token)
	some v in consts
	regex.match(concat("", [`(^|[^\w.])`, v, `\b`]), args)
}

# The call text: the line, or the lines up to where the call's parentheses
# balance when its arguments run on (at most five further lines).
_opens(s) := count(indexof_n(s, "(")) - count(indexof_n(s, ")"))

_closes_at(lines, i) := ends[0] if {
	end := min([count(lines) - 1, i + 5])
	ends := [k | some k in numbers.range(i + 1, end); _opens(concat(" ", array.slice(lines, i, k + 1))) <= 0]
	count(ends) > 0
}

_joined(lines, i) := lines[i] if _opens(lines[i]) <= 0

_joined(lines, i) := concat(" ", array.slice(lines, i, _closes_at(lines, i) + 1)) if _opens(lines[i]) > 0

_joined(lines, i) := lines[i] if {
	_opens(lines[i]) > 0
	not _closes_at(lines, i)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _needles[lang])
	not _is_test(path)
	lines := split(content, "\n")
	consts := _suid_const_names(lines)
	some i, line in lines
	_has_any(line, _needles[lang])
	some check in _checks[lang]
	regex.match(check[0], line)
	not helpers.is_comment_line(line)
	parts := regex.split(check[0], _strip(_joined(lines, i)))
	args := concat(" ", array.slice(parts, 1, count(parts)))
	not _clears(args)
	_sets_suid(args, check[1], lines, i, consts)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── A chmod command run from a program ───────────────────────────────────

_shell_mode := `0?[4-7][0-7]{3}|([ugoa]*[ua][ugoa]*)?[+=][rwxXt]*s[rwxXt]*`

_exec_re := "\\b(system|popen|_popen|exec\\w*|spawn\\w*|run|call|check_call|check_output|Popen|getoutput|getstatusoutput|Command|CommandContext)\\s*\\("

_cmd_re := concat("", [
	"[\"'`](sudo\\s+)?chmod\\s+(-[A-Za-z]+\\s+)*(", _shell_mode, ")([\"'`\\s]|$)",
	"|[\"']chmod[\"']\\s*,\\s*(\\[\\s*)?([\"']-[A-Za-z]+[\"']\\s*,\\s*)*[\"'](", _shell_mode, ")[\"']",
])

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "chmod")
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "chmod")
	not helpers.is_comment_line(line)
	regex.match(_exec_re, line)
	regex.match(_cmd_re, line)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── CMake and Meson install rules ────────────────────────────────────────

_cmake(path) if {
	base := lower(regex.replace(path, `^.*/`, ""))
	base == "cmakelists.txt"
}

_cmake(path) if endswith(lower(path), ".cmake")

# install(... PERMISSIONS ... SETUID) / file(COPY ... FILE_PERMISSIONS ...
# SETUID): the SETUID word inside the permission list of an install or copy
# command, on its line or a few lines below the command's opening.
_cmake_in_permissions(lines, i) if {
	start := max([0, i - 8])
	heads := [j |
		some j in numbers.range(start, i)
		regex.match(`(?i)\b(install|file|configure_file)\s*\(`, lines[j])
	]
	count(heads) > 0
	h := heads[count(heads) - 1]
	text := concat(" ", [regex.replace(l, `"[^"]*"|#.*$`, "") | some l in array.slice(lines, h, i + 1)])
	regex.match(`\b\w*PERMISSIONS\b[^)]*\bSETUID\b`, text)
}

findings contains finding if {
	some path, content in input.file_contents
	_cmake(path)
	contains(content, "SETUID")
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "SETUID")
	not helpers.is_comment_line(line)
	regex.match(`\bSETUID\b`, regex.replace(line, `"[^"]*"|#.*$`, ""))
	_cmake_in_permissions(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Meson: install_mode : 'rwsr-xr-x' (an s in the owner-execute position).
findings contains finding if {
	some path, content in input.file_contents
	lower(regex.replace(path, `^.*/`, "")) == "meson.build"
	contains(content, "install_mode")
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "install_mode")
	not helpers.is_comment_line(line)
	regex.match(`\binstall_mode\s*:\s*\[?\s*'[r-][w-][sS]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Shell scripts and Dockerfiles ────────────────────────────────────────

_suid_shell_mode(tok) if regex.match(`^0?[4-7][0-7]{3}$`, tok)

_suid_shell_mode(tok) if {
	some clause in split(tok, ",")
	regex.match(`^([ugoa]*[ua][ugoa]*)?[+=][rwxXt]*s`, clause)
}

_sh_code(line) := regex.replace(line, `"(\\.|[^"\\])*"|'[^']*'`, "Q")

# A recipe line may start with make's @ (silent) or - (ignore errors).
_sh_mode_tokens(code) := {m[2] |
	some m in regex.find_all_string_submatch_n(`(^|[\s;&|(@-])chmod\s+(?:-[A-Za-z]+\s+|--[\w-]+\s+)*(\S+)`, code, -1)
} | {m[1] |
	# install takes options with values before -m (install -o root -g root
	# -m 4755 ...), so the mode is looked for anywhere in its own words.
	some seg in regex.find_all_string_submatch_n(`(?:^|[\s;&|(@-])install\s+([^;&|]*)`, code, -1)
	some m in regex.find_all_string_submatch_n(`(?:^|\s)(?:-[A-Za-z]*m\s*|--mode[= ])(\S+)`, seg[1], -1)
} | {m[1] |
	some m in regex.find_all_string_submatch_n(`--chmod=(\S+)`, code, -1)
}

_sh_suid(line) if {
	some tok in _sh_mode_tokens(_sh_code(line))
	_suid_shell_mode(tok)
}

_sh_suid(line) if regex.match(concat("", [`"chmod"\s*,\s*("-[A-Za-z]+"\s*,\s*)*"(`, _shell_mode, `)"`]), line)

findings contains finding if {
	some path, content in input.file_contents
	_shell(path)
	_has_any(content, {"chmod", "install"})
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, {"chmod", "install"})
	not helpers.is_comment_line(line)
	_sh_suid(line)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
