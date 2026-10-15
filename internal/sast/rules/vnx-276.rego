# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_276

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-276",
	"name": "Incorrect Default Permissions",
	"description": "A file or directory is given a world-writable mode by a call the umask does not filter, so any local user can modify what the program or its installer put there. Reported: chmod/fchmod/lchmod/fchmodat and std::filesystem::permissions (perms::all, perms::others_write) in C and C++; os.chmod/os.fchmod/Path.chmod in Python; os.Chmod/File.Chmod (including os.ModePerm) in Go; chmod() and ->chmod() in PHP; fs.chmod/chmodSync/fchmod in JavaScript and TypeScript (numeric or string modes); File.chmod/FileUtils.chmod/chmod_R and FileUtils.mkdir/mkdir_p/install with mode: (which chmod after creating) in Ruby; Files.setPosixFilePermissions with rwxrwxrwx or OTHERS_WRITE and File.setWritable(true, false) in Java; fs::Permissions::from_mode and PermissionsExt::set_mode in Rust (which feed fs::set_permissions); mode: and mode= in Ansible file/copy/template tasks; `chmod`, `install -m` (also after -o/-g options), `mkdir -m` and `COPY --chmod` with a world-writable mode in shell scripts, Makefile recipes, PKGBUILD/APKBUILD and Dockerfiles; and `chmod 777`-style commands run through system/exec/subprocess from any of those languages. A mode is world-writable when it grants others write (an octal mode ending in 2, 3, 6 or 7, S_IWOTH/S_IRWXO, o+w/a+w, PHP octdec('0777') or Python int('777', 8)). A call whose arguments run onto following lines is read up to its closing parenthesis. Also reported when the mode comes from a variable assigned such a literal a few lines above, or from a constant declared once for the file (const/#define/static final, an ALL_CAPS module constant, a Go const block, PHP define()). Not reported: modes passed to creation calls the umask filters (open, mkdir, os.makedirs, os.WriteFile, fs.writeFile, Rust OpenOptions/DirBuilder .mode()), the sticky-bit modes for shared directories (1777, +t), modes computed from the umask or masked (0777 - umask(), mode & ~S_IWOTH, a mode variable masked after it is assigned), a tree made writable only to be removed a few lines later (an rmtree onerror handler, a walk before RemoveAll), reading permissions (st.permissions() & perms::others_write), test code, and the pattern in comments or log strings. Modes held in shell variables, Kotlin, C#, Kubernetes manifests and YAML CI steps are not covered.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-276/",
	"languages": ["c", "cpp", "python", "go", "php", "javascript", "ruby", "java", "rust", "bash", "docker", "yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [276],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["default-permissions", "world-writable", "chmod", "file-permissions", "cwe-276"],
}

_msg := "World-writable permissions: any local user can modify this file or directory, replacing code, configuration or data the program trusts. Grant write to the owner (and a group if needed) only, e.g. 0755/0644, and use a sticky directory (1777) for shared drop areas"

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

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"}
	endswith(path, ext)
}

_lang(path) := "ruby" if {
	some ext in {".rb", ".rake"}
	endswith(path, ext)
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "rs" if endswith(path, ".rs")

_shell(path) if {
	some ext in {".sh", ".bash", ".zsh", ".ksh", ".bats"}
	endswith(path, ext)
}

_shell(path) if _dockerfile(path)

# Makefile recipes and package build scripts are shell too: an install
# target is where modes are most often set.
_shell(path) if {
	base := lower(regex.replace(path, `^.*/`, ""))
	_make_or_pkg(base)
}

_make_or_pkg(base) if base in {"makefile", "gnumakefile", "makefile.am", "makefile.in", "pkgbuild", "apkbuild"}

_make_or_pkg(base) if endswith(base, ".mk")

_dockerfile(path) if {
	lp := lower(path)
	_has_any(lp, {"dockerfile", "containerfile"})
	base := regex.replace(lp, `^.*/`, "")
	regex.match(`^(dockerfile|containerfile)([._-].*)?$|\.(dockerfile|containerfile)$`, base)
}

# ── Mode literals ────────────────────────────────────────────────────────

# An octal literal granting others write, without the sticky bit: 0777, 0o666,
# 02777. 01777 (a sticky shared directory) is not world-modifiable in the
# sense that matters and is excluded.
_ww_octal := `(^|[^\w.])0[oO]?[0246]?[0-7]{2}[2367]\b`

_ww_token := {
	"c": concat("|", [_ww_octal, `\b(S_IWOTH|S_IRWXO|ACCESSPERMS|ALLPERMS|DEFFILEMODE)\b`, `\bperms::(all|others_write|others_all|mask)\b`]),
	"py": concat("|", [_ww_octal, `\bS_IWOTH\b|\bS_IRWXO\b`]),
	"go": concat("|", [_ww_octal, `\b(os|fs)\.ModePerm\b`]),
	"php": _ww_octal,
	"js": concat("|", [_ww_octal, "[\"'`]0?[0246]?[0-7]{2}[2367][\"'`]", `\bS_IWOTH\b|\bS_IRWXO\b`]),
	"ruby": concat("|", [_ww_octal, `["'][ugoa]*[oa][ugoa]*[+=][rwxX]*w[rwxX]*["']`]),
	"rs": _ww_octal,
}

# The mode is computed: masked, subtracted from, or a bit removed.
_masked(args) if regex.match(`(0[oO]?[0-7]{3,5}|\bS_I\w+|ModePerm|perms::\w+)\s*(-|&|\^)|(&\^?|-|\^)\s*~?\s*\(?\s*(0[oO]?[0-7]{3,5}|(stat\.)?S_I\w+|(os|fs)\.ModePerm)|~\s*\(?\s*(stat\.)?S_I|perm_options::remove|\bumask\b`, args)

# A call whose mode argument the umask does not filter.
_call_re := {
	"c": `(^|[^\w.>])(::)?(chmod|fchmod|lchmod|fchmodat)\s*\(|(^|[^\w.>])(\w+::)*permissions\s*\(`,
	"py": `\.chmod\s*\(|\bos\.(fchmod|lchmod)\s*\(`,
	"go": `\.Chmod\s*\(`,
	"php": `\bchmod\s*\(`,
	"js": `\b(chmod|chmodSync|fchmod|fchmodSync|lchmod|lchmodSync)\s*\(`,
	"ruby": `\b(File|FileUtils)\.l?chmod(_R)?\b|\.chmod\s*\(`,
	# Rust: PermissionsExt::from_mode / set_mode feed fs::set_permissions, which
	# the umask does not filter (OpenOptions and DirBuilder `.mode()` it does).
	"rs": `\b(from_mode|set_mode)\s*\(`,
}

# Substring gates, per file and per line: cheaper than a regular expression.
_needles := {
	"c": {"chmod", "permissions"},
	"py": {"chmod"},
	"go": {"Chmod"},
	"php": {"chmod"},
	"js": {"chmod"},
	"ruby": {"chmod"},
	"java": {"chmod", "setWritable", "OTHERS_WRITE", "fromString"},
	"rs": {"from_mode", "set_mode"},
}

# String contents are blanked where a mode is never a string, so a log line
# that mentions chmod(…, 0777) is not a call.
_code(line, lang) := line if lang in {"js", "ruby"}

_code(line, lang) := regex.replace(_octal_strings(line), `"(\\.|[^"\\])*"|'(\\.|[^'\\])*'`, `""`) if not lang in {"js", "ruby"}

# A mode spelled as a string and converted, PHP's octdec('0777') and
# Python's int("777", 8), is rewritten as the octal literal it is before
# string contents are blanked.
_octal_strings(line) := regex.replace(
	regex.replace(line, `\boctdec\s*\(\s*['"](0?[0-7]{3,4})['"]\s*\)`, "0$1"),
	`\bint\s*\(\s*['"](0?[0-7]{3,4})['"]\s*,\s*8\s*\)`, "0o$1",
)

_args(code, lang) := concat(" ", array.slice(parts, 1, count(parts))) if {
	parts := regex.split(_call_re[lang], code)
	count(parts) > 1
}

# The call text: the line itself, or, when the call's argument list runs on
# (`os.chmod(\n    path,\n    0o777,\n)`), the lines up to where its
# parentheses balance, at most five further lines.
_opens(s) := count(indexof_n(s, "(")) - count(indexof_n(s, ")"))

_joined(lines, i, code) := code if _opens(code) <= 0

_joined(lines, i, code) := s if {
	_opens(code) > 0
	end := min([count(lines) - 1, i + 5])
	ends := [k | some k in numbers.range(i + 1, end); _opens(concat(" ", array.slice(lines, i, k + 1))) <= 0]
	count(ends) > 0
	s := concat(" ", array.concat([code], array.slice(lines, i + 1, ends[0] + 1)))
}

_joined(lines, i, code) := code if {
	_opens(code) > 0
	end := min([count(lines) - 1, i + 5])
	not _closes_within(lines, i, end)
}

_closes_within(lines, i, end) if {
	some k in numbers.range(i + 1, end)
	_opens(concat(" ", array.slice(lines, i, k + 1))) <= 0
}

# A name assigned a bare world-writable literal (`mode = 0o777`,
# `perm := os.FileMode(0777)`) a few lines above.
_ww_lit := `((os|fs)\.FileMode\(\s*)?0[oO]?[0246]?[0-7]{2}[2367]\s*\)?`

_ww_assign := concat("", [`=\s*`, _ww_lit, `\s*;?\s*(#.*|//.*)?$`])

# Names declared once for the whole file with such a literal: a constant
# (`const socketMode = 0o777`, `static final int MODE = 0777;`, an entry in a
# Go `const (` block), an ALL_CAPS module constant, `#define MODE 0777`, or
# PHP's define('MODE', 0777). These are used far from where they are set.
_tail := `\s*;?\s*(#.*|//.*|/\*.*)?$`

_ww_const_res := [
	concat("", [`^\s*#\s*define\s+([A-Za-z_]\w*)\s+\(?\s*`, _ww_lit, `\s*\)?`, _tail]),
	concat("", [`^\s*(?:export\s+)?(?:pub\s+)?(?:const|let|var|static)\s+([A-Za-z_]\w*)\s*(?::\s*[\w.:]+\s*|[\w.]+\s*)?=\s*`, _ww_lit, _tail]),
	concat("", [`^\s*(?:(?:static|const|constexpr|final|private|public|protected|inline)\s+)+[\w:<>*]+\s+\*?([A-Za-z_]\w*)\s*=\s*`, _ww_lit, _tail]),
	concat("", [`^\s*(?:const\s+)?([A-Z][A-Z0-9_]*)\s*=\s*`, _ww_lit, _tail]),
	concat("", [`\bdefine\s*\(\s*['"]([A-Za-z_]\w*)['"]\s*,\s*`, _ww_lit, `\s*\)`]),
]

_ww_const_names(lines) := {m[1] |
	some l in lines
	contains(l, "0")
	some re in _ww_const_res
	some m in regex.find_all_string_submatch_n(re, l, 1)
} | {v |
	some k, l in lines
	regex.match(concat("", [`^\s+[A-Za-z_]\w*\s*(?:[\w.]+\s*)?=\s*`, _ww_lit, _tail]), l)
	_in_decl_block(lines, k)
	v := helpers.assigned_first(l)
}

# Line k sits inside a top-level Go `const (` / `var (` block.
_in_decl_block(lines, k) if {
	k > 0
	tops := [j | some j in numbers.range(max([0, k - 40]), k - 1); regex.match(`^\S`, lines[j])]
	count(tops) > 0
	regex.match(`^(const|var)\s*\(\s*$`, lines[tops[count(tops) - 1]])
}

_ww_args(args, lang, _, _, _) if {
	regex.match(_ww_token[lang], args)
	not _masked(args)
}

_ww_args(args, lang, lines, i, _) if {
	not _masked(args)
	some v in helpers.tainted_names(lines, i, 15, _ww_assign)
	regex.match(concat("", [`(^|[^\w.])`, v, `\b`]), args)
	not _remasked(lines, i, v)
}

# The variable is masked after it is assigned: `mode &= ~old_umask;`,
# `mode &^= 0o022`, `mode = mode & ~umask`.
_remasked(lines, i, v) if {
	some k in numbers.range(max([0, i - 15]), i - 1)
	regex.match(concat("", [`(^|[^\w.])`, v, `\s*(&\^?|-|\^)=|(^|[^\w.])`, v, `\s*=\s*`, v, `\s*(&|-)`]), lines[k])
}

_ww_args(args, lang, _, _, consts) if {
	not _masked(args)
	some v in consts
	regex.match(concat("", [`(^|[^\w.])`, v, `\b`]), args)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_call_re[lang]
	_has_any(content, _needles[lang])
	not _is_test(path)
	lines := split(content, "\n")
	consts := _ww_const_names(lines)
	some i, line in lines
	_has_any(line, _needles[lang])
	regex.match(_call_re[lang], line)
	not helpers.is_comment_line(line)
	args := _args(_code(_joined(lines, i, line), lang), lang)
	_ww_args(args, lang, lines, i, consts)
	not _deleted_after(lines, i, args)
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

# ── Ruby: FileUtils creation calls that chmod ────────────────────────────

# FileUtils.mkdir/mkdir_p/install with mode: chmod the result to exactly that
# mode after creating it, so unlike Dir.mkdir the umask does not filter it.
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "ruby"
	contains(content, "mode:")
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "mode:")
	not helpers.is_comment_line(line)
	regex.match(`\bFileUtils\.(mkdir_p|mkdir|makedirs|mkpath|install)\b`, line)
	regex.match(`\bmode:\s*0[oO]?[0246]?[0-7]{2}[2367]\b`, _joined(lines, i, line))
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

# ── Java ─────────────────────────────────────────────────────────────────

_java_ww(line, _) if regex.match(`\.setWritable\s*\(\s*true\s*,\s*false\s*\)`, line)

_java_ww(line, content) if {
	regex.match(`fromString\s*\(\s*"[r-][w-][x-][r-][w-][x-][r-]w[x-]"\s*\)|\bOTHERS_WRITE\b`, line)
	contains(content, "setPosixFilePermissions")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	_has_any(content, _needles.java)
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _needles.java)
	not helpers.is_comment_line(line)
	_java_ww(line, content)
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

_shell_mode := `0?[0246]?[0-7]{2}[2367]|[ugoa]*[oa][ugoa]*[+=][rwxX]*w[rwxX]*`

_exec_re := "\\b(system|popen|_popen|exec\\w*|spawn\\w*|run|call|check_call|check_output|Popen|getoutput|getstatusoutput|Command|CommandContext|shell_exec|passthru|proc_open|ProcessBuilder|capture2e?|capture3)\\s*\\(|`|%x[({\\[]"

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

# ── Shell scripts and Dockerfiles ────────────────────────────────────────

# A symbolic or numeric chmod mode that grants others write and is not sticky.
_ww_shell_mode(tok) if regex.match(`^0?[0246]?[0-7]{2}[2367]$`, tok)

_ww_shell_mode(tok) if {
	not contains(tok, "t")
	some clause in split(tok, ",")
	regex.match(`^[ugoa]*[oa][ugoa]*[+=][rwxX]*w`, clause)
}

# Quoted words are blanked: `echo "chmod 777"` is not a command.
_sh_code(line) := regex.replace(line, `"(\\.|[^"\\])*"|'[^']*'`, "Q")

# A recipe line may start with make's @ (silent) or - (ignore errors).
_sh_mode_tokens(code) := {m[2] |
	some m in regex.find_all_string_submatch_n(`(^|[\s;&|(@-])chmod\s+(?:-[A-Za-z]+\s+|--[\w-]+\s+)*(\S+)`, code, -1)
} | {m[1] |
	# install/mkdir take other options with values before -m
	# (install -o root -g root -m 0777 ...), so the mode is looked for
	# anywhere in the command's own words.
	some seg in regex.find_all_string_submatch_n(`(?:^|[\s;&|(@-])(?:install|mkdir)\s+([^;&|]*)`, code, -1)
	some m in regex.find_all_string_submatch_n(`(?:^|\s)(?:-[A-Za-z]*m\s*|--mode[= ])(\S+)`, seg[1], -1)
} | {m[1] |
	some m in regex.find_all_string_submatch_n(`--chmod=(\S+)`, code, -1)
}

_sh_ww(line) if {
	some tok in _sh_mode_tokens(_sh_code(line))
	_ww_shell_mode(tok)
}

# Dockerfile exec form: RUN ["chmod", "777", "/srv"]
_sh_ww(line) if regex.match(concat("", [`"chmod"\s*,\s*("-[A-Za-z]+"\s*,\s*)*"(`, _shell_mode, `)"`]), line)

findings contains finding if {
	some path, content in input.file_contents
	_shell(path)
	_has_any(content, {"chmod", "install", "mkdir"})
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, {"chmod", "install", "mkdir"})
	not helpers.is_comment_line(line)
	_sh_ww(line)
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

# ── Made writable only to be deleted ─────────────────────────────────────

# `os.chmod(path, 0o777); func(path)` in an rmtree onerror handler, or a walk
# that makes a read-only tree writable before RemoveAll: the mode lives only
# until the removal a few lines on.
_first_arg(args) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*&?([A-Za-z_][\w.]*)\s*[,)]`, args, 1)
	count(m) > 0
}

_deleted_after(lines, i, _) if {
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 6]))
	regex.match(`\b(RemoveAll|rmtree|rm_rf|rm_r|rmSync|rimraf|remove_dir_all|deleteRecursively)\s*\(`, lines[k])
}

_deleted_after(lines, i, args) if {
	v := _first_arg(args)
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 3]))
	regex.match(concat("", [`\b(remove|Remove|unlink|unlinkSync|rmdir|rmdirSync|delete|func)\s*\(\s*&?`, replace(v, ".", `\.`), `\s*[,)]`]), lines[k])
}

# ── Ansible tasks ────────────────────────────────────────────────────────

_yaml(path) if endswith(path, ".yml")

_yaml(path) if endswith(path, ".yaml")

# The file is an Ansible task list: a module that writes files with a mode.
_ansible(content) if contains(content, "ansible.builtin.")

_ansible(content) if regex.match(`(?m)^\s*-?\s*(file|copy|template|unarchive|get_url|assemble|synchronize)\s*:(\s*$|\s+\w+=)`, content)

# `mode: '0777'`, `mode: 0666`, `mode: a+w`, and the k=v form `mode=0777`.
_ansible_modes(line) := {m[1] | some m in regex.find_all_string_submatch_n(`^\s*mode\s*:\s*["']?([^"'\s#]+)["']?\s*(#.*)?$`, line, 1)} | {m[1] | some m in regex.find_all_string_submatch_n(`(?:^|\s)mode=["']?([^"'\s]+)`, line, -1)}

findings contains finding if {
	some path, content in input.file_contents
	_yaml(path)
	contains(content, "mode")
	not _is_test(path)
	_ansible(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "mode")
	not helpers.is_comment_line(line)
	some tok in _ansible_modes(line)
	_ww_shell_mode(tok)
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
