# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_272

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-272",
	"name": "Least Privilege Violation",
	"description": "Root privilege that a privileged operation needed is kept after the operation. Two shapes are reported in C, C++, Python and Go: a chroot (chroot(), os.chroot() or chroot() imported from os, syscall.Chroot()/unix.Chroot(), or a Chroot field of a SysProcAttr literal for a child process, inline or on its own line) in a project that never drops its identity afterwards (no setuid/setgid/setresuid/setgroups/initgroups call, no drop_privileges/drop_root/lower_euid-style wrapper, no SysProcAttr Credential, set in the literal or assigned afterwards), so everything the jailed process does still runs as root; and a temporary return to root (seteuid(0), setegid(0), setreuid(-1, 0), setresuid(-1, 0, -1), os.seteuid(0)) that no later call in the file lowers again, directly or through such a wrapper. Not reported: a drop anywhere in the project's code for that language (a privsep module counts), an elevation inside a function whose name says it regains privileges (the caller lowers them), a Chroot field of any other struct (a configuration value), test code, and the names in comments or string literals. Whether the privileged section is longer than it needs to be is not decidable line by line and is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-272/",
	"languages": ["c", "cpp", "python", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [272],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["least-privilege", "chroot", "privilege-drop", "cwe-272"],
}

# ── Languages ────────────────────────────────────────────────────────────

_lang(path) := "c" if {
	some ext in {".c", ".cc", ".cpp", ".cxx"}
	endswith(path, ext)
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "go" if endswith(path, ".go")

# Cheap whole-file gates (substring tests, not regular expressions): the file
# names a chroot, or an elevation, at all.
_chroot_needle := {"c": "chroot", "py": "chroot", "go": "Chroot"}

_elevate_needles := {
	"c": {"seteuid", "setegid", "setreuid", "setregid", "setresuid", "setresgid"},
	"py": {"sete"},
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# Substrings every drop call or wrapper contains, to skip files cheaply.
_drop_needles := {
	"c": {"setuid", "setgid", "seteuid", "setegid", "setre", "setres", "setgroups", "initgroups", "setusercontext", "cap_set_proc", "capng_change_id", "priv", "Priv", "PRIV", "drop", "Drop", "DROP", "lower", "Lower", "_user", "_User", "_USER", "set_uid"},
	"py": {"setuid", "setgid", "seteuid", "setegid", "setre", "setres", "setgroups", "initgroups", "priv", "Priv", "PRIV", "drop", "Drop", "DROP", "lower", "Lower", "_user", "_User", "_USER", "set_uid"},
	"go": {"Set", "Credential", "priv", "Priv", "PRIV", "drop", "Drop", "DROP", "lower", "Lower", "_user", "_User", "_USER", "set_uid"},
}

# String literals are blanked so `printf("chroot(%s)")` is not a call.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# ── Chroot without a drop ────────────────────────────────────────────────

# A call to chroot itself: not `ops->chroot(`, `jail.chroot(`, `my_chroot(`.
# Python also writes it bare after `from os import chroot`.
_chroot_re := {
	"c": `(^|[^\w.>])chroot\s*\(`,
	"py": `\bos\.chroot\s*\(`,
	"go": `\b(syscall|unix)\.Chroot\s*\(|\bSysProcAttr\s*\{[^}]*\bChroot\s*:\s*[^\s,}]`,
}

_chroot_call(lines, i, "c", c) if regex.match(_chroot_re.c, c)

_chroot_call(lines, i, "go", c) if regex.match(_chroot_re.go, c)

_chroot_call(lines, i, "py", c) if regex.match(_chroot_re.py, c)

_chroot_call(lines, i, "py", c) if {
	regex.match(`(^|[^\w.])chroot\s*\(`, c)
	_py_imports_chroot(lines)
}

_py_imports_chroot(lines) if {
	some l in lines
	regex.match(`^\s*from\s+os\s+import\s+[^#]*\bchroot\b`, l)
}

# A `Chroot:` field on its own line belongs to SysProcAttr only when the
# composite literal it sits in was opened as one: `Options{Chroot: "/srv"}`
# is a configuration value, not a jail.
_chroot_call(lines, i, "go", c) if {
	regex.match(`^\s*Chroot\s*:\s*\S`, c)
	_in_sysprocattr(lines, i)
}

_in_sysprocattr(lines, i) if {
	i > 0
	opens := [j |
		some j in numbers.range(max([0, i - 12]), i - 1)
		regex.match(`\{\s*(//.*)?$`, lines[j])
	]
	count(opens) > 0
	regex.match(`\bSysProcAttr\s*\{`, lines[opens[count(opens) - 1]])
}

# A prototype or macro is not a call.
_declaration(line) if regex.match(`^\s*(#\s*define|extern\s|int\s+chroot\s*\()`, line)

# Any identity change, or a wrapper whose name says it drops privileges.
# drop_privileges(), lower_privs(), drop_root(), lower_euid(), dropRoot()...
_drop_wrapper := `(?i)\b\w*(drop|lower|revoke|relinquish|shed)_?(priv|root|e?[ug]id|perm)\w*\s*\(|\bpermanently_set_uid\s*\(|(?i)\b(become|switch_to|change_to)_user\s*\(`

_drop_re := {
	"c": concat("|", [`(^|[^\w.>])(set(e|re|res)?[ug]id|setgroups|initgroups|setusercontext|cap_set_proc|capng_change_id)\s*\(`, _drop_wrapper]),
	"py": concat("|", [`(^|[^\w.])(os\.)?(set(e|re|res)?[ug]id|setgroups|initgroups)\s*\(`, _drop_wrapper]),
	"go": concat("|", [`\b(syscall|unix)\.(Set(e|re|res)?[ug]id|Setgroups)\s*\(|\bCredential\s*:|\bsyscall\.Credential\s*\{|\.Credential\s*=`, _drop_wrapper]),
}

# The project drops privileges somewhere in this language's code. A privsep
# module in another file protects the chroot in this one.
_project_drops(lang) if {
	some path, content in input.file_contents
	_lang(path) == lang
	not helpers.is_test_path(path)
	_has_any(content, _drop_needles[lang])
	some line in split(content, "\n")
	_has_any(line, _drop_needles[lang])
	not helpers.is_comment_line(line)
	c := _code(line)
	regex.match(_drop_re[lang], c)
	not regex.match(object.get(_elevate_re, lang, "^$"), c) # seteuid(0) raises, it does not drop
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, _chroot_needle[lang])
	not helpers.is_test_path(path)
	not _project_drops(lang)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, _chroot_needle[lang])
	not helpers.is_comment_line(line)
	not _declaration(line)
	_chroot_call(lines, i, lang, _code(line))
	finding := {
		"rule_id": metadata.id,
		"message": "chroot is done but the program never drops root afterwards: a process that is still root can escape the jail and every file it opens is opened with full privileges. Call setgroups/setgid/setuid (os.setgid/os.setuid, a SysProcAttr Credential) to an unprivileged user right after entering the jail",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Elevation that is never lowered ──────────────────────────────────────

_elevate_re := {
	"c": `(^|[^\w.>])(sete[ug]id\s*\(\s*0\s*\)|setre[ug]id\s*\(\s*-1\s*,\s*0\s*\)|setres[ug]id\s*\(\s*-1\s*,\s*0\s*,\s*-1\s*\))`,
	"py": `(^|[^\w.])(os\.)?sete[ug]id\s*\(\s*0\s*\)`,
}

# A later identity change that is not itself another elevation.
_lowered_after(lines, i, lang) if {
	some j in numbers.range(i + 1, count(lines) - 1)
	not helpers.is_comment_line(lines[j])
	c := _code(lines[j])
	regex.match(_drop_re[lang], c)
	not regex.match(_elevate_re[lang], c)
}

# The nearest enclosing function header, by language.
_fn_header_re := {
	"c": `^[A-Za-z_][\w \t\*]*\b\w+\s*\([^;]*$`,
	"py": `^\s*(async\s+)?def\s+\w+\s*\(`,
}

# A wrapper that exists to regain privileges: its caller lowers them.
_in_regain_wrapper(lines, i, lang) if {
	heads := [j | some j in numbers.range(0, i); regex.match(_fn_header_re[lang], lines[j])]
	count(heads) > 0
	regex.match(`(?i)(restore|regain|raise|elevate|gain|acquire|become)_?(priv|root|admin|su)|priv\w*_(restore|regain|raise|elevate|gain|acquire|up)\b`, lines[heads[count(heads) - 1]])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _elevate_needles[lang])
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _elevate_needles[lang])
	not helpers.is_comment_line(line)
	regex.match(_elevate_re[lang], _code(line))
	not _lowered_after(lines, i, lang)
	not _in_regain_wrapper(lines, i, lang)
	finding := {
		"rule_id": metadata.id,
		"message": "The effective identity is raised back to root and never lowered again, so everything after this point runs as root. Restore the unprivileged effective uid/gid (seteuid(saved), os.seteuid(saved)) as soon as the privileged operation is done, ideally in a finally/cleanup path",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
