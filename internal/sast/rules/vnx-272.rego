# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_272

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-272",
	"name": "Least Privilege Violation",
	"description": "Root privilege that a privileged operation needed is kept after the operation. Two shapes are reported in C, C++, Python and Go: a chroot (chroot() or ::chroot(), os.chroot(), chroot() imported from os or called on an `import os as` alias, syscall.Chroot()/unix.Chroot(), or a Chroot field of a SysProcAttr literal for a child process, inline or on its own line) in a project that never drops its identity afterwards (no setuid/setgid/setresuid/setgroups/initgroups call, no drop_privileges/drop_root/lower_euid/priv_drop/switch_user-style wrapper, no SysProcAttr Credential, set in the literal or assigned afterwards), so everything the jailed process does still runs as root; and a return to root (seteuid(0), setegid(0), setuid(0) and setgid(0) in a setuid-root helper, setreuid(-1, 0), setresuid(-1, 0, -1), os.seteuid(0), os.setuid(0)) that no later call in the file lowers again, directly or through such a wrapper. Not reported: a drop anywhere in the project's code for that language (a privsep module counts), a check that root can no longer be regained after a drop (`if (setuid(0) != -1) abort();`, `if (!seteuid(0))`, a Python try whose else clause raises), an elevation inside a function whose name says it regains privileges (the caller lowers them), a Chroot field of any other struct (a configuration value), test code, and the names in comments or string literals. Whether the privileged section is longer than it needs to be is not decidable line by line and is not judged.",
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
	"c": {"setuid", "setgid", "seteuid", "setegid", "setreuid", "setregid", "setresuid", "setresgid"},
	"py": {"setuid", "setgid", "sete"},
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# A line worth the drop regex: a direct identity call, or a word that names
# a drop next to one that names what is dropped (drop_privileges, lowerEuid).
# "lower" alone is every strings.ToLower; "priv" alone is every "private".
_direct_needles := {
	"c": {"setuid", "setgid", "seteuid", "setegid", "setre", "setres", "setgroups", "initgroups", "setusercontext", "cap_set_proc", "capng_change_id"},
	"py": {"setuid", "setgid", "seteuid", "setegid", "setre", "setres", "setgroups", "initgroups"},
	"go": {"syscall.Set", "unix.Set", "Credential"},
}

_file_may_drop(content, lang) if _has_any(content, _direct_needles[lang])

_file_may_drop(content, _) if _has_any(lower(content), _wrapper_needles)

# Lower-cased spellings of the wrapper names the drop regex accepts.
_wrapper_needles := {
	"drop_priv", "droppriv", "drop_root", "droproot", "drop_uid", "dropuid", "drop_euid", "dropeuid",
	"drop_gid", "dropgid", "drop_egid", "dropegid", "drop_perm", "dropperm", "lower_priv", "lowerpriv",
	"lower_root", "lowerroot", "lower_uid", "loweruid", "lower_euid", "lowereuid", "lower_gid", "lowergid",
	"lower_egid", "loweregid", "lower_perm", "lowerperm", "revoke_priv", "revokepriv", "revoke_root", "revokeroot",
	"relinquish", "shed_priv", "shedpriv", "shed_root", "shedroot", "priv_drop", "privdrop", "privsep_drop", "privs_drop",
	"privileges_drop", "priv_lower", "privlower", "permanently_set_uid", "become_user", "switch_to_user", "change_to_user",
	"switch_user", "change_user",
}

_drop_candidate(line, lang) if _has_any(line, _direct_needles[lang])

_drop_candidate(line, _) if {
	l := lower(line)
	_has_any(l, {"drop", "lower", "revoke", "relinquish", "shed", "_user", "set_uid"})
	_has_any(l, {"priv", "root", "uid", "gid", "perm", "_user"})
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

# `import os as _os` then `_os.chroot(...)`.
_chroot_call(lines, i, "py", c) if {
	regex.match(`\b\w+\.chroot\s*\(`, c)
	some l in lines
	some m in regex.find_all_string_submatch_n(`^\s*import\s+os\s+as\s+(\w+)\s*(#.*)?$`, l, 1)
	regex.match(concat("", [`(^|[^\w.])`, m[1], `\.chroot\s*\(`]), c)
}

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
_drop_wrapper := `(?i)\b\w*(drop|lower|revoke|relinquish|shed)_?(priv|root|e?[ug]id|perm)\w*\s*\(|(?i)\b\w*priv\w*?_?(drop|lower|revoke|shed)\w*\s*\(|\bpermanently_set_uid\s*\(|(?i)\b(become|switch_to|change_to|switch|change)_user\s*\(`

_drop_re := {
	"c": concat("|", [`(^|[^\w.>])(set(e|re|res)?[ug]id|setgroups|initgroups|setusercontext|cap_set_proc|capng_change_id)\s*\(`, _drop_wrapper]),
	"py": concat("|", [`(^|[^\w.])(\w+\.)?(set(e|re|res)?[ug]id|setgroups|initgroups)\s*\(`, _drop_wrapper]),
	"go": concat("|", [`\b(syscall|unix)\.(Set(e|re|res)?[ug]id|Setgroups)\s*\(|\bCredential\s*:|\bsyscall\.Credential\s*\{|\.Credential\s*=`, _drop_wrapper]),
}

# The project drops privileges somewhere in this language's code. A privsep
# module in another file protects the chroot in this one.
_project_drops(lang) if {
	some path, content in input.file_contents
	_lang(path) == lang
	not helpers.is_test_path(path)
	_file_may_drop(content, lang)
	some line in split(content, "\n")
	_drop_candidate(line, lang)
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
	"c": `(^|[^\w.>])(sete?[ug]id\s*\(\s*0\s*\)|setre[ug]id\s*\(\s*-1\s*,\s*0\s*\)|setres[ug]id\s*\(\s*-1\s*,\s*0\s*,\s*-1\s*\))`,
	"py": `(^|[^\w.])(os\.)?sete?[ug]id\s*\(\s*0\s*\)`,
}

# The call checks that root can NOT be regained after a drop: success is the
# error (`if (setuid(0) != -1) abort();`, `if (!seteuid(0))`), or, in Python,
# the try's else clause raises.
_verifies(lines, i, _) if regex.match(`set\w*id\s*\([^()]*\)\s*(!=\s*-\s*1|==\s*0\b|>=\s*0\b)|!\s*\(?\s*(::)?set\w*id\s*\(`, lines[i])

_verifies(lines, i, "py") if {
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 6]))
	regex.match(`^\s*else\s*:\s*(#.*)?$`, lines[j])
	some k in numbers.range(j + 1, min([count(lines) - 1, j + 2]))
	regex.match(`\braise\b|\bsys\.exit\s*\(|\bos\._exit\s*\(|\babort\s*\(`, lines[k])
}

# A later identity change that is not itself another elevation.
_lowered_after(lines, i, lang) if {
	some j in helpers.span(i + 1, count(lines) - 1)
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
	not _verifies(lines, i, lang)
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
