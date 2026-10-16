# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_266

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-266",
	"name": "Incorrect Privilege Assignment",
	"description": "Root is assigned as a process's whole identity, or a file is given the set-user-ID or set-group-ID bit. Reported in C and C++: setuid(0), setgid(0), setreuid(0, 0), setregid(0, 0), setresuid(0, 0, 0) and setresgid(0, 0, 0) (also ::-qualified), which make root the real, effective and saved identity so nothing later in the process or its children runs unprivileged, in a function that never drops to another user; and chmod/fchmod/fchmodat with S_ISUID or S_ISGID or an octal mode with the 04000/02000 bit (04755, 06755, 02755), also when the mode is on the line after the call opens, and C++17 std::filesystem::permissions adding perms::set_uid or perms::set_gid. Reported in Python: os.setuid(0), os.setgid(0), os.setreuid(0, 0), os.setresuid(0, 0, 0) and the gid forms, and os.chmod/os.fchmod/os.lchmod (or a chmod imported from os, or pathlib Path.chmod) with stat.S_ISUID/S_ISGID or a 0o4xxx/0o2xxx/0o6xxx mode. Not reported: a temporary seteuid(0) (VNX-272 judges whether it is lowered again), a function that also drops to a non-root user (setuid(pw->pw_uid), including the `setuid(0) != -1` check that a drop is irreversible), testing or clearing the bits (st_mode & S_ISUID, mode & ~S_ISUID), ordinary modes (0755, 0644), the set-group-ID bit alone on a directory made by mkdir/makedirs in the six lines above (group inheritance for a shared directory), perm_options::remove, wrappers such as my_setuid(), and the calls in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-266/",
	"languages": ["c", "cpp", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [266],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["privilege", "setuid", "cwe-266"],
}

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_lang(path) := "py" if endswith(path, ".py")

# String literals blanked, so a quoted example is not a call.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_root_id_re := {
	"c": `(?:^|[^\w.>])(?:::)?(?:set[ug]id\s*\(\s*(?:\(\s*[ug]id_t\s*\)\s*)?0\s*\)|setre[ug]id\s*\(\s*0\s*,\s*0\s*\)|setres[ug]id\s*\(\s*0\s*,\s*0\s*,\s*0\s*\))`,
	"py": `\bos\.(?:set[ug]id\(\s*0\s*\)|setre[ug]id\(\s*0\s*,\s*0\s*\)|setres[ug]id\(\s*0\s*,\s*0\s*,\s*0\s*\))`,
}

# A change to a non-root user identity: the function drops privileges itself.
_drop_re := {
	"c": `(?:^|[^\w.>])(?:::)?set(?:res|re)?uid\s*\(\s*(?:[^0\s)]|0\w)`,
	"py": `\bos\.set(?:res|re)?uid\(\s*(?:[^0\s)]|0\w)`,
}

_chmod_re := {
	"c": `(?:^|[^\w.>])(?:::)?f?chmod(?:at)?\s*\(`,
	"py": `\bos\.(?:f|l)?chmod\s*\(|^\s*(?:return\s+)?(?:f|l)?chmod\s*\(|\.chmod\s*\(\s*(?:mode\s*=\s*)?0o[2467][0-7]{3}\b`,
}

_suid_mode_re := {
	"c": `\bS_IS[UG]ID\b|,\s*0[2467][0-7]{3}\b`,
	"py": `\bS_IS[UG]ID\b|,\s*(?:mode\s*=\s*)?0o[2467][0-7]{3}\b|\.chmod\s*\(\s*(?:mode\s*=\s*)?0o[2467][0-7]{3}\b`,
}

_clears_re := `~\s*\(?\s*(?:stat\.)?S_IS[UG]ID|&\s*~`

# A call broken after its opening parenthesis or a comma takes its mode from
# the next two lines.
_call_text(_, _, c) := c if not regex.match(`[(,]\s*$`, c)

_call_text(lines, i, c) := concat(" ", array.concat([c], [_code(l) | some l in array.slice(lines, i + 1, i + 3)])) if {
	regex.match(`[(,]\s*$`, c)
}

# A bare chmod() in Python is os.chmod only when it was imported from os.
_py_chmod_is_os("c", _, _)

_py_chmod_is_os("py", _, line) if regex.match(`\bos\.(?:f|l)?chmod\s*\(|\.chmod\s*\(`, line)

_py_chmod_is_os("py", content, line) if {
	not regex.match(`\bos\.(?:f|l)?chmod\s*\(|\.chmod\s*\(`, line)
	regex.match(`(?m)^\s*from\s+os\s+import\s+.*\b(?:f|l)?chmod\b`, content)
}

_gate(c) if contains(c, "set")

_gate(c) if contains(c, "chmod")

# Bounds of the enclosing function: column-0 closing braces in C, def lines in Python.
_fn_bounds(lines, i, "c") := [s, e] if {
	before := [j | some j in numbers.range(0, i); startswith(lines[j], "}")]
	after := [j | some j in numbers.range(i, count(lines) - 1); startswith(lines[j], "}")]
	s := max(array.concat([0], before))
	e := min(array.concat([count(lines) - 1], after))
}

_fn_bounds(lines, i, "py") := [s, e] if {
	before := [j | some j in numbers.range(0, i); regex.match(`^\s*(?:async\s+)?def\s`, lines[j])]
	after := [j | some j in helpers.span(i + 1, count(lines) - 1); regex.match(`^\s*(?:async\s+)?def\s|^class\s`, lines[j])]
	s := max(array.concat([0], before))
	e := min(array.concat([count(lines) - 1], after))
}

_drops_in_function(lines, i, lang) if {
	b := _fn_bounds(lines, i, lang)
	some j in numbers.range(b[0], b[1])
	l := lines[j]
	contains(l, "uid")
	not helpers.is_comment_line(l)
	regex.match(_drop_re[lang], _code(l))
}

_msg_root := "Root is assigned as the process's real, effective and saved identity: everything after this, including child processes, runs as root with no way back. Do the privileged step with a temporary seteuid(0) and drop permanently to an unprivileged user afterwards"

_msg_suid := "File given the set-user-ID/set-group-ID bit: whoever runs it gets the owner's (often root's) privileges. Grant a narrow capability or use a privileged helper with a fixed interface instead"

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "id")
	not helpers.is_comment_line(line)
	regex.match(_root_id_re[lang], _code(line))
	not _drops_in_function(lines, i, lang)
	finding := _finding(path, i, line, _msg_root)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, "chmod")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "chmod")
	not helpers.is_comment_line(line)
	regex.match(_chmod_re[lang], _code(line))
	_py_chmod_is_os(lang, content, line)
	c := _call_text(lines, i, _code(line))
	regex.match(_suid_mode_re[lang], c)
	not regex.match(_clears_re, c)
	not _setgid_on_new_dir(lines, i, c)
	finding := _finding(path, i, line, _msg_suid)
}

# C++17 std::filesystem::permissions adding perms::set_uid / perms::set_gid.
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "c"
	contains(content, "perms::set_")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "permissions")
	not helpers.is_comment_line(line)
	regex.match(`(?:^|[^\w.>])(?:(?:std::)?(?:filesystem|fs)::)?permissions\s*\(`, _code(line))
	c := concat(" ", [_code(l) | some l in array.slice(lines, i, i + 3)])
	regex.match(`\bperms::set_[ug]id\b`, c)
	not regex.match(`perm_options::remove`, c)
	finding := _finding(path, i, line, _msg_suid)
}

# The set-group-ID bit alone on a directory created just above is group
# inheritance for a shared directory, not a privilege grant.
_setgid_on_new_dir(lines, i, c) if {
	regex.match(`\bS_ISGID\b|\b0o?2[0-7]{3}\b`, c)
	not regex.match(`\bS_ISUID\b|\b0o?[4567][0-7]{3}\b`, c)
	m := regex.find_all_string_submatch_n(`chmod\s*\(\s*([A-Za-z_][\w.]*)\s*,|([A-Za-z_]\w*)\.chmod\s*\(`, c, 1)
	count(m) > 0
	arg := concat("", [m[0][1], m[0][2]])
	arg != ""
	some j in numbers.range(max([0, i - 6]), i - 1)
	regex.match(`\b(?:mkdir|makedirs|mkdtemp|mkdirat)\b`, lines[j])
	contains(lines[j], arg)
}
