# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_269

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-269",
	"name": "Improper Privilege Management",
	"description": "Privileges are dropped in the wrong order: the user ID is changed to a non-root user first, and the group ID or the supplementary groups are changed afterwards in the same function (or later on the same line, as in `setuid(u) < 0 || setgid(g) < 0`; a C/C++ function is bounded by a column-0 brace or a function header, so inline class methods are judged separately). Once the user ID is no longer root the later call fails (or, for seteuid, setegid and setgroups, has no permission), so the process keeps root's group and supplementary groups. Reported in C and C++ for setgid, setegid, setregid, setresgid, setgroups and initgroups after setuid, seteuid, setreuid or setresuid with a non-zero argument (also ::-qualified), and in Python for os.setgid, os.setegid, os.setregid, os.setresgid, os.setgroups and os.initgroups after os.setuid, os.seteuid, os.setreuid or os.setresuid. Not reported: the correct order (setgroups/initgroups, then setgid, then setuid), a regain of root (seteuid(0), os.seteuid(0)) between the two calls, a setgid(0) after the drop (the check that root cannot be regained), calls in different functions, and the names in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-269/",
	"languages": ["c", "cpp", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [269],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["privilege-mgmt", "privilege-drop", "cwe-269"],
}

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_lang(path) := "py" if endswith(path, ".py")

# String literals blanked, so a quoted example is not a call.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_pre := {"c": `(?:^|[^\w.>])(?:::)?`, "py": `\bos\.`}

# A user ID changed to a non-root value (the first argument is not a literal 0).
_uid_drop_re(lang) := concat("", [_pre[lang], `set(?:res|re|e)?uid\s*\(\s*(?:[^0\s)]|0\w)`])

# A group change: a non-zero gid, or the supplementary group list.
_gid_change_re(lang) := concat("", [_pre[lang], `(?:set(?:res|re|e)?gid\s*\(\s*(?:[^0\s)]|0\w)|setgroups\s*\(|initgroups\s*\()`])

# Root regained between the drop and the group change.
_regain_re(lang) := concat("", [_pre[lang], `(?:set(?:e)?uid\s*\(\s*0\s*\)|setreuid\s*\(\s*-1\s*,\s*0\s*\)|setresuid\s*\(\s*-1\s*,\s*0\s*,)`])

# C/C++: the last column-0 closing brace, or the last function header (a
# method defined inside a class body is indented, so its braces are too).
_fn_start(lines, i, "c") := max(array.concat([0], [j |
	some j in numbers.range(max([0, i - 200]), i)
	_c_boundary(lines[j])
]))

_c_boundary(l) if startswith(l, "}")

_c_boundary(l) if {
	contains(l, "(")
	regex.match(`^\s*(?:[\w:<>,*&]+\s+)+[*&]*~?[\w:]+\s*\([^;=]*\)\s*(?:const|noexcept|override|\s)*\{?\s*$`, l)
	not regex.match(`^\s*(?:if|else|while|for|switch|return|do|case|catch)\b`, l)
}

_fn_start(lines, i, "py") := max(array.concat([0], [j | some j in numbers.range(0, i); regex.match(`^\s*(?:async\s+)?def\s`, lines[j])]))

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, "uid")
	regex.match(`gid|groups`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`gid|groups`, line)
	not helpers.is_comment_line(line)
	regex.match(_gid_change_re(lang), _code(line))
	s := _fn_start(lines, i, lang)
	s <= i - 1
	drops := [u |
		some u in numbers.range(s, i - 1)
		contains(lines[u], "uid")
		not helpers.is_comment_line(lines[u])
		regex.match(_uid_drop_re(lang), _code(lines[u]))
		not _regained(lines, u, i, lang)
	]
	count(drops) > 0
	u := drops[0]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Group privileges changed after the user ID was dropped (line %d): without root this call fails or is refused, and the process keeps root's group and supplementary groups. Call setgroups/initgroups, then setgid, then setuid", [u + 1]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Both on one line: if (setuid(uid) < 0 || setgid(gid) < 0).
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, "uid")
	regex.match(`gid|groups`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "uid")
	regex.match(`gid|groups`, line)
	not helpers.is_comment_line(line)
	regex.match(concat("", [_uid_drop_re(lang), `.*`, _gid_change_re(lang)]), _code(line))
	finding := {
		"rule_id": metadata.id,
		"message": "Group privileges changed after the user ID was dropped on the same line: without root the group call fails or is refused, and the process keeps root's group and supplementary groups. Call setgroups/initgroups, then setgid, then setuid",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_regained(lines, u, i, lang) if {
	u + 1 <= i - 1
	some k in helpers.span(u + 1, i - 1)
	regex.match(_regain_re(lang), _code(lines[k]))
}
