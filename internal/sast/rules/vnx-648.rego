# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_648

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-648",
	"name": "Privilege drop in the wrong order or without clearing supplementary groups",
	"description": "The POSIX identity calls are used in a way that leaves privilege behind (CWE-648, CERT POS36-C). Reported in C, C++ and Python (os.*), on the line of the user-id call: (1) a user-id drop (setuid, seteuid, setreuid, setresuid, also ::setuid and os.setuid) followed within 15 lines of the same function by a group call (setgid, setegid, setregid, setresgid, setgroups, initgroups): once the user id is unprivileged the group change fails or is silently skipped, so the process keeps root's group; (2) a permanent drop to another user (setuid, setreuid, setresuid with an argument that is not getuid() or a variable assigned from it) in a file that never calls setgroups, initgroups or setusercontext, so the supplementary groups of the starting identity (root's, typically) are kept. Not reported: raising to root (an argument of 0, as in seteuid(0)) which vnx-272 covers, restoring a saved privileged id (an argument named saved/orig/old/prev/root..., as in seteuid(saved_euid)), where uid before gid is the correct order, a drop back to the real user id (setuid(getuid())), temporary seteuid switches, the correct setgroups/initgroups, setgid, setuid order, comments and string literals. Unchecked return values of these calls are vnx-273.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-648/",
	"languages": ["c", "cpp", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [648],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["incorrect-privilege-use", "privilege-drop", "setuid", "cwe-648"],
}

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_lang(path) := "py" if endswith(path, ".py")

_uid_re := {
	"c": `(?:^|[^\w.>])(?:::)?(set(?:e|re|res)?uid)\s*\((.*)$`,
	"py": `\bos\.(set(?:e|re|res)?uid)\s*\((.*)$`,
}

_gid_re := {
	"c": `(?:^|[^\w.>])(?:::)?(?:set(?:e|re|res)?gid|setgroups|initgroups)\s*\(`,
	"py": `\bos\.(?:set(?:e|re|res)?gid|setgroups|initgroups)\s*\(`,
}

_groups_re := {
	"c": `(?:^|[^\w.>])(?:::)?(?:setgroups|initgroups|setusercontext)\s*\(`,
	"py": `\bos\.(?:setgroups|initgroups)\s*\(`,
}

# String literals blanked, so a message naming the calls is not code.
_code(line) := regex.replace(line, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, `""`)

# The argument list of the call (text up to the call's closing parenthesis,
# with getuid() folded to one token).
_args(rest) := [trim_space(a) | some a in split(split(regex.replace(rest, `(?:os\.)?getuid\(\s*\)`, "GETUID"), ")")[0], ",")]

# Raising to root: every argument is 0 or -1 and at least one is 0.
_raise(args) if {
	some a in args
	a == "0"
	every b in args {
		b in {"0", "-1"}
	}
}

# Restoring a saved privileged id (seteuid(saved_euid)) before the group is
# the correct order for regaining privilege.
_raise(args) if {
	some a in args
	regex.match(`(?i)^\w*(?:saved|orig|old|prev|root|privileged)\w*$`, a)
}

# Back to the real user id.
_real_uid(args, content) if {
	every a in args {
		_real_arg(a, content)
	}
}

_real_arg("GETUID", _)

_real_arg("-1", _)

_real_arg(a, content) if {
	regex.match(`^[A-Za-z_]\w*$`, a)
	regex.match(concat("", [`\b`, a, `\s*=\s*(?:os\.)?getuid\(\s*\)`]), content)
}

# End of the enclosing function between the drop and line k.
_fn_boundary(lines, i, k, "c") if {
	some m in numbers.range(i + 1, k)
	startswith(lines[m], "}")
}

_fn_boundary(lines, i, k, "py") if {
	some m in numbers.range(i + 1, k)
	regex.match(`^\s*(?:async\s+)?def\s`, lines[m])
}

_gid_after(lines, i, lang) if {
	end := min([count(lines) - 1, i + 15])
	i + 1 <= end
	some k in numbers.range(i + 1, end)
	not helpers.is_comment_line(lines[k])
	regex.match(_gid_re[lang], _code(lines[k]))
	not _fn_boundary(lines, i, k, lang)
}

_msg(lines, i, lang, _, _, _) := "The user id is dropped before the group id: once it is unprivileged, the setgid/setgroups call that follows fails or is skipped and the process keeps the privileged group. Call setgroups/initgroups, then setgid, then setuid" if {
	_gid_after(lines, i, lang)
} else := "The process switches to another user without clearing its supplementary groups (no setgroups/initgroups in this file), so it keeps the starting identity's groups. Call setgroups() or initgroups() before setgid and setuid" if {
	not _gid_after(lines, i, lang)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(`set(?:e|re|res)?uid\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "uid")
	not helpers.is_comment_line(line)
	c := _code(line)
	m := regex.find_all_string_submatch_n(_uid_re[lang], c, 1)
	count(m) > 0
	args := _args(m[0][2])
	not _raise(args)
	_reportable(lines, i, lang, m[0][1], args, content)
	msg := _msg(lines, i, lang, m[0][1], args, content)
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_reportable(lines, i, lang, _, _, _) if _gid_after(lines, i, lang)

_reportable(_, _, lang, fn, args, content) if {
	fn in {"setuid", "setreuid", "setresuid"}
	not _real_uid(args, content)
	not regex.match(_groups_re[lang], content)
}
