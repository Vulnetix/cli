# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_270

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-270",
	"name": "Privilege Context Switching Error",
	"description": "A program is started after only a temporary privilege drop: the effective user ID is lowered (seteuid(uid), setreuid(-1, uid), setresuid(-1, uid, -1), os.seteuid(uid), os.setreuid(-1, uid)) and then, in the same function and with no permanent drop in between, the process execs or spawns another program. The new program keeps root as its real user ID and can switch straight back to root, so the context switch into the less trusted program never happened. Reported in C and C++ for execl/execlp/execle/execv/execvp/execvpe/execve, system, popen and posix_spawn/posix_spawnp, and in Python for os.exec*, os.system, os.popen, os.spawn* and subprocess.run/call/check_call/check_output/Popen and asyncio.create_subprocess_exec/shell. A C/C++ function is bounded by a column-0 brace or a function header, so inline class methods are judged separately. Not reported: a permanent drop (setuid(uid), setresuid(uid, uid, uid), setreuid(uid, uid), os.setuid, or a drop_privileges()/drop_root()-style wrapper) before the exec, root restored with seteuid(0) before the exec (the program then runs as root deliberately; VNX-272 judges that), subprocess calls with user=, the two calls in different functions, and the names in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-270/",
	"languages": ["c", "cpp", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [270],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["privilege-context-switching", "privilege-drop", "cwe-270"],
}

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_lang(path) := "py" if endswith(path, ".py")

# String literals blanked, so a quoted example is not a call.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_nz := `(?:[^0\s)]|0\w)`

_pre := {"c": `(?:^|[^\w.>])(?:::)?`, "py": `\bos\.`}

# Only the effective user ID is lowered; the real (and saved) ID stays root.
_temp_drop_re(lang) := concat("", [_pre[lang], `(?:seteuid\s*\(\s*`, _nz, `|setreuid\s*\(\s*-1\s*,\s*`, _nz, `|setresuid\s*\(\s*-1\s*,\s*`, _nz, `[^,]*,\s*-1\s*\))`])

# A permanent drop, or root restored, between the two calls.
_settled_re(lang) := concat("", [_pre[lang], `(?:setuid\s*\(|setresuid\s*\(\s*[^-\s]|setreuid\s*\(\s*[^-\s]|seteuid\s*\(\s*0\s*\))`])

_exec_re := {
	"c": `(?:^|[^\w.>])(?:::)?(?:std::)?(?:exec(?:l|lp|le|v|vp|vpe|ve)|system|popen|posix_spawnp?)\s*\(`,
	"py": `\bos\.(?:exec[lv]p?e?|system|popen|spawn[lv]p?e?)\s*\(|\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\(|\basyncio\.create_subprocess_(?:exec|shell)\s*\(`,
}

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
	regex.match(`exec|system|popen|spawn|subprocess`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`exec|system|popen|spawn|subprocess`, line)
	not helpers.is_comment_line(line)
	c := _code(line)
	regex.match(_exec_re[lang], c)
	not regex.match(`\buser\s*=`, c)
	s := _fn_start(lines, i, lang)
	drops := [t |
		some t in numbers.range(s, i)
		contains(lines[t], "uid")
		not helpers.is_comment_line(lines[t])
		regex.match(_temp_drop_re(lang), _code(lines[t]))
		not _settled(lines, t, i, lang)
	]
	count(drops) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Program executed after only the effective user ID was lowered (line %d): its real user ID is still root, so it can switch back to root. Drop permanently (setgroups, setgid, setuid / setresuid(uid, uid, uid)) in the child before exec", [drops[count(drops) - 1] + 1]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A permanent drop or a return to root on a line after the temporary drop and
# up to the exec.
_settled(lines, t, i, lang) if {
	t + 1 <= i
	some k in numbers.range(t + 1, i)
	regex.match(_settled_re(lang), _code(lines[k]))
}

# A drop_privileges()/drop_root()/lower_privs()-style wrapper called in between.
_settled(lines, t, i, _) if {
	t + 1 <= i
	some k in numbers.range(t + 1, i)
	regex.match(`(?i)\b\w*(?:drop|lower|relinquish|revoke)_?(?:all_?)?(?:priv\w*|root|perms?)\s*\(`, lines[k])
	not helpers.is_comment_line(lines[k])
}
