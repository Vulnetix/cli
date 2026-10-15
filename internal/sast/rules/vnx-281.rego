# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_281

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-281",
	"name": "Improper Preservation of Permissions",
	"description": "A file is replaced through a temporary copy without carrying the original's permissions over, so a file the administrator restricted (0600 credentials, an ACL or key store) comes back readable by group or others. Reported in C and C++ (sources and headers): rename(), renameat(), std::rename() or std::filesystem::rename() of a temporary whose creation in the 60 lines above gives it a default or group/other-accessible mode (fopen(tmp, \"w\"),std::ofstream/fstream, open(tmp, ...O_CREAT..., 0644), creat(tmp, 0666)), or an owner-only temporary (mkstemp, open with 0600) widened by a literal chmod/fchmod such as fchmod(fd, 0644). Not reported: a temporary whose mode is taken from elsewhere (st_mode, or chmod/fchmod with any mode that is not a literal: a variable, macro, cast or call), a temporary created under umask(077), an owner-only temporary (including open() whose mode sits two lines below the call) that is never widened, a rename that moves an existing file (such as a log opened with fopen(path, \"a\") and rotated),creating a new file without replacing one, and comments or string literals. Whether the replaced file was ever more restrictive than the new mode is decided at run time and is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-281/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [281],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["improper-preservation-permissions", "file-permissions", "cwe-281"],
}

_is_c(path) if {
	some ext in {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx"}
	endswith(path, ext)
}

# String literals blanked so a message naming rename() is not a call.
_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

_rename_re := `(^|[^\w.>])rename\s*\(\s*&?\s*([A-Za-z_]\w*)[^,]*,`

# renameat(olddirfd, oldpath, newdirfd, newpath): the temporary is the second argument.
_renameat_re := `(^|[^\w.>])renameat2?\s*\(\s*[^,()]+,\s*&?\s*([A-Za-z_]\w*)[^,]*,`

_renamed(line) := m[0][2] if {
	m := regex.find_all_string_submatch_n(_rename_re, line, 1)
	count(m) > 0
} else := m[0][2] if {
	m := regex.find_all_string_submatch_n(_renameat_re, line, 1)
	count(m) > 0
}

# The temporary's creation, and the mode it is created with.
# "default" is fopen(.., "w")/ofstream (0666 & ~umask); "owner" is mkstemp.
# fopen(.., "a") appends to a file that already exists (a log being rotated),
# so it is not a fresh temporary.
_created(lines, j, t) := "default" if {
	regex.match(concat("", [`\bfopen\s*\(\s*`, t, `\b[^,]*,\s*"w`]), lines[j])
}

_created(lines, j, t) := "default" if {
	regex.match(concat("", [`\b(std::)?(o|)fstream\s+\w+\s*[\({]\s*`, t, `\b`]), lines[j])
}

_created(lines, j, t) := "owner" if {
	regex.match(concat("", [`\bmko?stemps?\s*\(\s*`, t, `\b`]), lines[j])
}

_created(lines, j, t) := m if {
	regex.match(concat("", [`(^|[^\w.>])(open|creat)\s*\(\s*`, t, `\b`]), lines[j])
	nxt := concat(" ", [lines[j], lines[min([j + 1, count(lines) - 1])], lines[min([j + 2, count(lines) - 1])]])
	regex.match(`O_CREAT|\bcreat\s*\(`, nxt)
	m := _open_mode(nxt)
}

_open_mode(s) := m if {
	mm := regex.find_all_string_submatch_n(`,\s*(0[0-7]{3,4}|S_I[A-Z|\s]+)\s*\)`, s, 1)
	count(mm) > 0
	m := _class(mm[0][1])
} else := "default"

_class(mode) := "owner" if _class_owner(mode)

_class(mode) := "wide" if {
	not _class_owner(mode)
}

_class_owner(mode) if regex.match(`^\s*0?[0-7]00\b`, mode)

_class_owner(mode) if {
	contains(mode, "S_I")
	not regex.match(`GRP|OTH|RWXG|RWXO`, mode)
}

# chmod/fchmod calls between the creation and just after the rename.
_chmod_modes(lines, c, i) := [mm[0][1] |
	some k in numbers.range(c, min([count(lines) - 1, i + 3]))
	contains(lines[k], "chmod")
	not helpers.is_comment_line(lines[k])
	mm := regex.find_all_string_submatch_n(`\bf?chmod\s*\([^,]+,\s*([^;]*)\)\s*(;|\)|==|!=|<)`, lines[k], 1)
	count(mm) > 0
]

# The original's mode is consulted: st_mode near the copy, or a chmod whose
# mode is a variable.
_preserved(lines, c, i) if {
	some k in numbers.range(max([0, c - 20]), min([count(lines) - 1, i + 3]))
	contains(lines[k], "st_mode")
	not helpers.is_comment_line(lines[k])
}

_preserved(lines, c, i) if {
	some mode in _chmod_modes(lines, c, i)
	not _literal_mode(mode)
}

# umask(077) around the creation makes even fopen()'s default owner-only.
_preserved(lines, c, i) if {
	some k in numbers.range(max([0, c - 10]), i)
	contains(lines[k], "umask")
	regex.match(`\bumask\s*\(\s*0*77\s*\)`, lines[k])
}

# A literal mode: octal digits or S_I* constants (optionally masked). A
# variable, macro, cast or call is a mode taken from somewhere and not judged.
_literal_mode(mode) if regex.match(`^\s*(0[0-7]{2,4}|[1-7][0-7]{2})\s*(&.*)?$`, mode)

_literal_mode(mode) if regex.match(`^\s*S_I[A-Z]+(\s*\|\s*S_I[A-Z]+)*\s*$`, mode)

# The mode the replacement ends up with: a literal chmod that opens it to
# group/others wins over the creation mode.
_final(lines, c, i, _) := "wide" if _widening_chmod(lines, c, i)

_final(lines, c, i, created) := created if not _widening_chmod(lines, c, i)

_widening_chmod(lines, c, i) if {
	some mode in _chmod_modes(lines, c, i)
	_literal_mode(mode)
	_class(regex.replace(mode, `\s*&.*$`, "")) == "wide"
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "rename")
	regex.match(`fopen|fstream|open\s*\(|creat\s*\(|mkstemp|mkostemp`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "rename")
	not helpers.is_comment_line(line)
	t := _renamed(_code(line))
	cands := [j |
		some j in numbers.range(max([0, i - 60]), i - 1)
		contains(lines[j], t)
		not helpers.is_comment_line(lines[j])
		_created(lines, j, t)
	]
	count(cands) > 0
	c := cands[count(cands) - 1]
	not _preserved(lines, c, i)
	_final(lines, c, i, _created(lines, c, t)) != "owner"
	finding := {
		"rule_id": metadata.id,
		"message": "This file is replaced by a temporary created with a default or group/other-readable mode, so the original's permissions are lost (a 0600 file comes back as 0644). Create the temporary with mkstemp()/0600 and copy the original's st_mode onto it (fchmod(fd, st.st_mode)) before the rename",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
