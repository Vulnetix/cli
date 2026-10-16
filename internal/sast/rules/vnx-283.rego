# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_283

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-283",
	"name": "Unverified Ownership",
	"description": "A file is trusted because of its permission bits alone: the code tests whether group or others may read or write it (st_mode & S_IWOTH/S_IWGRP/S_IRWXG/S_IRWXO/S_IROTH/S_IRGRP, or an octal mask such as 022, 077, 0002, in either operand order, across a line break after the &, or on a variable the mode was copied into a few lines above) or, in C++, std::filesystem permissions() against group_*/others_* bits, but never compares st_uid with the expected owner within 25 lines. A file with tight modes that belongs to another user still passes, so an attacker who owns a key, config or plugin file the program loads can control it. Reported in C and C++. Not reported: a check that also compares st_uid (against getuid()/geteuid()/0 or a looked-up user), an executable-bit or file-type test (S_IXUSR, S_ISREG), copying or clearing a mode (st_mode & 07777, st_mode & ~(S_IRWXG|S_IRWXO)), printing or logging the bits (printf, syslog, std::cout), setting permissions (std::filesystem::permissions(p, perms::others_all, perm_options::remove)), ls-style formatting of a mode string ((st_mode & S_IROTH) ? 'r' : '-') and comments or string literals. Ownership verified in a different function is not visible to this rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-283/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [283],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["unverified-ownership", "file-permissions", "cwe-283"],
}

_is_c(path) if {
	some ext in {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hpp"}
	endswith(path, ext)
}

_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

# Group/other permission bits as a mask.
_bits := `(S_I(W|R)(GRP|OTH)|S_IRWX[GO]|0+[0-7]{1,2}\b)`

# A mode test against group/other bits, either operand order.
_check_re := concat("", [`st_mode\s*\)?\s*&\s*\(?\s*`, _bits, `|`, _bits, `\s*\)?\s*&\s*\(?\s*[\w.>\-]*st_mode\b|&\s*\(?\s*[\w:]*perms::(group|others)_(write|read|all)\b`])

# The test written across a line break: "st.st_mode &" / "(S_IWGRP | S_IWOTH)".
_split_re := concat("", [`^\s*\(?\s*`, _bits])

_is_test(lines, i, c) if regex.match(_check_re, c)

_is_test(lines, i, c) if {
	regex.match(`st_mode\s*\)?\s*&\s*$`, c)
	i + 1 < count(lines)
	regex.match(_split_re, lines[i + 1])
}

# The mode copied into a variable, then tested a few lines below.
_var_test(lines, i, c) if {
	not regex.match(`st_mode|perms::`, c)
	contains(c, "&")
	some k in numbers.range(max([0, i - 6]), i - 1)
	contains(lines[k], "st_mode")
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*\(?[\w.>\-]*st_mode\s*\)?\s*;`, lines[k], 1)
	count(m) > 0
	regex.match(concat("", [`\b`, m[0][1], `\s*&\s*\(?\s*`, _bits]), c)
}

_candidate(lines, i, c) if {
	regex.match(`st_mode|perms::`, c)
	_is_test(lines, i, c)
}

_candidate(lines, i, c) if _var_test(lines, i, c)

_continuation(lines, i) if {
	i > 0
	regex.match(`(\|\||&&)\s*$`, _code(lines[i - 1]))
	regex.match(`st_mode|perms::`, lines[i - 1])
	_is_test(lines, i - 1, _code(lines[i - 1]))
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(`st_mode|perms::`, content)
	regex.match(`S_I(W|R)(GRP|OTH)|S_IRWX[GO]|&\s*\(?\s*0+[0-7]{1,2}\b|perms::(group|others)_`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "&")
	not helpers.is_comment_line(line)
	c := _code(line)
	_candidate(lines, i, c)
	not contains(c, "chmod")
	# The continuation of a condition whose previous line is itself a reported test is one condition.
	not _continuation(lines, i)
	# Printing or logging the bits is not a trust decision.
	not regex.match(`\b(printf|fprintf|snprintf|sprintf|dprintf|syslog|puts|fputs)\s*\(|\bstd::(cout|cerr|format)\b|\b(cout|cerr)\s*<<`, c)
	# ls-style formatting of a mode string, not a trust decision.
	not regex.match(`\?\s*'.'\s*:`, c)
	not contains(helpers.code_window(lines, i, 25, 25), "st_uid")
	finding := {
		"rule_id": metadata.id,
		"message": "The file is trusted because its permission bits are tight, but its owner is never checked: a file owned by another user with mode 0600 still passes. Compare st_uid with the expected owner (getuid()/geteuid() or root) before trusting the file",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
