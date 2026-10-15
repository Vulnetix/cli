# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_708

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-708",
	"name": "Incorrect Ownership Assignment",
	"description": "A file's owner or group is set from a value the caller controls, so the resource can be handed to an account outside the program's control sphere (or, in a privileged program, an arbitrary path can be given to the caller). Reported in C and C++: chown(), lchown(), fchown() and fchownat() whose path, uid or gid argument is taken from the command line or the environment (argv[...], optarg, getenv()/secure_getenv()) directly in the call, through a variable assigned from such a source up to 20 lines above (atoi(argv[2]), strtoul(optarg, ...)), or through one further assignment from that variable (getpwnam(name) then pw->pw_uid). A call broken over several lines is read up to three lines on. Not reported: ownership set to constants, to getuid()/geteuid()/getgid() alone, to values read from the program's own configuration or computed from stat() of another file, the uid/gid -1 (unchanged), a tainted value tested by a condition other than a null check before the call (if (!uid_allowed(uid)) return, if (uid < 1000)), test code, comments and string literals. Flows through other functions or files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-708/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [708],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["incorrect-ownership-assignment", "chown", "cwe-708"],
}

_is_c(path) if {
	some ext in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
	endswith(path, ext)
}

# A call of the libc function itself, not ops->chown( or my_chown(.
_chown_re := `(^|[^\w.>])(l|f)?chown(at)?\s*\(`

_src_re := `\bargv\s*\[|\boptarg\b|\b(secure_)?getenv\s*\(`

# String literals blanked, so a message naming argv is not a source.
_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

# The call's text from the function name on, joined with up to three
# following lines when the call is broken.
_call_text(lines, i) := t if {
	end := min([count(lines) - 1, i + 3])
	parts := [_code(lines[k]) | some k in numbers.range(i, end)]
	joined := concat(" ", parts)
	idx := regex.find_all_string_submatch_n(`(?:l|f)?chown(?:at)?\s*\([^;]*`, joined, 1)
	count(idx) > 0
	t := idx[0][0]
}

# The name assigned on a C line: `uid_t uid = ...`, `struct passwd *pw = ...`,
# `uid = ...`.
_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`(?:^|[\s\*\(])([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?=[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_first_hop(lines, i) := {v |
	some j in numbers.range(max([0, i - 20]), i - 1)
	l := _code(lines[j])
	not helpers.is_comment_line(l)
	regex.match(_src_re, l)
	v := _assigned(l)
}

_second_hop(lines, i, first) := {w |
	some j in numbers.range(max([0, i - 20]), i - 1)
	l := _code(lines[j])
	not helpers.is_comment_line(l)
	some v in first
	regex.match(concat("", [`=[^=].*\b`, v, `\b`]), l)
	w := _assigned(l)
	w != v
}

_tainted(_, _, text) if regex.match(_src_re, text)

_tainted(lines, i, text) if {
	i > 0
	first := _first_hop(lines, i)
	names := first | _second_hop(lines, i, first)
	some v in names
	regex.match(concat("", [`\b`, v, `\b`]), text)
	not _guarded(lines, i, v)
}

# A condition on the tainted name between source and sink that is not just a
# null test (`if (!uid_allowed(uid)) return 1;`, `if (uid < 1000)`): the value
# is validated before the call.
_guarded(lines, i, v) if {
	some j in numbers.range(max([0, i - 20]), i - 1)
	l := _code(lines[j])
	regex.match(`\b(if|assert)\s*\(`, l)
	not contains(l, "chown")
	regex.match(concat("", [`\b`, v, `\b`]), l)
	not regex.match(concat("", [`\b`, v, `\s*[!=]=\s*(NULL|nullptr|0)\b|\b(NULL|nullptr)\s*[!=]=\s*`, v, `\b|!\s*`, v, `\s*\)`]), l)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "chown")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "chown")
	not helpers.is_comment_line(line)
	regex.match(_chown_re, _code(line))
	not regex.match(`^\s*(#\s*define|extern\s|int\s+\w*chown)`, line)
	text := _call_text(lines, i)
	_tainted(lines, i, text)
	finding := {
		"rule_id": metadata.id,
		"message": "chown()/fchown()/lchown() takes its path, uid or gid from the command line or environment: the caller decides who owns the file. Resolve the owner from trusted configuration and validate it against an allow-list",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
