# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_242

import rego.v1

metadata := {
	"id": "VNX-242",
	"name": "Use of Inherently Dangerous Function",
	"description": "A C or C++ function that cannot be called safely because it writes input of any length into a buffer it is given no size for: gets(), std::gets(), _getws(), getws(), _getts() and getwd(); and the C++ extraction of a stream (cin, wcin, or a variable declared as an istream, ifstream, istringstream, stringstream or fstream) into a char or wchar_t array with operator>> and no std::setw() before it, which is unbounded before C++20. Not reported: the bounded replacements (fgets, gets_s, fgetws, getcwd), method calls with the same name (conn.gets(), p->gets()), prototypes, #define/#undef lines, extraction into std::string or numbers, a shift expression, comments and string literals. atoi/atol/atof are not inherently dangerous (they are unsafe only on unvalidated input, CWE-676) and are not reported here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-242/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [242],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["dangerous-function", "cwe-242", "buffer-overflow"],
}

_c_ext(path) if regex.match(`\.(?:c|h|cc|cpp|cxx|hpp|hh|hxx)$`, path)

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*|#)`, line)

# String and character literals are blanked.
_code(line) := c if {
	a := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)
	c := regex.replace(a, `'(?:[^'\\]|\\.)*'`, `''`)
}

_gets_re := `(?:^|[^\w.>:]|\bstd::)(gets|_getws|getws|_getts|getwd)\s*\(`

_prototype_re := `\b(?:char|wchar_t|TCHAR|_TCHAR)\s*\*\s*(?:gets|_getws|getws|_getts|getwd)\s*\(`

_mentions(s) if {
	some w in ["gets(", "gets (", "getws(", "getts(", "getwd(", "getws (", "getwd ("]
	contains(s, w)
}

findings contains finding if {
	some path, content in input.file_contents
	_c_ext(path)
	_mentions(content)
	lines := split(content, "\n")
	some i, line in lines
	_mentions(line)
	not _is_comment(line)
	code := _code(line)
	m := regex.find_all_string_submatch_n(_gets_re, code, 1)
	count(m) == 1
	not regex.match(_prototype_re, code)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s() writes input of any length into a buffer it has no size for and cannot be used safely. Use fgets()/getline() (or getcwd() for getwd())", [m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_char_arrays(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b(?:char|wchar_t|TCHAR)\s+([A-Za-z_]\w*)\s*\[`, content, -1)
}

_streams(content) := {"cin", "wcin"} | {m[1] |
	some m in regex.find_all_string_submatch_n(`\b(?:std::)?w?(?:ifstream|istream|istringstream|stringstream|fstream)\s+([A-Za-z_]\w*)`, content, -1)
}

findings contains finding if {
	some path, content in input.file_contents
	_c_ext(path)
	contains(content, ">>")
	_includes_streams(content)
	regex.match(`\b(?:char|wchar_t|TCHAR)\s+\w+\s*\[`, content)
	arrays := _char_arrays(content)
	streams := _streams(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ">>")
	not _is_comment(line)
	code := _code(line)
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.:])(?:std::)?([A-Za-z_]\w*)\s*>>(.*)$`, code, 1)
	m[1] in streams
	ops := split(m[2], ">>")
	some k, op in ops
	target := regex.replace(trim_space(op), `[;)\s].*$`, "")
	target in arrays
	not _setw_before(ops, k)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("operator>> reads a whole word into the char array %s with no width limit, overflowing it on long input. Read into std::string, or put std::setw(sizeof %s) before it", [target, target]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# operator>> on a stream needs one of the stream headers.
_includes_streams(content) if {
	some h in ["iostream", "fstream", "sstream", "istream"]
	contains(content, h)
}

_setw_before(ops, k) if {
	k > 0
	regex.match(`\bsetw\s*\(`, ops[k - 1])
}
