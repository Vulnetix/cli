# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_785

import rego.v1

metadata := {
	"id": "VNX-785",
	"name": "Use of Path Manipulation Function without Maximum-sized Buffer",
	"description": "Reports C/C++ calls to path functions that write a path of unbounded length into a caller buffer without taking its size: getwd() (always), realpath() whose output is a local array declared in the file with a size below PATH_MAX/MAXPATHLEN (4096), and the Windows PathCanonicalize/PathCombine/PathAppend family whose output array is declared smaller than MAX_PATH (260). The size is read from the nearest declaration of the array above the call (including 'char a[8], out[64];'), and a size macro #defined in the file as a number is judged by that number. realpath(p, NULL), output buffers whose declaration is not visible in the file (pointers, struct members) and size-taking functions such as getcwd() are deliberately not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-785/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [785],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["path-manipulation-call-to-uncanonical", "cwe-785"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}

_c_file(path) if {
	some ext in _exts
	endswith(path, ext)
}

_gate := `\b(getwd|realpath|Path(Canonicalize|Combine|Append)[AW]?)\s*\(`

_is_comment(line) if regex.match(`^\s*(//|/\*|\*)`, line)

_msg := "Path function writes into a buffer smaller than the maximum path length (or takes no size at all); a long path overflows it. Size the buffer PATH_MAX/MAX_PATH, pass NULL to realpath(), or use getcwd()/PathCchCanonicalizeEx with an explicit size"

# getwd(): no size argument at all.
findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`\bgetwd\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(^|[^\w.>])getwd\s*\(\s*[\w&]`, line)
	not _is_comment(line)
	not _in_string(line, "getwd")
	finding := _finding(path, i, line)
}

# realpath(src, dst) / PathXxx(dst, ...) with an undersized declared array.
findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate, line)
	not _is_comment(line)
	call := concat(" ", array.slice(lines, i, i + 3))
	some pair in _dest(call)
	kind := pair[0]
	dst := pair[1]
	size := _nearest_size(lines, i, dst)
	not _size_ok(kind, _resolve(content, size))
	finding := _finding(path, i, line)
}

# The size of the nearest array declaration of `name` at or above line i
# (within 300 lines), so a PATH_MAX buffer in one function does not excuse a
# small one of the same name in another. `char a[8], name[64];` counts.
_nearest_size(lines, i, name) := size if {
	re := concat("", [`\b(?:char|wchar_t|WCHAR|TCHAR|CHAR|_TCHAR)\s+(?:[^;{}()=]*,\s*)?\**\s*`, name, `\s*\[\s*([^\]]+?)\s*\]`])
	sizes := [m[1] |
		some k in numbers.range(max([0, i - 300]), i)
		contains(lines[k], name)
		not _is_comment(lines[k])
		some m in regex.find_all_string_submatch_n(re, lines[k], 1)
	]
	count(sizes) > 0
	size := trim_space(sizes[count(sizes) - 1])
}

# a plain identifier #defined in the file as a number (or as PATH_MAX) is
# judged by that definition
_resolve(content, s) := v if {
	regex.match(`^[A-Za-z_]\w*$`, s)
	ms := regex.find_all_string_submatch_n(concat("", [`(?m)^\s*#\s*define\s+`, s, `\s+\(?\s*([0-9]+|[A-Z_]\w*)\s*\)?\s*$`]), content, 1)
	count(ms) > 0
	v := ms[0][1]
} else := s

_dest(call) := posix | win if {
	posix := {["posix", m[1]] |
		some m in regex.find_all_string_submatch_n(`(?:^|[^\w])realpath\s*\(\s*[^,;]+,\s*&?\s*([A-Za-z_]\w*)\s*\)`, call, 1)
	}
	win := {["win", m[1]] |
		some m in regex.find_all_string_submatch_n(`\bPath(?:Canonicalize|Combine|Append)[AW]?\s*\(\s*&?\s*([A-Za-z_]\w*)\s*[,\[]`, call, 1)
	}
}

_size_ok(_, s) if regex.match(`PATH_MAX|MAXPATHLEN|MAX_PATH`, s)

_size_ok("posix", s) if {
	regex.match(`^\d+$`, s)
	to_number(s) >= 4096
}

_size_ok("win", s) if {
	regex.match(`^\d+$`, s)
	to_number(s) >= 260
}

# a size we cannot evaluate (sizeof expression, arithmetic on an unknown
# macro) is given the benefit of the doubt unless it is a plain identifier
_size_ok(_, s) if {
	not regex.match(`^\d+$`, s)
	not regex.match(`^[A-Za-z_]\w*$`, s)
}

_in_string(line, word) if regex.match(concat("", [`"[^"]*\b`, word, `\b[^"]*"`]), line)

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
