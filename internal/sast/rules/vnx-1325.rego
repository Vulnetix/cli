# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1325

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1325",
	"name": "Improperly Controlled Sequential Memory Allocation",
	"description": "An allocation is sized by a value that arrived from outside the program (a request, a length prefix, a header, a command-line argument) with no upper bound. An attacker who controls the size, or the iteration count of a loop that allocates, can exhaust memory and cause denial of service. Allocations sized by the length of data already in memory, by a constant, or by a value the program computed itself are not reported: they cannot grow past what the program already holds.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1325/",
	"languages": ["c", "cpp", "go", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1325],
	"capec": ["CAPEC-130"],
	"attack_technique": ["T1499"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["memory", "allocation", "dos", "loop", "cwe-1325"],
}

_skip(path) if endswith(path, ".lock")

_skip(path) if endswith(path, ".sum")

_skip(path) if endswith(path, ".min.js")

# ── Sources of attacker-controlled sizes ─────────────────────────────────

# Go: a number parsed from text, a length header or prefix, a request value.
_go_source := `(strconv\.(Atoi|ParseInt|ParseUint)\(|ContentLength|Content-Length|\.FormValue\(|\.PostFormValue\(|URL\.Query\(\)|binary\.(BigEndian|LittleEndian)\.Uint|binary\.Read\(|ReadUvarint|ReadVarint|os\.Args|\bflag\.(Int|Uint)|\.Header\.Get\()`

_java_source := `(getContentLength|getContentLengthLong|getParameter\(|getHeader\(|readInt\(|readLong\(|parseInt\(|parseLong\(|Integer\.valueOf\()`

_c_source := `(atoi\(|atol\(|strtol\(|strtoul\(|ntohl\(|ntohs\(|argv\[|fread\(|recv\(|scanf\()`

# A size that is only the length of something already held is not amplification.
_strip_len(s) := regex.replace(s, `\b(len|cap|sizeof|length|size)\s*\([^()]*\)`, "")

# ── Go ───────────────────────────────────────────────────────────────────

_go_make_args(line) := args if {
	m := regex.find_all_string_submatch_n(`\bmake\(\s*(?:\[\][^,()]*|map\[[^\]]*\][^,()]*|chan\s+[^,()]*)\s*,\s*(.*)$`, line, 1)
	count(m) > 0
	args := _strip_len(m[0][1])
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	not endswith(path, "_test.go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	args := _go_make_args(line)
	_go_tainted(lines, i, line, args)
	finding := {
		"rule_id": metadata.id,
		"message": _go_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The size expression itself reads the source…
_go_tainted(_, _, _, args) if regex.match(_go_source, args)

# …or names a variable that a nearby line assigned from one.
_go_tainted(lines, i, _, args) if {
	some v in helpers.tainted_names(lines, i, 25, _go_source)
	regex.match(concat("", [`\b`, v, `\b`]), args)
}

# ── Java ─────────────────────────────────────────────────────────────────

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\bnew\s+(?:byte|char|int|long)\s*\[\s*([^\]]+)\]`, line, 1)
	count(m) > 0
	size := _strip_len(m[0][1])
	regex.match(`[A-Za-z_]`, size)
	_java_tainted(lines, i, size)
	finding := {
		"rule_id": metadata.id,
		"message": _java_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_java_tainted(_, _, size) if regex.match(_java_source, size)

_java_tainted(lines, i, size) if {
	some v in helpers.tainted_names(lines, i, 25, _java_source)
	regex.match(concat("", [`\b`, v, `\b`]), size)
}

# ── C / C++ ──────────────────────────────────────────────────────────────

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	some ext in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
	endswith(path, ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\b(?:malloc|calloc|realloc)\s*\(([^;]*)\)`, line, 1)
	count(m) > 0
	size := _strip_len(m[0][1])
	regex.match(`[A-Za-z_]`, size)
	_c_tainted(lines, i, size)
	finding := {
		"rule_id": metadata.id,
		"message": _c_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_c_tainted(_, _, size) if regex.match(_c_source, size)

_c_tainted(lines, i, size) if {
	some v in helpers.tainted_names(lines, i, 25, _c_source)
	regex.match(concat("", [`\b`, v, `\b`]), size)
}

# ── Allocation inside a loop whose bound comes from outside ──────────────
# The size can be a constant: `for i < n { buf = malloc(4096) }` allocates
# n*4096 bytes, and n is the attacker's. The `for` header must sit above the
# allocation at a shallower indent, so a loop that has already ended does not
# count.

_indent(l) := n if {
	m := regex.find_all_string_submatch_n(`^\s*`, l, 1)
	n := count(m[0][0])
}

_for_bound_tainted(lines, j, source) if regex.match(source, lines[j])

_for_bound_tainted(lines, j, source) if {
	some v in helpers.tainted_names(lines, j, 25, source)
	regex.match(concat("", [`\b`, v, `\b`]), lines[j])
}

_in_tainted_loop(lines, i, source) if {
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	regex.match(`^\s*for\b`, lines[j])
	_indent(lines[j]) < _indent(lines[i])
	_for_bound_tainted(lines, j, source)
}

_go_msg := "Allocation sized by a value read from outside the program; cap it with a maximum before allocating to prevent memory exhaustion"

_c_msg := "Allocation sized by a value read from outside the program; check it against a maximum (and for multiplication overflow) before allocating"

_java_msg := "Array sized by a value read from outside the program; validate it against a maximum limit before allocation to prevent OutOfMemoryError or DoS"

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	not endswith(path, "_test.go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(`\bmake\(\s*(\[\]|map\[|chan\s)`, line)
	_in_tainted_loop(lines, i, _go_source)
	finding := {
		"rule_id": metadata.id,
		"message": _go_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	some ext in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
	endswith(path, ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(`\b(malloc|calloc|realloc)\s*\(`, line)
	_in_tainted_loop(lines, i, _c_source)
	finding := {
		"rule_id": metadata.id,
		"message": _c_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(`\bnew\s+(byte|char|int|long)\s*\[`, line)
	_in_tainted_loop(lines, i, _java_source)
	finding := {
		"rule_id": metadata.id,
		"message": _java_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
