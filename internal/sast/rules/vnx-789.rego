# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_789

import rego.v1

metadata := {
	"id": "VNX-789",
	"name": "Memory Allocation with Excessive Size Value",
	"description": "Reports C/C++ allocations (malloc, calloc, realloc, reallocarray, alloca, valloc, new T[n], and the container calls v.resize(n), v.reserve(n) and std::vector<T> v(n)) whose size comes from an externally controlled number with no upper bound checked first: a value parsed with atoi/atol/strtol/strtoul/std::stoi and friends, read with scanf/fscanf/sscanf, or decoded from the wire with ntohl/ntohs/beNNtoh/leNNtoh within the ten lines above, or such a call written inline in the size argument. A comparison against an upper limit or a MIN()/min() clamp between the read and the allocation suppresses the report; a lower-bound check alone does not. Sizes derived from strlen(), sizeof or constants, and flows across functions, are deliberately not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-789/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [789],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["memory-allocation", "cwe-789"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}

_c_file(path) if {
	some ext in _exts
	endswith(path, ext)
}

_is_comment(line) if regex.match(`^\s*(//|/\*|\*)`, line)

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_src_call := `\b(?:std::)?(atoi|atol|atoll|strtol|strtoul|strtoll|strtoull|strtoimax|strtoumax|stoi|stol|stoul|stoll|stoull|ntohl|ntohs|be16toh|be32toh|be64toh|le16toh|le32toh|le64toh)\s*\(`

_scanf := `\b(scanf|fscanf|sscanf)\s*\(`

# C allocators, new T[n], and the C++ container calls that allocate n
# elements up front: v.resize(n), v.reserve(n), std::vector<T> v(n)
_alloc := `(?:\b(?:malloc|calloc|realloc|reallocarray|alloca|_alloca|valloc|xmalloc)\s*\(|\bnew\s+[\w:<>]+\s*\[|\.(?:resize|reserve)\s*\(|\b(?:std::)?vector\s*<[^;()]*>\s*[A-Za-z_]\w*\s*\()`

_alloc_args := concat("", [_alloc, `([^;]*)`])

_msg := "Allocation size comes from an externally controlled number with no upper bound; an attacker can request a huge allocation (memory exhaustion) or, after wrap-around, a tiny one. Reject sizes above a fixed maximum before allocating"

_c_assigned(line) := m[1] if {
	ms := regex.find_all_string_submatch_n(`^\s*(?:[A-Za-z_][\w:]*\s+|\*\s*)*\**\s*([A-Za-z_]\w*)\s*=[^=]`, line, 1)
	count(ms) > 0
	m := ms[0]
}

_args(lines, i) := args if {
	regex.match(_alloc, _strip_strings(lines[i]))
	text := _strip_strings(concat(" ", [l | some l in array.slice(lines, i, i + 3); not _is_comment(l)]))
	ms := regex.find_all_string_submatch_n(_alloc_args, text, 1)
	count(ms) > 0
	args := ms[0][1]
}

# names assigned from a parse/decode call, or written by scanf, within 10 lines
_tainted(lines, i) := {[n, j] |
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := _strip_strings(lines[j])
	not _is_comment(l)
	regex.match(_src_call, l)
	n := _c_assigned(l)
} | {[n, j] |
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	not _is_comment(l)
	regex.match(_scanf, l)
	some m in regex.find_all_string_submatch_n(`&\s*([A-Za-z_]\w*)`, l, -1)
	n := m[1]
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(_alloc, content)
	regex.match(`\b(atoi|atol|atoll|strto[a-z]+|sto[a-z]+|ntoh[ls]|[bl]e(16|32|64)toh|[fs]?scanf)\s*\(`, content)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(_alloc, raw)
	not _is_comment(raw)
	args := _args(lines, i)
	_tainted_size(lines, i, args)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}

_tainted_size(_, _, args) if regex.match(_src_call, args)

_tainted_size(lines, i, args) if {
	some t in _tainted(lines, i)
	n := t[0]
	regex.match(concat("", [`\b`, n, `\b`]), args)
	not _bounded(lines, t[1], i, n)
}

_bounded(lines, j, i, n) if {
	some k in numbers.range(j + 1, i)
	l := _strip_strings(lines[k])
	not _is_comment(l)
	_upper(l, n)
}

_upper(l, n) if regex.match(concat("", [`\b`, n, `\s*>=?\s*([A-Za-z_(]|[2-9]|\d\d)`]), l)

_upper(l, n) if regex.match(concat("", [`([A-Za-z_)]|\d\d)\s*<=?\s*`, n, `\b`]), l)

_upper(l, n) if regex.match(concat("", [`\b`, n, `\s*<=?\s*([A-Za-z_(]|\d\d)`]), l)

_upper(l, n) if regex.match(concat("", [`([A-Za-z_)]|\d\d)\s*>=?\s*`, n, `\b`]), l)

_upper(l, n) if regex.match(concat("", [`\b(MIN|min|std::min|clamp|std::clamp)\s*\([^;]*\b`, n, `\b`]), l)
