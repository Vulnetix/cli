# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_932

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-932",
	"name": "Source code switches off stack protection or FORTIFY_SOURCE",
	"description": "CWE-932 is an OWASP Top Ten 2013 category with no code shape of its own; this rule reports the concrete C/C++ hardening signal it was generated for, source that turns off a compiler memory-safety defence for the code that follows: #pragma GCC/clang optimize(\"no-stack-protector\"/\"-fno-stack-protector\"), __attribute__((no_stack_protector)) and __attribute__((optimize(..., \"no-stack-protector\"))) (also after other attributes in the list, and inside #pragma clang attribute push), [[gnu::no_stack_protector]], #undef _FORTIFY_SOURCE that is not followed by a non-zero redefinition, #define _FORTIFY_SOURCE 0, and MSVC #pragma strict_gs_check(off) and __declspec(safebuffers). Not reported: optimisation-level pragmas and attributes (O0, O2, O3; optimize(\"O0\") is the usual secure-zeroing idiom), _FORTIFY_SOURCE set to 1-3, comments (including a trailing comment after code) and string literals, and test or fuzzing code. Build-system flags (-fno-stack-protector in a Makefile) are out of scope.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-932/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [932],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["os-hardening", "c", "cpp", "cwe-932"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".inl", ".ino"}

_ext(path) if {
	some e in _exts
	endswith(path, e)
}

_gate_re := `no[-_]stack[-_]protector|_FORTIFY_SOURCE|strict_gs_check|safebuffers`

_sink_re := concat("|", [
	`^\s*#\s*pragma\s+(GCC|clang)\s+optimize\s*\(?\s*"[^"]*no-stack-protector`,
	concat("", [`__attribute__\s*\(\(\s*`, _attr_list, `(__)?no_stack_protector(__)?\b`]),
	concat("", [`__attribute__\s*\(\(\s*`, _attr_list, `(__)?optimize(__)?\s*\([^)]*"[^"]*no-stack-protector`]),
	`\[\[\s*(gnu|clang)::no_stack_protector\s*\]\]`,
	`^\s*#\s*define\s+_FORTIFY_SOURCE\s+0\b`,
	`^\s*#\s*pragma\s+strict_gs_check\s*\(\s*(push\s*,\s*)?off\s*\)`,
	`__declspec\s*\(\s*safebuffers\s*\)`,
])

# Attributes listed before the one that matters: noinline, used, aligned(16), ...
_attr_list := `(\w+(\s*\([^()]*\))?\s*,\s*)*`

# Outside a preprocessor line, the attribute must be in code, not in a string
# literal or a trailing comment.
_in_code(line) if startswith(trim_space(line), "#")

_in_code(line) if {
	not startswith(trim_space(line), "#")
	no_str := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)
	code := regex.replace(regex.replace(no_str, `/\*.*?\*/`, ""), `//.*$`, "")
	regex.match(`__attribute__|\[\[|__declspec`, code)
}

_c_comment(line) if startswith(trim_space(line), "//")

_c_comment(line) if startswith(trim_space(line), "/*")

_c_comment(line) if startswith(trim_space(line), "*")

_hit(line, _, _) if {
	regex.match(_sink_re, line)
	_in_code(line)
}

_hit(line, lines, i) if {
	regex.match(`^\s*#\s*undef\s+_FORTIFY_SOURCE\b`, line)
	not _redefined(lines, i)
}

_redefined(lines, i) if {
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 4]))
	regex.match(`^\s*#\s*define\s+_FORTIFY_SOURCE\s+[1-9]`, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	not helpers.is_test_path(path)
	not regex.match(`(^|/)fuzz[^/]*/|(^|/)fuzz_[^/]*$`, path)
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate_re, line)
	not _c_comment(line)
	_hit(line, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Source disables a compiler hardening defence (stack protector, FORTIFY_SOURCE or /GS) for the code that follows; an overflow there is no longer caught. Remove it, or confine it to code that runs before the canary is set up and document why",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
