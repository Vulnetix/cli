# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_710

import rego.v1

metadata := {
	"id": "VNX-710",
	"name": "Security-relevant compiler warning suppressed in source",
	"description": "Source code switches off a compiler warning whose purpose is to catch a memory-safety or injection defect, so the code it covers can carry that defect without a diagnostic (CWE-710, improper adherence to coding standards, in its one statically recognisable form). Reported in C and C++: #pragma warning(disable: ...) or #pragma warning(suppress: ...) naming MSVC C4996 (unsafe CRT functions such as strcpy/sprintf/gets), C4789 (buffer overrun), C4700/C4701/C4703 (uninitialised variable or pointer), C6385/C6386 (buffer read/write overrun) or C6387/C6011 (null pointer); #pragma GCC/clang diagnostic ignored for -Wformat-security, -Wformat-nonliteral, -Wformat-overflow, -Wformat-truncation, -Wstringop-overflow, -Wstringop-truncation, -Wstringop-overread, -Warray-bounds, -Wuninitialized, -Wmaybe-uninitialized, -Wreturn-local-addr, -Wreturn-stack-address, -Wfree-nonheap-object, -Wuse-after-free and -Wdangling-pointer; and #define _CRT_SECURE_NO_WARNINGS or _CRT_SECURE_NO_DEPRECATE. Not reported: suppressions of style or portability warnings (unused parameters, sign comparison, deprecated declarations, conversions), #pragma warning(push/pop/default/error), #pragma GCC/clang diagnostic warning or error (the diagnostic is still emitted), compiler flags in build files (another rule's concern), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-710/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [710],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["improper-adherence-to-coding-standards", "compiler-warnings", "cwe-710"],
}

_is_c(path) if {
	some ext in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl"}
	endswith(path, ext)
}

_msvc_re := `^\s*#\s*pragma\s+warning\s*\(\s*(disable|suppress)\s*:[^)]*\b(4996|4789|4700|4701|4703|6385|6386|6387|6011)\b`

_gcc_re := `^\s*#\s*pragma\s+(GCC|clang)\s+diagnostic\s+ignored\s+"-W(format-security|format-nonliteral|format-overflow|format-truncation|stringop-overflow|stringop-truncation|stringop-overread|array-bounds|uninitialized|maybe-uninitialized|return-local-addr|return-stack-address|free-nonheap-object|use-after-free|dangling-pointer)\b`

_crt_re := `^\s*#\s*define\s+(_CRT_SECURE_NO_WARNINGS|_CRT_SECURE_NO_DEPRECATE)\b`

# `__pragma(warning(disable: 4996))` and `_Pragma("GCC diagnostic ignored ...")`
# are the macro spellings of the same directives.
_macro_re := `\b__pragma\s*\(\s*warning\s*\(\s*(disable|suppress)\s*:[^)]*\b(4996|4789|4700|4701|4703|6385|6386|6387|6011)\b|\b_Pragma\s*\(\s*"(GCC|clang)\s+diagnostic\s+ignored\s+\\"-W(format-security|format-nonliteral|format-overflow|format-truncation|stringop-overflow|stringop-truncation|stringop-overread|array-bounds|uninitialized|maybe-uninitialized|return-local-addr|return-stack-address|free-nonheap-object|use-after-free|dangling-pointer)\b`

_suppresses(line) if regex.match(_msvc_re, line)

_suppresses(line) if regex.match(_gcc_re, line)

_suppresses(line) if regex.match(_crt_re, line)

_suppresses(line) if {
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	not startswith(trim_space(line), "/*")
	regex.match(_macro_re, line)
}

_gate(s) if contains(s, "pragma")

_gate(s) if contains(s, "Pragma")

_gate(s) if contains(s, "_CRT_SECURE_NO_")

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	_gate(line)
	_suppresses(line)
	finding := {
		"rule_id": metadata.id,
		"message": "A compiler warning that detects memory-safety or format-string defects is disabled in source. Fix the code the warning reports instead of silencing it, or scope the suppression to one audited line",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
