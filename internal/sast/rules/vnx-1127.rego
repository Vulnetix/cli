# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1127

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1127",
	"name": "Compilation with Insufficient Warnings or Errors",
	"description": "Reports C and C++ code and build files that switch off the compiler warnings which catch memory-safety and format-string defects. In C/C++ sources: #define _CRT_SECURE_NO_WARNINGS / _CRT_SECURE_NO_DEPRECATE / _SCL_SECURE_NO_WARNINGS, #pragma warning(disable: ...) naming C4996 (unsafe CRT functions such as strcpy) or the uninitialised-variable and buffer-overrun warnings (C4700, C4701, C4703, C4789), and #pragma GCC/clang diagnostic ignored (or the _Pragma(\"GCC diagnostic ignored ...\") operator in a macro) for -Wall, -Wextra, -Weverything, -Wformat, -Wformat-security, -Wformat-nonliteral, -Wimplicit-function-declaration, -Wint-conversion, -Wincompatible-pointer-types or -Wreturn-type. In CMakeLists.txt, *.cmake, meson.build, Makefiles and MSBuild .vcxproj/.props files: a compiler flag that disables all warnings (-w, /W0, -Wno-everything, meson warning_level=0), -Wno-format / -Wno-format-security, MSVC /wd4996 (and /wd for C4700, C4701, C4703, C4789) and -D_CRT_SECURE_NO_WARNINGS, on a flags line (CFLAGS, CXXFLAGS, CMAKE_*_FLAGS, the COMPILE_FLAGS/COMPILE_OPTIONS properties, add_compile_options, target_compile_options, add_definitions, add_project_arguments, or a cc/gcc/clang/$(CC) command); _CRT_SECURE_NO_WARNINGS / _CRT_SECURE_NO_DEPRECATE / _SCL_SECURE_NO_WARNINGS named as a definition on any line (target_compile_definitions, add_compile_definitions, PreprocessorDefinitions) other than a message/echo; and MSBuild <WarningLevel>TurnOffAllWarnings or <DisableSpecificWarnings> listing 4996, 4700, 4701, 4703 or 4789. Not reported: a pragma or flag scoped to a GCC memory diagnostic such as -Warray-bounds, -Wstringop-overread or -Wuse-after-free (well-maintained projects silence these locally for known compiler false positives), suppression of a specific stylistic warning (fallthrough, unused parameter, constant conditional), strict flags such as -Wall -Werror, -w in a non-compiler command (sysctl -w), comments and strings in C sources.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1127/",
	"languages": ["c", "cpp", "bash"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1127],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["insufficient-warnings", "cwe-1127"],
}

_c_source(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}
	endswith(path, ext)
}

_build_file(path) if {
	base := lower(regex.replace(path, `^.*/`, ""))
	base in {"cmakelists.txt", "meson.build", "makefile", "gnumakefile", "makefile.am", "makefile.in", "configure.ac"}
}

_build_file(path) if endswith(lower(path), ".cmake")

_build_file(path) if endswith(lower(path), ".mk")

# ── C / C++ sources ─────────────────────────────────────────────────────

_build_file(path) if endswith(lower(path), ".vcxproj")

_build_file(path) if endswith(lower(path), ".props")

_c_gate := `_CRT_SECURE_NO_|_SCL_SECURE_NO_|pragma|_Pragma`

_c_patterns := [
	`^\s*#\s*define\s+_(?:CRT_SECURE_NO_WARNINGS|CRT_SECURE_NO_DEPRECATE|SCL_SECURE_NO_WARNINGS)\b`,
	`^\s*#\s*pragma\s+warning\s*\(\s*disable\s*:[^)]*\b(?:4996|4700|4701|4703|4789)\b`,
	`^\s*#\s*pragma\s+(?:GCC|clang)\s+diagnostic\s+ignored\s+"-W(?:all|extra|everything|format|format-security|format-nonliteral|implicit-function-declaration|int-conversion|incompatible-pointer-types|return-type)"`,
	`_Pragma\s*\(\s*"(?:GCC|clang)\s+diagnostic\s+ignored\s+\\"-W(?:all|extra|everything|format|format-security|format-nonliteral|implicit-function-declaration|int-conversion|incompatible-pointer-types|return-type)\\"`,
]

findings contains finding if {
	some path, content in input.file_contents
	_c_source(path)
	regex.match(_c_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`#|_Pragma`, line)
	some p in _c_patterns
	regex.match(p, line)
	# `#  pragma` (an indented directive) is normalised so the engine does not
	# take the snippet for a shell-style comment.
	finding := _finding(path, i, regex.replace(line, `^\s*#\s*`, "#"), "Compiler warnings that catch unsafe CRT calls, format-string bugs or uninitialised memory are switched off here. Fix the code the warning reports (strcpy_s/snprintf, a literal format string) instead of silencing it")
}

# ── Build files ─────────────────────────────────────────────────────────

_flags_ctx := `(?i)(?:\b(?:C|CXX|CPP|LD)FLAGS\b|CMAKE_\w*FLAGS|COMPILE_FLAGS|COMPILE_OPTIONS|add_compile_options|target_compile_options|add_definitions|add_project_arguments|add_global_arguments|c_args|cpp_args|\$\(CC\)|\$\(CXX\)|(?:^|[\s;])(?:gcc|g\+\+|clang|clang\+\+|cc|c\+\+)\s)`

_flag_patterns := [
	`(?:^|[\s"'(\[,])-w(?:$|[\s"')\],])`,
	`(?:^|[\s"'(\[,])/W0(?:$|[\s"')\],])`,
	`-Wno-everything\b`,
	`-Wno-format(?:-security)?(?:$|[\s"')\],])`,
	`[-/]D\s*_CRT_SECURE_NO_(?:WARNINGS|DEPRECATE)\b`,
	`(?:^|[\s"'(\[,])[-/]wd\s*(?:4996|4700|4701|4703|4789)\b`,
]

findings contains finding if {
	some path, content in input.file_contents
	_build_file(path)
	regex.match(`-w\b|/W0|-Wno-|_CRT_SECURE_NO_|_SCL_SECURE_NO_|warning_level|wd\s*4[0-9]{3}|TurnOffAllWarnings|DisableSpecificWarnings`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	_build_hit(line)
	finding := _finding(path, i, line, "The build disables compiler warnings (all of them, or the format-security / unsafe-CRT checks), so memory-safety and format-string defects compile silently. Remove the flag and fix what the compiler reports")
}

_build_hit(line) if {
	regex.match(_flags_ctx, line)
	some p in _flag_patterns
	regex.match(p, line)
}

_build_hit(line) if regex.match(`warning_level\s*[=:]\s*'?0\b`, line)

# A definition named on its own (target_compile_definitions, a multi-line
# add_compile_definitions, an MSBuild PreprocessorDefinitions list). A
# message()/echo line only talks about it.
_build_hit(line) if {
	regex.match(`\b_(?:CRT_SECURE_NO_WARNINGS|CRT_SECURE_NO_DEPRECATE|SCL_SECURE_NO_WARNINGS)\b`, line)
	not regex.match(`(?i)\b(?:message|echo|printf|\$\(info|\$\(warning)\b`, line)
}

# MSBuild (.vcxproj / .props).
_build_hit(line) if regex.match(`<WarningLevel>\s*TurnOffAllWarnings\s*<`, line)

_build_hit(line) if regex.match(`<DisableSpecificWarnings>[^<]*\b(?:4996|4700|4701|4703|4789)\b`, line)

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
