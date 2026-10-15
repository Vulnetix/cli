# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1105

import rego.v1

metadata := {
	"id": "VNX-1105",
	"name": "Insufficient Encapsulation of Machine-Dependent Functionality",
	"description": "C or C++ inline assembly (asm(...), asm volatile(...), __asm__ __volatile__(...), MSVC __asm/_asm { ... } blocks and single-line __asm/_asm instructions) appears in a file that is not a dedicated machine-dependent module, so CPU-specific code is mixed into general logic instead of being isolated behind a portable interface. Every port to a new architecture or compiler then has to find and rewrite it in place. A file counts as a dedicated module when it lives in a directory named for an architecture or platform layer (arch/, asm/, platform/, port/, hal/, cpu/, x86/, x86_64/, x86-64/, arm64/, aarch64/, riscv/, simd/, intrinsics/, atomic/ and similar) or its name says so (*atomic*, *intrin*, *simd*, barrier*, spinlock*, cpu*, *_x86, *_arm, *_avx2, *_neon, rdtsc*, platform*, osdep*, and the time-source modules monotonic*, clock*, timer*). Reported: the line opening each assembly statement. Not reported: inline assembly in such modules, calls to wrapper functions and compiler intrinsics, the asm keyword inside strings, identifiers that merely contain 'asm', and comments. Machine dependence other than inline assembly (system calls, intrinsics, preprocessor platform checks) is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1105/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1105],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["portability", "inline-assembly", "encapsulation", "cwe-1105"],
}

_c_file(path) if regex.match(`\.(?:c|h|cc|cpp|cxx|hpp|hh|hxx|inl)$`, path)

_dir_re := `(?i)(?:^|/)(?:arch|archs|asm|platforms?|ports?|hal|cpu|machine|mach|x86|x86_64|x86-64|x64|amd64|i386|i686|ia32|arm|arm32|arm64|aarch64|mips\d*|ppc|ppc64|powerpc|riscv\d*|s390x?|sparc\d*|loongarch\d*|simd|intrin|intrinsics|osdep|atomics?|sysdep|sysdeps)/`

_base(path) := lower(regex.replace(path, `^.*/|\.[^.]*$`, ""))

# The file is named for a machine-dependent concern.
_platform_name(b) if regex.match(`(?:^|[_\-.])(?:barrier|spinlock|spin_?lock|sse\d*|avx\d*|neon|x86|amd64|i386|aarch64|riscv|rdtsc|platform|osdep|cpuid|isa|asm|monotonic|clock|timer)`, b)

# immintrin.h, nmmintrin.h, hdr_atomic.h, simd_utils.c
_platform_name(b) if regex.match(`intrin|simd|atomic`, b)

_platform_name(b) if regex.match(`(?:^|[_\-.])(?:arm|arm64|port|ports|arch|cpu|ppc|mips|tsc|win32|win64|cycles?|msvc|gcc|clang)(?:[_\-.\d]|$)`, b)

_dedicated(path) if regex.match(_dir_re, path)

_dedicated(path) if _platform_name(_base(path))

_asm_re := `(?:^|[^\w])(?:(?:__asm__|__asm|_asm|asm)\s*(?:(?:__volatile__|volatile|__volatile|goto|inline)\s*)*[({]|_?_asm\s+[A-Za-z_]\w*)`

_comment(line) if regex.match(`^\s*(?://|/\*|\*/|\*\s|\*$)`, line)

_code(line) := regex.replace(regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`), `//.*$|/\*.*?\*/`, "")

# A #define (or its backslash continuation) is the encapsulation: the
# assembly is wrapped once in a named macro that callers use portably.
_in_macro(lines, i) if regex.match(`^\s*#\s*define\b`, lines[i])

_in_macro(lines, i) if {
	i > 0
	endswith(trim_right(lines[i - 1], " \t\r"), "\\")
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	contains(content, "asm")
	not _dedicated(path)
	regex.match(`(?m)(?:^|[^\w])(?:__asm__|__asm|_asm|asm)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "asm")
	not _comment(line)
	regex.match(_asm_re, _code(line))
	not _in_macro(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Inline assembly in a general-purpose source file; isolate machine-dependent code in an architecture module (arch/<cpu>/...) behind a portable function, or use a compiler builtin",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
