# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_474

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-474",
	"name": "Use of Function with Inconsistent Implementations",
	"description": "C or C++ calls to library functions whose behaviour differs between platforms or C libraries in a way that changes correctness: signal() or std::signal() installing a handler function (System V resets the disposition to the default after the first delivery and does not restart interrupted calls, BSD does neither; reported once per file, at the first such install), strerror_r() (glibc's _GNU_SOURCE version returns a char * and may leave the buffer untouched, the XSI version returns an int and fills it), realloc(p, 0) (frees and returns NULL on some libraries, returns a new minimal block on others), the Microsoft _snprintf/_vsnprintf/_snwprintf family including `#define snprintf _snprintf` (does not NUL-terminate on truncation, unlike C99 snprintf), and vfork() (shares the parent's memory on some systems and is a plain fork on others). Not reported: signal() with SIG_IGN, SIG_DFL or a SIG_ERR test, signal() restoring a disposition saved from an earlier signal() call, sigaction, strerror_r inside a preprocessor branch that selects the variant (__GLIBC__, _GNU_SOURCE, _POSIX_C_SOURCE, _XOPEN_SOURCE, STRERROR_R, an OS macro) within 15 lines above, realloc with a non-zero size, snprintf/vsnprintf, fork, member calls and lookalike names (queue->signal, xsignal, my_realloc), test sources, comments and string literals. Format-string argument-count mismatches belong to CWE-685, not here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-474/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [474],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["inconsistent-implementation", "portability", "cwe-474"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

# Preprocessor lines are code here, so only C comment markers count.
_comment(line) if startswith(trim_space(line), "//")

_comment(line) if startswith(trim_space(line), "/*")

_comment(line) if startswith(trim_space(line), "*")

_code(line) := regex.replace(
	regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), `/\*.*?\*/`, " "),
	`//.*$`, "",
)

_pre := `(?:^|[^\w.>:])`

_signal_re := `(?:^|[^\w.>:]|std::)signal\s*\(\s*[A-Za-z_]\w*\s*,\s*&?\s*([A-Za-z_][\w:]*)\s*\)`

_variant_guard := `^\s*#\s*(?:if|ifdef|ifndef|elif)\b.*(?:GNU_SOURCE|GLIBC|STRERROR_R|_POSIX_C_SOURCE|_XOPEN_SOURCE|__APPLE__|__FreeBSD__|__NetBSD__|__OpenBSD__|_WIN32|__linux__|__MUSL__)`

_kind(code, _, _) := "realloc" if regex.match(concat("", [_pre, `realloc\s*\([^,()]+(?:\([^()]*\))?\s*,\s*0\s*\)`]), code)

_kind(code, _, _) := "msvc" if regex.match(concat("", [_pre, `_(?:v?snw?printf|snprintf_l)\s*\(|^\s*#\s*define\s+v?snprintf\s+_v?snprintf\b`]), code)

_kind(code, _, _) := "vfork" if regex.match(concat("", [_pre, `vfork\s*\(\s*\)`]), code)

_kind(code, lines, i) := "strerror_r" if {
	regex.match(concat("", [_pre, `strerror_r\s*\(`]), code)
	not regex.match(`^\s*#\s*define\b`, code)
	not _variant_guarded(lines, i)
}

_variant_guarded(lines, i) if {
	some j in numbers.range(max([0, i - 15]), i - 1)
	regex.match(_variant_guard, lines[j])
}

_handler_install(code, saved) if {
	some m in regex.find_all_string_submatch_n(_signal_re, code, -1)
	not m[1] in {"SIG_IGN", "SIG_DFL", "SIG_ERR", "SIG_HOLD", "NULL", "nullptr", "0"}
	not saved[m[1]]
}

# Handlers saved from an earlier signal() call (`prev = signal(SIGINT, SIG_IGN)`):
# putting the saved disposition back installs nothing new.
_saved_handlers(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*=\s*(?:std::)?signal\s*\(`, content, -1)
}

_messages := {
	"realloc": "realloc(p, 0) is implementation-defined: some C libraries free p and return NULL, others return a new minimal block, so code that frees or uses the result is wrong on one of them. Call free(p) explicitly",
	"msvc": "_snprintf/_vsnprintf do not NUL-terminate on truncation, unlike C99 snprintf, so the buffer can be read past its end. Use snprintf or _snprintf_s with _TRUNCATE",
	"vfork": "vfork() shares the parent's address space on some systems and is a plain fork() on others; anything but exec or _exit in the child is undefined. Use posix_spawn or fork",
	"strerror_r": "strerror_r has two incompatible implementations: the GNU version returns a char * and may leave the buffer untouched, the XSI version returns an int and fills it. Select the variant with a feature test, or use strerror_l",
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not helpers.is_test_path(path)
	regex.match(`realloc|_v?snw?printf|vfork|strerror_r`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`realloc|_v?snw?printf|vfork|strerror_r`, line)
	not _comment(line)
	k := _kind(_code(line), lines, i)
	finding := _finding(path, i, line, _messages[k])
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not helpers.is_test_path(path)
	contains(content, "signal")
	lines := split(content, "\n")
	saved := _saved_handlers(content)
	installs := [i |
		some i, line in lines
		contains(line, "signal")
		not _comment(line)
		_handler_install(_code(line), saved)
	]
	count(installs) > 0
	i := min(installs)
	finding := _finding(path, i, lines[i], "signal() installing a handler behaves differently across systems: System V resets the handler to the default after one delivery and does not restart interrupted system calls, BSD does neither. Use sigaction() with explicit flags (reported once per file)")
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
