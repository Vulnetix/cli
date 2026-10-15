# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_589

import rego.v1

metadata := {
	"id": "VNX-589",
	"name": "Call to non-ubiquitous API",
	"description": "A C or C++ call to a library function that exists only on some platforms, or whose signature differs between them, in a file with no platform or feature guard: C11 Annex K bounds-checked functions that only Microsoft's runtime ships (strcpy_s, strcat_s, sprintf_s, memcpy_s, fopen_s, gets_s, scanf_s and kin), Microsoft-only names (_stricmp, _strnicmp, _strdup, _snprintf, _vsnprintf, _itoa, itoa), BSD extensions (strlcpy, strlcat, arc4random*, strtonum, getprogname, reallocarray) and GNU/BSD extensions the Microsoft runtime lacks (asprintf, vasprintf, strcasestr, memrchr, strchrnul, mempcpy, qsort_r, whose argument order differs between glibc and BSD). Such code fails to build, or misbehaves, on a platform without the function. Not reported: a file with an #if/#ifdef on a platform or HAVE_* macro, that defines _GNU_SOURCE or __STDC_WANT_LIB_EXT1__, or that includes <windows.h> or <tchar.h> (the dependency is deliberate: the file is guarded or built for one platform); a file whose path names a platform (impl/apple/, win32_io.c); a function the project itself defines, declares at file scope or #defines (a compat implementation); member calls (obj.f(), p->f()) and identifiers that only contain the name (my_strlcpy); comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-589/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [589],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["non-portable-api", "cwe-589"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}

_lang(path) if {
	some ext in _exts
	endswith(path, ext)
}

_apis := [
	"strcpy_s", "strncpy_s", "strcat_s", "strncat_s", "sprintf_s", "snprintf_s",
	"vsprintf_s", "vsnprintf_s", "memcpy_s", "memmove_s", "memset_s", "fopen_s",
	"freopen_s", "gets_s", "scanf_s", "sscanf_s", "fscanf_s", "strtok_s", "strerror_s",
	"localtime_s", "gmtime_s", "_stricmp", "_strnicmp", "_strdup", "_snprintf",
	"_vsnprintf", "_itoa", "itoa", "strlcpy", "strlcat", "arc4random",
	"arc4random_uniform", "arc4random_buf", "strtonum", "getprogname", "memrchr",
	"strchrnul", "mempcpy", "qsort_r", "asprintf", "vasprintf", "strcasestr",
	"reallocarray",
]

_call_re(api) := concat("", [`(?:^|[^\w.>$:])`, api, `\s*\(`])

# The file already deals with portability.
_guard_re := `(?m)^\s*#\s*(?:(?:if|ifdef|ifndef|elif)\b[^\n]*(?:_WIN32|_WIN64|_MSC_VER|__linux__|__APPLE__|__MACH__|__GLIBC__|__FreeBSD__|__OpenBSD__|__NetBSD__|__DragonFly__|__unix__|__MINGW|__CYGWIN__|__STDC_LIB_EXT1__|HAVE_\w+|_GNU_SOURCE|__BSD|BSD)|define\s+(?:_GNU_SOURCE|__STDC_WANT_LIB_EXT1__|_BSD_SOURCE|_DEFAULT_SOURCE)\b|include\s*[<"](?:windows|windef|winbase|tchar)\.h[>"])`

# A source file that is platform-specific by its path (impl/apple/,
# win32_io.c, os_linux.cpp) is built only where the API exists.
_platform_path(path) if regex.match(`(?i)(?:^|[/_.-])(?:apple|darwin|macos|osx|ios|win|win32|win64|windows|msvc|mingw|linux|bsd|freebsd|openbsd|netbsd)(?:[/_.-])`, path)

_comment(line) if startswith(trim_space(line), "//")

_comment(line) if startswith(trim_space(line), "/*")

_comment(line) if startswith(trim_space(line), "*")

_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`), `//.*$|/\*.*?\*/`, "")

# Functions the project provides itself: a file-scope definition or
# prototype (return type on the same line or the line above) or a macro.
_project_defined contains api if {
	some p, c in input.file_contents
	_lang(p)
	some api in _apis
	contains(c, api)
	regex.match(concat("", [`(?m)^(?:[A-Za-z_][\w \t\*]*\b|)`, api, `\s*\(|^\s*#\s*define\s+`, api, `\b`]), c)
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	present := [a | some a in _apis; contains(content, a)]
	count(present) > 0
	not _platform_path(path)
	not regex.match(_guard_re, content)
	lines := split(content, "\n")
	some i, line in lines
	some api in present
	contains(line, api)
	not _comment(line)
	regex.match(_call_re(api), _code(line))
	not _project_defined[api]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s() is not available on every platform (or differs between them): the code will not build or will misbehave elsewhere. Use a portable equivalent (snprintf, memcpy, strcasecmp), or guard the call and provide a fallback", [api]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
