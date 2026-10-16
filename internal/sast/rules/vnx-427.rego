# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_427

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-427",
	"name": "Uncontrolled Search Path Element",
	"description": "A library or program is looked up through a search path that contains a directory an attacker can control, in C and C++. Reported: LoadLibrary/LoadLibraryA/LoadLibraryW with a bare DLL name (no directory), and LoadLibraryEx with a bare name whose flags carry no LOAD_LIBRARY_SEARCH_* restriction and no LOAD_LIBRARY_AS_DATAFILE/AS_IMAGE_RESOURCE, so the DLL search order reaches the application and current directories (DLL planting); dlopen() of a relative path containing a slash (\"./plugins/libauth.so\", \"lib/libx.so\"), which resolves against the current working directory; SetDllDirectory/SetDllDirectoryA/W given a relative directory (\"plugins\", \".\\\\addons\"); setenv/putenv/_putenv/SetEnvironmentVariable setting PATH, LD_LIBRARY_PATH, LD_PRELOAD, LD_AUDIT, DYLD_LIBRARY_PATH or DYLD_INSERT_LIBRARIES to a literal with an empty element (\"::\", a leading or trailing separator, which means the current directory) or a relative element (\".\", \"bin\", \"./lib\"), including calls split over up to three lines; and setenv/SetEnvironmentVariable of those variables to a value taken from argv or optarg, directly or through a variable assigned from them up to fifteen lines above. Not reported: absolute paths, LoadLibrary of a KnownDLL (kernel32, user32, ntdll, advapi32 and the other system DLLs Windows always maps from System32), any LoadLibrary in a file that calls SetDefaultDllDirectories, dlopen of a bare soname (\"libssl.so.3\", resolved through the system search path), of an @rpath/@executable_path/@loader_path name, or of NULL, SetDllDirectory(\"\") (which removes the current directory), a library name held in a variable (a loader choice taken from input is VNX-114), other environment variables, the patterns inside string literals and comments. Running a command by relative name through system() is an untrusted search path (CWE-426) and is not reported here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-427/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [427],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["search-path-element", "dll-planting", "cwe-427"],
}

_c_exts := {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}

_is_c(path) if {
	some ext in _c_exts
	endswith(path, ext)
}

_needles := {"LoadLibrary", "dlopen", "setenv", "putenv", "SetEnvironmentVariable", "SetDllDirectory"}

_has_needle(s) if {
	some n in _needles
	contains(s, n)
}

# The call's text from line i, up to its first semicolon (calls are split over
# a few lines often enough that one line is not the statement).
_stmt(lines, i) := s if {
	end := min([count(lines) - 1, i + 3])
	joined := concat("\n", [lines[j] | some j in numbers.range(i, end)])
	s := split(joined, ";")[0]
}

_str_prefix := `(?:L|u8|u|_T\(\s*|TEXT\(\s*)?`

# Windows maps these from System32 whatever the search order.
_known_dlls := {
	"kernel32", "kernelbase", "user32", "gdi32", "advapi32", "ole32", "oleaut32",
	"shell32", "shlwapi", "comdlg32", "ws2_32", "ntdll", "rpcrt4", "msvcrt",
	"setupapi", "imagehlp", "psapi", "normaliz", "wldap32", "sechost", "combase",
	"clbcatq", "difxapi", "imm32", "lpk", "msctf", "nsi", "usp10", "wow64",
	"wow64win", "wow64cpu", "gdiplus", "comctl32",
}

_dll_base(name) := lower(trim_suffix(lower(name), ".dll"))

# ── LoadLibrary / LoadLibraryEx with a bare name ─────────────────────────

_reason(1, lines, i, content) := "LoadLibrary of a bare DLL name searches the application and current directories: an attacker-planted DLL of that name is loaded. Load it by full System32 path or with LoadLibraryEx(..., LOAD_LIBRARY_SEARCH_SYSTEM32)" if {
	contains(lines[i], "LoadLibrary")
	not contains(content, "SetDefaultDllDirectories(")
	s := _stmt(lines, i)
	m := regex.find_all_string_submatch_n(concat("", [`\bLoadLibrary(Ex)?[AW]?\s*\(\s*`, _str_prefix, `"([^"\\/]+)"`]), s, 1)
	count(m) > 0
	not _dll_base(m[0][2]) in _known_dlls
	_unrestricted(m[0][1], s)
}

_unrestricted("", _)

_unrestricted("Ex", s) if not regex.match(`LOAD_LIBRARY_SEARCH_|LOAD_LIBRARY_AS_DATAFILE|LOAD_LIBRARY_AS_IMAGE_RESOURCE`, s)

# ── dlopen of a relative path ────────────────────────────────────────────

_reason(2, lines, i, _) := "dlopen() of a relative path resolves against the current working directory, which the caller controls. Use an absolute path (or one built from the executable's own location)" if {
	contains(lines[i], "dlopen")
	s := _stmt(lines, i)
	m := regex.find_all_string_submatch_n(`\bdlopen\s*\(\s*"([^"]*)"`, s, 1)
	count(m) > 0
	name := m[0][1]
	contains(name, "/")
	not startswith(name, "/")
	not startswith(name, "$")
	not startswith(name, "@")
}

# ── PATH-like variables set to a relative or empty element ───────────────

_path_vars := `(PATH|LD_LIBRARY_PATH|LD_PRELOAD|LD_AUDIT|DYLD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|DYLD_FALLBACK_LIBRARY_PATH)`

_set_literal_re := concat("", [
	`\b(?:setenv|SetEnvironmentVariable[AW]?)\s*\(\s*`, _str_prefix, `"`, _path_vars,
	`"\s*\)?\s*,\s*`, _str_prefix, `"([^"]*)"`,
])

_putenv_re := concat("", [`\b_?w?putenv\s*\(\s*(?:const_cast\s*<[^>]*>\s*\(\s*|\(\s*(?:const\s+)?(?:unsigned\s+)?w?char\s*\*\s*\)\s*)?`, _str_prefix, `"`, _path_vars, `=([^"]*)"`])

# The call may be split over up to three lines; the match must start on the
# first one. Lines are joined with newlines, not split at ';', because a
# Windows PATH value contains semicolons.
_set_value(text) := [m[0][1], m[0][2]] if {
	m := regex.find_all_string_submatch_n(concat("", [`^[^\n]*?`, _set_literal_re]), text, 1)
	count(m) > 0
}

_set_value(text) := [m[0][1], m[0][2]] if {
	m := regex.find_all_string_submatch_n(concat("", [`^[^\n]*?`, _putenv_re]), text, 1)
	count(m) > 0
}

_joined(lines, i) := concat("\n", [lines[j] | some j in numbers.range(i, min([count(lines) - 1, i + 2]))])

_sep(value) := ";" if contains(value, ";")

_sep(value) := ":" if not contains(value, ";")

_absolute(e) if startswith(e, "/")

_absolute(e) if regex.match(`^[A-Za-z]:`, e)

_absolute(e) if startswith(e, "\\\\\\\\")

_absolute(e) if startswith(e, "%")

_absolute(e) if startswith(e, "$")

_bad_element(value) if {
	value != ""
	some e in split(value, _sep(value))
	not _absolute(trim_space(e))
}

_reason(3, lines, i, _) := "The search path is set with an empty or relative element, which resolves against the current working directory: a program or library planted there is found first. Use absolute directories only" if {
	regex.match(`setenv|putenv|SetEnvironmentVariable`, lines[i])
	v := _set_value(_joined(lines, i))
	_bad_element(v[1])
}

# ── SetDllDirectory with a relative directory ────────────────────────────

_reason(5, lines, i, _) := "SetDllDirectory with a relative directory puts a path resolved against the current working directory into the DLL search order: a DLL planted there is loaded. Pass an absolute directory, or \"\" to remove the current directory" if {
	contains(lines[i], "SetDllDirectory")
	m := regex.find_all_string_submatch_n(concat("", [`\bSetDllDirectory[AW]?\s*\(\s*`, _str_prefix, `"([^"]+)"`]), lines[i], 1)
	count(m) > 0
	not _absolute(m[0][1])
}

# ── PATH-like variables set from the command line ────────────────────────

_set_ident_re := concat("", [
	`\b(?:setenv|SetEnvironmentVariable[AW]?)\s*\(\s*`, _str_prefix, `"`, _path_vars,
	`"\s*\)?\s*,\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)`,
])

_argv_source := `=\s*(?:\([^)]*\)\s*)?(?:argv\s*\[|optarg\b)`

_local_assigned(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*=[^=]`, line, 1)
	count(m) > 0
}

_from_argv(_, _, arg) if regex.match(`^(argv\s*\[|optarg$)`, arg)

_from_argv(lines, i, arg) if {
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	not helpers.is_comment_line(lines[j])
	regex.match(_argv_source, lines[j])
	_local_assigned(lines[j]) == arg
}

_reason(4, lines, i, _) := "A library or program search path is taken from the command line: whoever runs the program chooses where libraries and programs are loaded from" if {
	regex.match(`setenv|SetEnvironmentVariable`, lines[i])
	m := regex.find_all_string_submatch_n(_set_ident_re, lines[i], 1)
	count(m) > 0
	_from_argv(lines, i, m[0][2])
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	_has_needle(content)
	lines := split(content, "\n")
	some i, line in lines
	_has_needle(line)
	not helpers.is_comment_line(line)
	some k in [1, 2, 3, 4, 5]
	msg := _reason(k, lines, i, content)
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
