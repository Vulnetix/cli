# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_428

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-428",
	"name": "Unquoted Search Path or Element",
	"description": "A Windows executable path that contains a space is handed, unquoted, to an API that splits the command line at the first space, so \"C:\\Program Files\\Acme Agent\\agent.exe\" is first tried as C:\\Program.exe and then C:\\Program Files\\Acme.exe, which a local user who can write there plants. Reported in C, C++ and C#: CreateProcess/CreateProcessA/CreateProcessW with a NULL application name and a command line that is such a literal, or a buffer (buf, &buf[0], str.data()) that a literal of that shape was assigned or copied into up to twenty lines above, unless that line formats it into its own quotes (\"\\\"%s\\\" --service\"); WinExec with such a literal or buffer; CreateService/CreateServiceA/CreateServiceW whose arguments include such a literal (the service binary path); a service ImagePath registry value (SetValue, Registry.SetValue, RegSetValueEx) set to such a literal; and an sc.exe binPath= whose path is quoted only for the outer process (binPath= \\\"C:\\Program Files\\...\\\"), which sc strips. Only a path with a space before its .exe/.com/.bat/.cmd (or, without an extension, in a directory) counts, or one that starts with %ProgramFiles%, %ProgramFiles(x86)%, %ProgramW6432% or %CommonProgramFiles%, which expand to a directory with a space. Not reported: a path wrapped in its own quotes (\"\\\"C:\\Program Files\\...\\\"\"), CreateProcess with lpApplicationName set, paths without a space, ShellExecute and .NET Process.Start (which take the file separately or quote it), other registry values, paths built at run time, comments and string literals that only mention the API.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-428/",
	"languages": ["c", "cpp", "csharp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [428],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["unquoted-path", "windows", "cwe-428"],
}

_exts := {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".cs"}

_in_scope(path) if {
	some ext in _exts
	endswith(path, ext)
}

_needles := {"CreateProcess", "WinExec", "CreateService", "ImagePath", "binPath=", "binpath="}

_has_needle(s) if {
	some n in _needles
	contains(s, n)
}

_stmt(lines, i, span) := s if {
	end := min([count(lines) - 1, i + span])
	joined := concat("\n", [lines[j] | some j in numbers.range(i, end)])
	s := split(joined, ";")[0]
}

# A literal's contents. The opening quote may not follow another quote, so the
# doubled quotes of a C# verbatim string (@"""C:\x y\a.exe""") are not read as
# a literal that starts at the drive letter.
_literals(s) := [m[2] | some m in regex.find_all_string_submatch_n(`(^|[^"\\])"((?:\\.|[^"\\])*)"`, s, -1)]

# The executable part of a Windows path literal: up to its .exe (or similar),
# else up to its last directory separator.
_head(content) := h if {
	hs := regex.find_n(`(?i)^.*?\.(exe|com|bat|cmd)\b`, content, 1)
	count(hs) > 0
	h := hs[0]
}

_head(content) := h if {
	not regex.match(`(?i)\.(exe|com|bat|cmd)\b`, content)
	hs := regex.find_n(`^.*\\`, content, 1)
	count(hs) > 0
	h := hs[0]
}

_bad_path(content) if {
	regex.match(`^[A-Za-z]:\\`, content)
	contains(_head(content), " ")
}

# %ProgramFiles% and its siblings expand to a directory with a space in it
# (the service control manager expands a REG_EXPAND_SZ image path).
_bad_path(content) if {
	regex.match(`(?i)^%(?:ProgramFiles(?:\(x86\))?|ProgramW6432|CommonProgramFiles(?:\(x86\))?|CommonProgramW6432)%\\`, content)
	_head(content)
}

_bad_literal_in(s) if {
	some c in _literals(s)
	_bad_path(c)
}

_prefix := `(?:L|TEXT\(\s*|_T\(\s*|@)?`

_null := `(?:NULL|nullptr|null|0)`

# A buffer that received an unquoted spaced path up to twenty lines above.
_bad_buffer(lines, i, ident) if {
	i > 0
	re := concat("", [`\b`, ident, `\b`])
	some j in numbers.range(max([0, i - 20]), i - 1)
	not helpers.is_comment_line(lines[j])
	regex.match(re, lines[j])
	not _quoting_format(lines[j])
	_bad_literal_in(lines[j])
}

# A format string that wraps its argument in quotes ("\"%s\" --service")
# quotes the path it is given.
_quoting_format(line) if contains(line, `\"%`)

# ── CreateProcess(NULL, <command line>) ──────────────────────────────────

_reason(1, lines, i) := "CreateProcess with a NULL application name and an unquoted command line containing a space: Windows tries C:\\Program.exe, then each space-truncated prefix, before the intended program. Quote the path inside the command line or pass it as lpApplicationName" if {
	contains(lines[i], "CreateProcess")
	s := _stmt(lines, i, 6)
	m := regex.find_all_string_submatch_n(concat("", [`\bCreateProcess[AW]?\s*\(\s*`, _null, `\s*,\s*`, _prefix, `"((?:\\.|[^"\\])*)"`]), s, 1)
	count(m) > 0
	_bad_path(m[0][1])
}

_reason(2, lines, i) := "CreateProcess with a NULL application name runs a command-line buffer holding an unquoted path with a space: Windows tries each space-truncated prefix first. Quote the path inside the command line or pass it as lpApplicationName" if {
	contains(lines[i], "CreateProcess")
	s := _stmt(lines, i, 6)
	m := regex.find_all_string_submatch_n(concat("", [`\bCreateProcess[AW]?\s*\(\s*`, _null, `\s*,\s*&?\s*([A-Za-z_]\w*)(?:\s*\[\s*0\s*\]|\s*\.\s*(?:data|c_str)\s*\(\s*\))?\s*[,)]`]), s, 1)
	count(m) > 0
	_bad_buffer(lines, i, m[0][1])
}

# ── WinExec ──────────────────────────────────────────────────────────────

_reason(3, lines, i) := "WinExec splits its command line at the first space: an unquoted path with a space runs C:\\Program.exe (or another planted prefix) first. Quote the path" if {
	contains(lines[i], "WinExec")
	m := regex.find_all_string_submatch_n(concat("", [`\bWinExec\s*\(\s*`, _prefix, `"((?:\\.|[^"\\])*)"`]), lines[i], 1)
	count(m) > 0
	_bad_path(m[0][1])
}

_reason(4, lines, i) := "WinExec splits its command line at the first space: a buffer holding an unquoted path with a space runs a planted prefix first. Quote the path" if {
	contains(lines[i], "WinExec")
	m := regex.find_all_string_submatch_n(`\bWinExec\s*\(\s*([A-Za-z_]\w*)\s*,`, lines[i], 1)
	count(m) > 0
	_bad_buffer(lines, i, m[0][1])
}

# ── Service binary path ──────────────────────────────────────────────────

_reason(5, lines, i) := "The service binary path is an unquoted path with a space: the service control manager starts C:\\Program.exe (or another space-truncated prefix) as the service account. Register the path in quotes" if {
	contains(lines[i], "CreateService")
	regex.match(`\bCreateService[AW]?\s*\(`, lines[i])
	_bad_literal_in(_stmt(lines, i, 14))
}

_reason(6, lines, i) := "The service ImagePath is an unquoted path with a space: the service control manager starts C:\\Program.exe (or another space-truncated prefix) as the service account. Store the path in quotes" if {
	contains(lines[i], "ImagePath")
	regex.match(`SetValue|RegSetValue|RegSetKeyValue`, lines[i])
	s := _stmt(lines, i, 4)
	parts := split(s, "\"ImagePath\"")
	count(parts) > 1
	_bad_literal_in(concat("", ["(", parts[1]]))
}

_reason(7, lines, i) := "sc.exe binPath= is quoted only for the outer command line, so the service is registered with an unquoted path containing a space. Escape an inner pair of quotes (binPath= \"\\\"C:\\Program Files\\...\\\"\")" if {
	regex.match(`(?i)binpath=`, lines[i])
	some m in regex.find_all_string_submatch_n(`(?i)binpath=\s*(?:\\"|"")?([A-Za-z]:\\[^"]*)`, lines[i], -1)
	_bad_path(m[1])
}

findings contains finding if {
	some path, content in input.file_contents
	_in_scope(path)
	_has_needle(content)
	lines := split(content, "\n")
	some i, line in lines
	_has_needle(line)
	not helpers.is_comment_line(line)
	some k in [1, 2, 3, 4, 5, 6, 7]
	msg := _reason(k, lines, i)
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
