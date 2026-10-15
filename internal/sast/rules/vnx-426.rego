# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_426

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-426",
	"name": "Untrusted Search Path",
	"description": "A Python program finds code, libraries or commands through a location it does not control, usually the current working directory, so whoever controls that directory chooses what runs. Reported: sys.path.insert/append/extend (or sys.path[:0] =) and site.addsitedir with an empty string, \".\", \"..\", a relative literal, os.getcwd(), os.curdir, Path.cwd(), os.path.abspath of a relative literal or os.path.join starting from os.getcwd() or a relative literal; os.environ[...] =, os.putenv, os.environ.update(VAR=...), dict(os.environ, VAR=...) or an env dict item setting PATH, PYTHONPATH, LD_LIBRARY_PATH, LD_PRELOAD, DYLD_LIBRARY_PATH or DYLD_INSERT_LIBRARIES to a concatenation with an empty element (a leading, trailing or doubled ':' or os.pathsep), \".\" or a relative directory (os.pathsep.join([...]) is read element by element), and os.environ[VAR] += an addition with such an element; subprocess run/call/check_call/check_output/Popen, os.system, os.popen, os.exec* and os.spawn* running a command by a cwd-relative path (\"./tool\", \"../bin/x\", \"bin/x\") with no cwd= argument; a command run by bare name (resolved through PATH) in a file that makes the process root with os.setuid(0)/seteuid(0)/setresuid(0, ...); and ctypes CDLL/WinDLL/OleDLL/PyDLL/LoadLibrary of a cwd-relative path or of a bare .dll name that is not a Windows KnownDLL, given as a literal or as a name every assignment of which in the file is such a literal. Not reported: paths anchored to __file__, sys.prefix or an absolute directory, commands run by bare name in an unprivileged program (normal PATH use), a call that sets cwd=, bare sonames (\"libc.so.6\") and ctypes.util.find_library, test files, comments and string literals. C and C++ search-path elements are VNX-427.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-426/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [426],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["untrusted-search-path", "cwe-426"],
}

_strip_comment(s) := regex.replace(s, `\s+#[^"']*$`, "")

# Code quoted inside a string literal (a string holding a call) is not code.
_code(s) := regex.replace(_strip_comment(s), `"[^"]*\([^"]*"|'[^']*\([^']*'`, `""`)

_joined(lines, i, n) := concat(" ", [lines[i], trim_space(lines[i + 1])]) if {
	i + 1 < n
	regex.match(`[(\[,]\s*$`, lines[i])
} else := lines[i]

# A string literal (optionally prefixed) that names a cwd-relative location.
_rel_lit := `[rbuRBU]?["'](?:|\.{1,2}|\.{1,2}/[^"']*|[A-Za-z_][\w.-]*(?:/[^"']*)?)["']`

_cwd_expr := concat("", [`(?:str\s*\(\s*)?(?:`, _rel_lit, `|os\.getcwd\s*\(\s*\)|os\.curdir\b|(?:pathlib\.)?Path\.cwd\s*\(\s*\)|(?:pathlib\.)?Path\s*\(\s*(?:["']\.?["'])?\s*\)|os\.path\.(?:abspath|realpath)\s*\(\s*`, _rel_lit, `\s*\)|os\.path\.join\s*\(\s*(?:os\.getcwd\s*\(\s*\)|os\.curdir\b|`, _rel_lit, `))`])

_syspath_re := concat("", [`\b(?:site\.addsitedir\s*\(\s*|sys\.path\s*(?:\.\s*insert\s*\(\s*[^,]+,\s*|\.\s*append\s*\(\s*|\.\s*extend\s*\(\s*\[\s*|\[\s*:\s*0\s*\]\s*=\s*\[\s*|=\s*\[\s*))`, _cwd_expr, `\s*[,)\]]`])

# Sphinx configuration is executed by sphinx-build from its own directory.
_sphinx_conf(path) if regex.match(`(?:^|/)(?:docs?|documentation)/(?:source/)?conf\.py$`, path)

_msg_syspath :="A directory relative to the current working directory is put on the module search path: whoever controls the directory the program is started from can plant a module there and have it imported. Anchor the path to the program itself (os.path.dirname(os.path.abspath(__file__))) or install the package"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`sys\.path|site\.addsitedir`, content)
	not helpers.is_test_path(path)
	not _sphinx_conf(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`sys\.path|site\.addsitedir`, line)
	not helpers.is_comment_line(line)
	regex.match(_syspath_re, _code(line))
	finding := _finding(path, i, line, _msg_syspath)
}

# ── PATH-like environment variables ──────────────────────────────────────

_pathvars := `PATH|PYTHONPATH|LD_LIBRARY_PATH|LD_PRELOAD|DYLD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES`

_env_set_re := concat("", [
	`(?:\b[\w.]*environ|\b\w*env\w*)\s*\[\s*["'](`, _pathvars, `)["']\s*\]\s*=\s*(.+)$|\bos\.putenv\s*\(\s*["'](`, _pathvars, `)["']\s*,\s*(.+)\)\s*$|\bos\.environ\.update\s*\(\s*(`, _pathvars, `)\s*=\s*(.+)\)\s*$|\bdict\s*\(\s*(?:os\.)?environ\s*,[^)]*?\b(`, _pathvars, `)\s*=\s*(.+)\)\s*$`,
])

_env_value(code) := v if {
	m := regex.find_all_string_submatch_n(_env_set_re, code, 1)
	count(m) > 0
	vs := [x | some k in [2, 4, 6, 8]; x := m[0][k]; x != ""]
	v := vs[0]
}

# os.environ["PATH"] += os.pathsep + ".": the existing value comes first.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "+=")
	regex.match(concat("", [`["'](?:`, _pathvars, `)["']\s*\]\s*\+=`]), content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "+=")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`(?:\b[\w.]*environ|\b\w*env\w*)\s*\[\s*["'](?:`, _pathvars, `)["']\s*\]\s*\+=\s*(.+)$`]), _strip_comment(line), 1)
	count(m) > 0
	v := trim_space(m[0][1])
	not regex.match(`^\s*\w+\s*$`, v)
	_bad_search_path(concat("", ["/X", _assembled(v)]))
	finding := _finding(path, i, line, _msg_env)
}

# Reads of the environment and interpolations stand for absolute values.
_normalise(v) := regex.replace(regex.replace(v, `os\.environ(?:\.get)?\s*(?:\[[^\]]*\]|\([^)]*\))|os\.getenv\s*\([^)]*\)|\{[^{}]*\}`, "/X"), `os\.pathsep`, `":"`)

_tok_re := `[rbfuRBFU]{0,2}"(?:[^"\\]|\\.)*"|[rbfuRBFU]{0,2}'(?:[^'\\]|\\.)*'|[^+\s"']+`

_tok_text(t) := regex.replace(t, `^[rbfuRBFU]{0,2}["']|["']$`, "") if regex.match(`^[rbfuRBFU]{0,2}["']`, t)

_tok_text(t) := "/X" if not regex.match(`^[rbfuRBFU]{0,2}["']`, t)

# os.pathsep.join([a, b, ...]): the elements are joined by ':'.
_assembled(v) := s if {
	m := regex.find_all_string_submatch_n(`^\s*":"\s*\.\s*join\s*\(\s*[\[(](.*)[\])]\s*\)\s*$`, _normalise(v), 1)
	count(m) > 0
	s := concat(":", [_elem_text(trim_space(e)) | some e in split(m[0][1], ","); trim_space(e) != ""])
} else := concat("", [_tok_text(t) | some t in regex.find_n(_tok_re, _normalise(v), -1)])

_elem_text(e) := regex.replace(e, `^[rbfuRBFU]{0,2}["']|["']$`, "") if regex.match(`^[rbfuRBFU]{0,2}["'][^"']*["']$`, e)

_elem_text(e) := "/X" if not regex.match(`^[rbfuRBFU]{0,2}["'][^"']*["']$`, e)

_bad_search_path(s) if regex.match(`^:|::|:$`, s)

_bad_search_path(s) if regex.match(`(?:^|:)(?:\.{1,2}(?:/[^:]*)?|[A-Za-z_][^:/]*(?:/[^:]*)?)(?::|$)`, s)

_msg_env := "A PATH-like search path is given an empty, '.' or relative element: programs or libraries are then looked up in the current working directory, where anyone controlling it can plant one. Use absolute directories only, and never leave a leading, trailing or doubled separator"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(concat("", [`["'](?:`, _pathvars, `)["']|(?:update\s*\(|,)\s*(?:`, _pathvars, `)\s*=`]), content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`PATH|LD_PRELOAD|DYLD_INSERT`, line)
	not helpers.is_comment_line(line)
	v := _env_value(_strip_comment(line))
	not regex.match(`^\s*\w+\s*$`, v)
	_bad_search_path(_assembled(trim_space(v)))
	finding := _finding(path, i, line, _msg_env)
}

# ── Commands ─────────────────────────────────────────────────────────────

_exec_call := `\b(?:subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)|os\.(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?)|(?:sp|sub)\.(?:run|call|check_call|check_output|Popen))\s*\(`

# First argument: a string literal, or the first element of a list/tuple
# (os.exec*/spawn* take a mode or path first; their path is the first
# string too).
_first_cmd(code) := c if {
	m := regex.find_all_string_submatch_n(concat("", [_exec_call, `\s*(?:os\.P_\w+\s*,\s*)?[\[(]?\s*[rfbu]?["']([^"']*)["']`]), code, 1)
	count(m) > 0
	c := m[0][1]
}

_cwd_relative_cmd(c) if {
	word := split(trim_space(c), " ")[0]
	regex.match(`^(?:\.{1,2}/|[A-Za-z_][\w.-]*/)`, word)
}

_bare_cmd(c) if {
	word := split(trim_space(c), " ")[0]
	regex.match(`^[A-Za-z_][\w.+-]*$`, word)
}

_privileged(content) if regex.match(`\bos\.(?:setuid|seteuid|setreuid|setresuid)\s*\(\s*0\b|\bos\.setre?s?uid\s*\(\s*-1\s*,\s*0\b`, content)

_msg_relcmd := "This command is run by a path relative to the current working directory: started from another directory the program runs whatever file of that name is there. Build the path from the program's own location (os.path.dirname(__file__)) or pass cwd= to a directory the program controls"

_msg_barecmd := "This process makes itself root and then runs a command by bare name, so the command is found through PATH: whoever controls PATH or a directory on it decides what runs as root. Call the command by its absolute path (/usr/bin/...) and reset PATH to a fixed value first"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`subprocess|os\.(?:system|popen|exec|spawn|posix_spawn)`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	n := count(lines)
	some i, line in lines
	regex.match(`subprocess|os\.|\b(?:sp|sub)\.`, line)
	not helpers.is_comment_line(line)
	code := _code(_joined(lines, i, n))
	c := _first_cmd(code)
	msg := _cmd_msg(content, c)
	not regex.match(`\bcwd\s*=`, concat(" ", array.slice(lines, i, min([n, i + 4]))))
	finding := _finding(path, i, line, msg)
}

_cmd_msg(_, c) := _msg_relcmd if _cwd_relative_cmd(c)

_cmd_msg(content, c) := _msg_barecmd if {
	not _cwd_relative_cmd(c)
	_bare_cmd(c)
	_privileged(content)
}

# ── ctypes ───────────────────────────────────────────────────────────────

_known_dlls := `(?i)^(?:kernel32|kernelbase|user32|gdi32|ntdll|advapi32|shell32|ole32|oleaut32|comdlg32|comctl32|ws2_32|crypt32|secur32|shlwapi|rpcrt4|msvcrt|ucrtbase|setupapi|winmm|version|bcrypt|iphlpapi|psapi|userenv|wininet|winhttp|dbghelp|imm32|wtsapi32|netapi32|mpr|normaliz|wldap32|clbcatq|combase|difxapi|gdiplus|imagehlp|msctf|sechost|shcore|wow64)(?:\.dll)?$`

_ctypes_re := `\b(?:ctypes\.)?(?:CDLL|WinDLL|OleDLL|PyDLL|(?:cdll|windll|oledll|pydll)\.LoadLibrary|LibraryLoader\s*\([^)]*\)\.LoadLibrary)\s*\(\s*[rbu]?["']([^"']+)["']`

_bad_lib(name) if regex.match(`^(?:\.{1,2}/|\.{1,2}\\|[A-Za-z_][\w.-]*[/\\])`, name)

_bad_lib(name) if {
	regex.match(`(?i)^[\w.-]+\.dll$`, name)
	not regex.match(_known_dlls, name)
}

_msg_lib := "This native library is loaded by a relative path or a bare DLL name, so it is searched for in the current working directory (and, on Windows, the application directory and PATH): a planted library of that name is loaded and runs inside the process. Load it by an absolute path built from the program's location, or with winmode/LOAD_LIBRARY_SEARCH_* restricted to System32"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`CDLL|WinDLL|OleDLL|PyDLL|LoadLibrary`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`DLL|LoadLibrary`, line)
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_ctypes_re, _code(line), -1)
	_bad_lib(m[1])
	finding := _finding(path, i, line, _msg_lib)
}

# LIB = "./native/libscan.so" ... ctypes.CDLL(LIB): a name assigned a string
# literal in this file (every assignment of it).
_ctypes_var_re := `\b(?:ctypes\.)?(?:CDLL|WinDLL|OleDLL|PyDLL|(?:cdll|windll|oledll|pydll)\.LoadLibrary)\s*\(\s*([A-Za-z_]\w*)\s*[,)]`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`CDLL|WinDLL|OleDLL|PyDLL|LoadLibrary`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`DLL|LoadLibrary`, line)
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_ctypes_var_re, _code(line), -1)
	v := m[1]
	defs := regex.find_all_string_submatch_n(concat("", [`(?m)^\s*`, v, `\s*(?::\s*\w+\s*)?=\s*(.*)$`]), content, -1)
	count(defs) > 0
	every d in defs {
		regex.match(`^[rbu]?["'][^"']+["']\s*(?:#.*)?$`, trim_space(d[1]))
	}
	val := regex.replace(trim_space(defs[0][1]), `^[rbu]?["']|["']\s*(?:#.*)?$`, "")
	_bad_lib(val)
	finding := _finding(path, i, line, _msg_lib)
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
