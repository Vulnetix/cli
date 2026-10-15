# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_268

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-268",
	"name": "Privilege Chaining",
	"description": "The program runs sudo, doas or pkexec with a command line that includes a runtime value, chaining whatever controls that value to the root rights granted to the program's account in sudoers or polkit. Reported in Python for subprocess.run (also through `import subprocess as sp` or `from subprocess import ...`)/call/check_call/check_output/Popen/getoutput, os.system, os.popen, os.exec*/os.spawn* and asyncio.create_subprocess_exec/shell, and in C and C++ for system, popen, the exec family and posix_spawn, when the command begins with sudo/doas/pkexec (or its /usr/bin path) and an argument is not a literal: a variable list element or argv, an f-string, concatenation, %-formatting or .format(), a .c_str() of a built string, or a command variable assigned or snprintf/sprintf-ed from such a sudo template in the eight lines above. Not reported: a fully constant privileged command (sudo systemctl reload nginx, sudo -n true, or one whose only names are ALL_CAPS constants such as *REQUIRED_PACKAGES), a value checked against an allow-list in the six lines above (if x not in ALLOWED, if x in (...)), commands without sudo/doas/pkexec, sudo text in messages and help strings, and the calls in comments. Whether the sudoers entry itself is too broad is outside the code and is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-268/",
	"languages": ["c", "cpp", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [268],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["privilege-chaining", "sudo", "cwe-268"],
}

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_lang(path) := "py" if endswith(path, ".py")

_spawn_re := {
	"py": `\b(?:subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)|os\.(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?)|asyncio\.create_subprocess_(?:exec|shell))\s*\(`,
	"c": `(?:^|[^\w.>])(?:::)?(?:std::)?(?:system|popen|exec[lv]p?e?|execvpe|posix_spawnp?)\s*\(`,
}

_py_spawn_fns := `(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)`

# The spawn regex for one file: Python also follows `import subprocess as sp`
# and `from subprocess import run, Popen`.
_spawn_for("c", _) := _spawn_re.c

_spawn_for("py", content) := concat("|", array.concat([_spawn_re.py], _py_alias_res(content)))

_py_alias_res(content) := array.concat(
	[concat("", [`\b`, m[1], `\.`, _py_spawn_fns, `\s*\(`]) |
		some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+subprocess\s+as\s+([A-Za-z_]\w*)`, content, -1)
	],
	[concat("", [`(?:^|[^\w.])`, _py_spawn_fns, `\s*\(`]) | regex.match(`(?m)^\s*from\s+subprocess\s+import\b`, content)],
)

# A string literal whose command is sudo, doas or pkexec.
_priv_lit_re := `(?:^|[^\w])[fFrRbB]?["'](?:/usr(?:/local)?/s?bin/|/s?bin/)?(?:sudo|doas|pkexec)(?:\s|["'])`

_priv_gate(s) if contains(s, "sudo")

_priv_gate(s) if contains(s, "doas")

_priv_gate(s) if contains(s, "pkexec")

# String literals blanked, so only code is left.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# The call's arguments: the rest of the line after the spawn call, and the
# next two lines when the call is broken after its opening parenthesis.
_args(lines, i, line, spawn) := a if {
	m := regex.find_all_string_submatch_n(concat("", [spawn, `(.*)$`]), line, 1)
	count(m) > 0
	rest := m[0][1]
	a := _with_next(lines, i, rest)
}

_with_next(_, _, rest) := rest if trim_space(rest) != ""

_with_next(lines, i, rest) := concat("\n", array.slice(lines, i + 1, i + 3)) if trim_space(rest) == ""

# A runtime value in the arguments.
_dynamic(arg) if regex.match(`\b[fF]["'][^"']*\{`, arg)

_dynamic(arg) if {
	c := _code(arg)
	no_kw := regex.replace(c, `\b\w+\s*=\s*[\w.]+`, "")
	no_calls := regex.replace(no_kw, `\.\w+\s*\(\s*\)`, "")
	no_null := regex.replace(no_calls, `\(\s*(?:const\s+)?char\s*\*\s*\)|\bNULL\b|\bnullptr\b|\bstd::|\*?\b[A-Z][A-Z0-9_]{2,}\b`, "")
	regex.match(`[A-Za-z_]\w*|%|\+`, no_null)
}

_message := "sudo/doas/pkexec run with a command line built from a runtime value: whoever controls that value can reach the root rights granted to this program's account. Run a fixed command with a validated, allow-listed argument, or move the privileged action into a dedicated helper"

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _message,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# The privileged command is written in the call.
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_priv_gate(content)
	spawn := _spawn_for(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(spawn, line)
	arg := _args(lines, i, line, spawn)
	regex.match(_priv_lit_re, arg)
	_dynamic(arg)
	not _allow_listed(lines, i, arg)
	finding := _finding(path, i, line)
}

# A value checked against an allow-list in the six lines above
# (`if x not in ALLOWED: raise`, `if x in ("a", "b"):`).
_allow_listed(lines, i, arg) if {
	some j in numbers.range(max([0, i - 6]), i - 1)
	m := regex.find_all_string_submatch_n(`\bif\s+([A-Za-z_]\w*)\s+(?:not\s+)?in\s+(?:[A-Z_][A-Z0-9_]{2,}\b|[\(\[\{])`, lines[j], 1)
	count(m) > 0
	regex.match(concat("", [`\b`, m[0][1], `\b`]), _code(arg))
}

# The command variable is built from a sudo template a few lines above.
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_priv_gate(content)
	spawn := _spawn_for(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(spawn, line)
	arg := _args(lines, i, line, spawn)
	m := regex.find_all_string_submatch_n(`^\s*\[?\s*([A-Za-z_]\w*)(?:\s*\.\s*(?:c_str|data)\s*\(\s*\))?\s*[,)\]]`, arg, 1)
	count(m) > 0
	v := m[0][1]
	_built_above(lines, i, v)
	finding := _finding(path, i, line)
}

_built_above(lines, i, v) if {
	some j in numbers.range(max([0, i - 8]), i - 1)
	prev := lines[j]
	_priv_gate(prev)
	not helpers.is_comment_line(prev)
	regex.match(concat("", [`^\s*(?:[\w:<>*\s]+\s)?`, v, `\s*=\s*`]), prev)
	regex.match(_priv_lit_re, prev)
	_dynamic(regex.replace(prev, concat("", [`^\s*(?:[\w:<>*\s]+\s)?`, v, `\s*=\s*`]), ""))
}

_built_above(lines, i, v) if {
	some j in numbers.range(max([0, i - 8]), i - 1)
	prev := lines[j]
	_priv_gate(prev)
	not helpers.is_comment_line(prev)
	regex.match(concat("", [`\bs?n?printf\s*\(\s*`, v, `\s*,.*"(?:/usr(?:/local)?/s?bin/)?(?:sudo|doas|pkexec)\s[^"]*%`]), prev)
}
