# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_403

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-403",
	"name": "Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')",
	"description": "Reports a long-lived file descriptor opened without close-on-exec in a C/C++ file that starts another program: open/openat/creat without O_CLOEXEC, socket without SOCK_CLOEXEC, or fopen with a literal mode lacking \"e\", whose result is assigned and not closed (close, fclose or dup2) within the next 40 lines, in a file that calls execv/execve/execvp/execl*/fexecve, posix_spawn(p), popen or system (plain, `::` or `std::` qualified). The child program inherits the descriptor and can read or write the file or socket. Not reported: files that use CLOEXEC anywhere (O_CLOEXEC, SOCK_CLOEXEC or FD_CLOEXEC through fcntl; the file is taken to manage inheritance, so a second open without it in such a file is missed) or close every descriptor before exec (close_range, closefrom, a loop to sysconf(_SC_OPEN_MAX)/getdtablesize or over F_GETFD), short-lived descriptors closed nearby, files that never start a program, test files, comments and string literals. Execs in another file than the open are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-403/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [403],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["fd-leak", "cwe-403"],
}

_c_file(path) if endswith(path, ".c")

_c_file(path) if endswith(path, ".cc")

_c_file(path) if endswith(path, ".cpp")

_c_file(path) if endswith(path, ".cxx")

_exec_re := `(?m)^[ \t]*(?:[^/* \t\n][^\n]*?[^\w.>:])?(?:(?:std)?::)?(execv|execve|execvp|execvpe|execl|execlp|execle|fexecve|posix_spawnp?|popen|system)\s*\(`

# Everything that already keeps descriptors out of children.
_mitigated(content) if contains(content, "CLOEXEC")

_mitigated(content) if regex.match(`close_range\s*\(|closefrom\s*\(|_SC_OPEN_MAX|getdtablesize\s*\(|F_GETFD`, content)

_strip(l) := regex.replace(l, `"(\\.|[^"\\])*"`, `""`)

# `fd = open(...)`, `s->sock = socket(...)`, `if ((fd = open(...)) < 0)`.
_open_re := `([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*=\s*(?:\([^()]*\)\s*)?(?:(?:std)?::)?(open|openat|creat|socket|fopen)\s*\(`

_esc(v) := regex.replace(v, `([.\->])`, `\$1`)

# The whole call, up to its terminating semicolon (at most 3 lines).
_call_text(lines, i) := concat(" ", [lines[k] | some k in numbers.range(i, min([count(lines) - 1, i + 2]))])

_no_cloexec("fopen", call, _) if {
	m := regex.find_all_string_submatch_n(`fopen\s*\([^;]*?,\s*"([^"]*)"`, call, 1)
	count(m) > 0
	not contains(m[0][1], "e")
}

_no_cloexec(fn, _, stripped) if {
	fn in {"open", "openat", "creat"}
	not contains(stripped, "O_CLOEXEC")
}

_no_cloexec("socket", _, stripped) if {
	regex.match(`socket\s*\(\s*(AF_|PF_)`, stripped)
	not contains(stripped, "SOCK_CLOEXEC")
}

_closed_soon(lines, i, v) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 40]))
	regex.match(concat("", [`\b(f?close|dup2)\s*\(\s*`, _esc(v), `\s*[,)]`]), lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	not helpers.is_test_path(path)
	regex.match(_exec_re, content)
	not _mitigated(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(open|openat|creat|socket)\s*\(`, line)
	not helpers.is_comment_line(line)
	stripped := _strip(line)
	m := regex.find_all_string_submatch_n(_open_re, stripped, 1)
	count(m) > 0
	v := m[0][1]
	fn := m[0][2]
	_no_cloexec(fn, _call_text(lines, i), _strip(_call_text(lines, i)))
	not _closed_soon(lines, i, v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is opened with %s() without close-on-exec, and this file starts other programs: every child inherits the descriptor. Add O_CLOEXEC / SOCK_CLOEXEC (\"e\" in the fopen mode) or set FD_CLOEXEC with fcntl.", [v, fn]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
