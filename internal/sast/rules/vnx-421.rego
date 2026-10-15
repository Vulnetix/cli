# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_421

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-421",
	"name": "Race Condition During Access to Alternate Channel",
	"description": "A local side channel (a Unix domain socket, a FIFO or a Windows named pipe) is created at a name another local user can claim first, so whoever wins the race owns the channel: the attacker pre-creates the socket or pipe, the service fails to bind or its clients talk to the attacker instead. Reported: C/C++ mkfifo/mkfifoat/mknod and a sockaddr_un sun_path filled (strcpy, strncpy, strlcpy, snprintf, memcpy, a designated initializer) with a fixed path in a shared world-writable directory (/tmp, /var/tmp, /dev/shm), directly or through a #define, a constant or a buffer filled by snprintf/sprintf with such a format (\"/tmp/jobs.%d.fifo\"); Go net.Listen/ListenPacket(\"unix\", ...), net.UnixAddr{Name: ...}, net.ResolveUnixAddr and syscall/unix.Mkfifo with such a path (a literal, a fmt.Sprintf format, a constant or variable, or filepath.Join of \"/tmp\" or os.TempDir()); Python os.mkfifo, socket .bind in a file that uses AF_UNIX, asyncio start_unix_server/create_unix_server and socketserver UnixStreamServer/UnixDatagramServer with such a path (a literal, an f-string or %-format, or os.path.join of tempfile.gettempdir(); pathlib Path(\"/tmp\") / name is not followed); and C/C++ CreateNamedPipe(A/W) in a file that never passes FILE_FLAG_FIRST_PIPE_INSTANCE, which lets another process create the first instance of the pipe name. Call arguments split over the next lines are read with the call. Not reported: sockets and FIFOs in a private directory (/run/<service>/, a mkdtemp/MkdirTemp result, $XDG_RUNTIME_DIR), client-side connects, paths only computed at run time, test files, comments and string literals that are not passed to these calls.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-421/",
	"languages": ["c", "cpp", "go", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [421],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["race-during-alternate-channel", "unix-socket", "named-pipe", "cwe-421"],
}

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx"}
	endswith(path, ext)
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "py" if endswith(path, ".py")

_shared_dir := `/(?:tmp|var/tmp|dev/shm)`

# A literal path in a shared world-writable directory.
_tmp_lit := concat("", [`^(?:fmt\.Sprintf\s*\(\s*)?[fF]?[rR]?["']`, _shared_dir, `/[^"']+["']`])

# A join whose first element is the shared temp directory.
_tmp_join := concat("", [`^(?:os\.path\.join|filepath\.Join|path\.Join|path\.join)\s*\(\s*(?:["']`, _shared_dir, `/?["']|tempfile\.gettempdir\s*\(\s*\)|os\.TempDir\s*\(\s*\))`])

_arg := `(fmt\.Sprintf\s*\(\s*"[^"]*"|[fF][rR]?"[^"]*"|[fF][rR]?'[^']*'|"[^"]*"|'[^']*'|(?:os\.path\.join|filepath\.Join|path\.Join|path\.join)\s*\([^)]*\)?|[A-Za-z_]\w*)`

_sinks := {
	"c": [
		concat("", [`(?:^|[^\w.>])(?:mkfifo|mknod)\s*\(\s*`, _arg]),
		concat("", [`(?:^|[^\w.>])mkfifoat\s*\(\s*[^,]+,\s*`, _arg]),
		concat("", [`\b\w*(?:strcpy|strncpy|strlcpy|snprintf|memcpy)\s*\(\s*[\w.>\[\]-]*sun_path\s*,\s*(?:sizeof\s*\(?[^,]*,\s*)?`, _arg]),
		concat("", [`\.sun_path\s*=\s*`, _arg]),
	],
	"go": [
		concat("", [`\bnet\.(?:Listen|ListenPacket)\s*\(\s*"unix(?:packet|gram)?"\s*,\s*`, _arg]),
		concat("", [`\bnet\.ResolveUnixAddr\s*\(\s*"unix(?:packet|gram)?"\s*,\s*`, _arg]),
		concat("", [`\bUnixAddr\s*\{[^}]*\bName\s*:\s*`, _arg]),
		concat("", [`\b(?:syscall|unix)\.Mkfifo\s*\(\s*`, _arg]),
	],
	"py": [
		concat("", [`\bos\.mkfifo\s*\(\s*`, _arg]),
		concat("", [`\b(?:start_unix_server|create_unix_server)\s*\([^)]*?\bpath\s*=\s*`, _arg]),
		concat("", [`\b(?:start_unix_server|create_unix_server)\s*\(\s*[\w.]+\s*,\s*`, _arg]),
		concat("", [`\bUnix(?:Stream|Datagram)Server\s*\(\s*`, _arg]),
	],
}

# Python .bind only counts in a file that creates AF_UNIX sockets.
_py_bind := concat("", [`\.bind\s*\(\s*`, _arg])

_gate := {
	"c": `mkfifo|mknod|sun_path`,
	"go": `"unix|UnixAddr|Mkfifo`,
	"py": `mkfifo|unix_server|UnixStreamServer|UnixDatagramServer|AF_UNIX`,
}

_strip_comment(lang, s) := regex.replace(s, `\s#.*$`, "") if lang == "py"

_strip_comment(lang, s) := regex.replace(s, `\s//.*$`, "") if lang != "py"

# The argument names a shared-temp path: a literal, a join, or a name the
# file defines as one.
_shared(arg, _) if regex.match(_tmp_lit, arg)

_shared(arg, _) if regex.match(_tmp_join, arg)

_shared(arg, content) if {
	regex.match(`^[A-Za-z_]\w*$`, arg)
	regex.match(concat("", [
		`(?m)(?:#\s*define\s+`, arg, `\s+|\b`, arg, `\s*(?:\[\s*\]\s*)?(?::=|=)\s*)(?:(?:fmt\.Sprintf\s*\(\s*)?[fF]?["']`, _shared_dir, `/[^"']+["']|(?:os\.path\.join|filepath\.Join|path\.Join|path\.join)\s*\(\s*(?:["']`, _shared_dir, `/?["']|tempfile\.gettempdir\s*\(\s*\)|os\.TempDir\s*\(\s*\)))`,
	]), content)
}

# C: snprintf(buf, sizeof buf, "/tmp/jobs.%d.fifo", getpid()) fills the name.
_shared(arg, content) if {
	regex.match(`^[A-Za-z_]\w*$`, arg)
	regex.match(concat("", [`(?m)\bs?n?printf\s*\(\s*`, arg, `\s*,\s*(?:sizeof\s*\(?[^,]*,\s*)?"`, _shared_dir, `/`]), content)
}

# A call whose arguments continue on the next lines is read with them.
_joined(lang, lines, i) := c if {
	l := _strip_comment(lang, lines[i])
	count(regex.find_n(`\(`, l, -1)) > count(regex.find_n(`\)`, l, -1))
	c := concat(" ", [trim_space(_strip_comment(lang, x)) | some x in array.slice(lines, i, min([count(lines), i + 4]))])
} else := _strip_comment(lang, lines[i])

_sink_args(lang, code, content) := {m[1] |
	some re in _sinks[lang]
	some m in regex.find_all_string_submatch_n(re, code, -1)
} | _bind_args(lang, code, content)

_bind_args(lang, code, content) := {m[1] |
	some m in regex.find_all_string_submatch_n(_py_bind, code, -1)
} if {
	lang == "py"
	contains(content, "AF_UNIX")
} else := set()

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	regex.match(_shared_dir, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`mkfifo|mknod|sun_path|unix|Unix|Mkfifo|\.bind\s*\(|\bnet\.(?:Listen|ListenPacket|ResolveUnixAddr)\s*\(\s*$`, line)
	not helpers.is_comment_line(line)
	code := _joined(lang, lines, i)
	some arg in _sink_args(lang, code, content)
	_shared(arg, content)
	finding := _finding(path, i, line, "This Unix socket or FIFO is created at a fixed name in a shared world-writable directory: another local user can create that name first, so the service fails to bind or its clients connect to the attacker's endpoint instead. Create it inside a directory only the service can write (/run/<service>/, $XDG_RUNTIME_DIR, a mkdtemp() directory)")
}

# Windows named pipe without FILE_FLAG_FIRST_PIPE_INSTANCE.
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "c"
	contains(content, "CreateNamedPipe")
	not contains(content, "FILE_FLAG_FIRST_PIPE_INSTANCE")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "CreateNamedPipe")
	not helpers.is_comment_line(line)
	regex.match(`(?:^|[^\w.>"])CreateNamedPipe[AW]?\s*\(`, regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`))
	finding := _finding(path, i, line, "CreateNamedPipe is called without FILE_FLAG_FIRST_PIPE_INSTANCE anywhere in this file: another process can create the first instance of this pipe name before the service does and receive its clients' connections and data. Pass FILE_FLAG_FIRST_PIPE_INSTANCE when creating the first instance and fail if the name already exists")
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
