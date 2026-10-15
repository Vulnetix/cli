# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_420

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-420",
	"name": "Unprotected Alternate Channel",
	"description": "A side channel into the service is left open to anyone while its main channel is protected. Two shapes. A local control socket made world-writable: in a C, C++, Go or Python file that creates a Unix domain socket (AF_UNIX/AF_LOCAL with bind, net.Listen/ListenUnix(\"unix\"), socket.AF_UNIX, asyncio start_unix_server/create_unix_server), a chmod/os.Chmod/os.chmod/pathlib Path.chmod whose mode lets other users write (0777, 0666, 0o777, any octal whose last digit grants write, S_IWOTH, S_IRWXO, ACCESSPERMS, ALLPERMS, DEFFILEMODE, os.ModePerm; arguments split over the next lines are read with the call), a C++ std::filesystem::permissions(..., perms::all/others_all/others_write) that does not remove them, or a umask(0)/syscall.Umask(0)/os.umask(0) that makes the socket file created by bind world-writable when the file never chmods it afterwards; any local user can then drive the service through it. And in Go, a plaintext http.ListenAndServe on a non-loopback address in a file that also serves TLS (ListenAndServeTLS, ServeTLS) where one of the two is started in a goroutine (go ..., go func, errgroup Go(func...)) so both run at once (a blocking plaintext call on one branch of an if/else, or before a TLS fallback, is a configuration choice and is not reported), unless the plaintext handler only redirects to HTTPS (http.Redirect, a handler named redirect*, autocert HTTPHandler, an https:// target nearby, or a handler function in the same file that calls http.Redirect) or serves only metrics, profiling or health checks (promhttp.Handler, pprof, expvar, /metrics, healthz). Not reported: modes without the other-write bit (0755, 0660, 0700), sockets bound to loopback, files that do not create a Unix socket, test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-420/",
	"languages": ["c", "cpp", "go", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [420],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["unprotected-alternate-channel", "unix-socket", "cwe-420"],
}

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx"}
	endswith(path, ext)
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "py" if endswith(path, ".py")

# The file creates a Unix domain socket.
_unix_socket := {
	"c": `\bAF_(?:UNIX|LOCAL)\b[\s\S]*\bbind\s*\(|\bbind\s*\([\s\S]*\bAF_(?:UNIX|LOCAL)\b`,
	"go": `\bnet\.(?:Listen|ListenUnix|ListenPacket)\s*\(\s*"unix(?:packet|gram)?"`,
	"py": `\bAF_UNIX\b|\b(?:start_unix_server|create_unix_server)\s*\(|UnixStreamServer|UnixDatagramServer`,
}

_ww_octal := `\b0[oO]?[0-7]?[0-7][0-7][2367]\b`

_ww_mode := {
	"c": concat("|", [_ww_octal, `\bS_IWOTH\b|\bS_IRWXO\b|\bACCESSPERMS\b|\bALLPERMS\b|\bDEFFILEMODE\b`]),
	"go": concat("|", [_ww_octal, `\bos\.ModePerm\b|\b0o?777\b`]),
	"py": concat("|", [_ww_octal, `\bstat\.S_IWOTH\b|\bstat\.S_IRWXO\b`]),
}

_chmod := {
	"c": `(?:^|[^\w.>])f?chmod\s*\((.*)\)`,
	"go": `\bos\.Chmod\s*\((.*)\)|\.Chmod\s*\((.*)\)`,
	"py": `\bos\.f?chmod\s*\((.*)\)`,
}

_umask0 := {
	"c": `(?:^|[^\w.>])umask\s*\(\s*0+\s*\)`,
	"go": `\b(?:syscall|unix)\.Umask\s*\(\s*0+\s*\)`,
	"py": `\bos\.umask\s*\(\s*0(?:o0+)?\s*\)`,
}

_strip(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

# A call whose arguments continue on the next lines is read with them.
_joined(lines, i) := c if {
	l := _strip(lines[i])
	count(regex.find_n(`\(`, l, -1)) > count(regex.find_n(`\)`, l, -1))
	c := concat(" ", [_strip(x) | some x in array.slice(lines, i, min([count(lines), i + 3]))])
} else := _strip(lines[i])

_mode_arg(code, lang) := a if {
	m := regex.find_all_string_submatch_n(_chmod[lang], code, 1)
	count(m) > 0
	args := [x | some x in array.slice(m[0], 1, count(m[0])); x != ""]
	a := args[0]
}

# chmod with a world-writable mode in a file that creates a Unix socket.
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(lower(content), "chmod")
	regex.match(_unix_socket[lang], content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(lower(line), "chmod")
	not helpers.is_comment_line(line)
	code := _joined(lines, i)
	a := _mode_arg(code, lang)
	parts := split(a, ",")
	count(parts) >= 2
	regex.match(_ww_mode[lang], concat(",", array.slice(parts, 1, count(parts))))
	finding := _finding(path, i, line, "The Unix control socket is given a mode that lets every local user write to it: any account on the host can connect and drive the service through this side channel without the authentication the main channel requires. Restrict it to the owner or a dedicated group (0600 or 0660) and check the peer's credentials (SO_PEERCRED) on connect")
}

# Python pathlib: Path(sock).chmod(0o666) takes the mode as its first argument.
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "py"
	contains(content, ".chmod(")
	regex.match(_unix_socket.py, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".chmod(")
	not helpers.is_comment_line(line)
	code := _strip(line)
	m := regex.find_all_string_submatch_n(`([A-Za-z_][\w.]*(?:\([^()]*\))?)\.chmod\s*\(\s*(?:mode\s*=\s*)?([^,)]*)`, code, 1)
	count(m) > 0
	not m[0][1] in {"os", "posix"}
	regex.match(_ww_mode.py, m[0][2])
	finding := _finding(path, i, line, "The Unix control socket is given a mode that lets every local user write to it: any account on the host can connect and drive the service through this side channel without the authentication the main channel requires. Restrict it to the owner or a dedicated group (0o600 or 0o660) and check the peer's credentials (SO_PEERCRED) on connect")
}

# C++17: std::filesystem::permissions(sock, perms::all / others_write ...)
# in a file that creates a Unix socket.
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "c"
	contains(content, "permissions")
	regex.match(_unix_socket.c, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "permissions")
	not helpers.is_comment_line(line)
	code := _joined(lines, i)
	regex.match(`\bpermissions\s*\([^;]*\bperms::(?:all|others_all|others_write)\b`, code)
	not regex.match(`perm_options::remove`, code)
	finding := _finding(path, i, line, "The Unix control socket is given permissions that let every local user write to it: any account on the host can connect and drive the service through this side channel without the authentication the main channel requires. Restrict it to owner_read|owner_write (and a dedicated group) and check the peer's credentials (SO_PEERCRED) on connect")
}

# umask(0) in a file that binds a Unix socket and never chmods it.
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(lower(content), "umask")
	regex.match(_unix_socket[lang], content)
	not regex.match(_chmod[lang], content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(lower(line), "umask")
	not helpers.is_comment_line(line)
	regex.match(_umask0[lang], _strip(line))
	finding := _finding(path, i, line, "umask(0) before binding a Unix socket creates the socket file world-writable, and nothing chmods it afterwards: any local user can connect and use this side channel. Use a restrictive umask (0077) around bind, or chmod the socket to 0600/0660")
}

# ── Go: plaintext listener beside a TLS one ──────────────────────────────

_loopback := `127\.0\.0\.1|\blocalhost\b|\[::1\]`

_redirect := `(?i)redirect|HTTPHandler\s*\(|https://|StatusMovedPermanently|StatusPermanentRedirect`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`ListenAndServeTLS\(|ServeTLS\(`, content)
	contains(content, "http.ListenAndServe(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "http.ListenAndServe(")
	not helpers.is_comment_line(line)
	not regex.match(_loopback, line)
	not regex.match(_redirect, helpers.code_window(lines, i, 5, 5))
	not regex.match(_ops_only, line)
	not _redirect_handler(lines, line)
	_concurrent(lines, i)
	finding := _finding(path, i, line, "This plaintext HTTP listener serves the application beside a TLS listener in the same program: the protected channel can be bypassed by talking to this one, where credentials and session cookies travel unencrypted. Serve only TLS, or make the plaintext listener do nothing but redirect to HTTPS")
}

# Both listeners run at once only when one of them is started in a goroutine
# (go ..., go func() {, errgroup g.Go(func...): a blocking ListenAndServe
# never returns, so a plaintext call on one branch of an if/else, or before a
# TLS fallback, is a configuration choice, not a second channel.
_in_goroutine(lines, k) if regex.match(`^\s*go\s`, lines[k])

_in_goroutine(lines, k) if {
	some j in numbers.range(max([0, k - 4]), k - 1)
	regex.match(`\bgo\s+func\s*\(|\.Go\s*\(\s*func\s*\(`, lines[j])
	not _closed(lines, j, k)
}

_closed(lines, j, k) if {
	k > j + 1
	some x in numbers.range(j + 1, k - 1)
	regex.match(`^\s*\}`, lines[x])
}

_concurrent(lines, i) if _in_goroutine(lines, i)

_concurrent(lines, i) if {
	some k, l in lines
	regex.match(`ListenAndServeTLS\(|ServeTLS\(`, l)
	not helpers.is_comment_line(l)
	_in_goroutine(lines, k)
}

# Metrics, profiling and health endpoints on their own port are operational
# listeners, not a second copy of the application.
_ops_only := `promhttp\.Handler\s*\(|\bpprof\b|expvar\.Handler|(?i)healthz?\b|"/metrics"`

# The plaintext handler is a function in this file that redirects:
# http.ListenAndServe(":80", http.HandlerFunc(upgrade)).
_redirect_handler(lines, line) if {
	m := regex.find_all_string_submatch_n(`http\.ListenAndServe\s*\(([^;]*)\)`, line, 1)
	count(m) > 0
	some id in regex.find_n(`[A-Za-z_]\w*`, m[0][1], -1)
	not id in {"http", "HandlerFunc", "nil", "log", "Fatal"}
	some j, l in lines
	regex.match(concat("", [`^func\s+(?:\([^)]*\)\s*)?`, id, `\s*\(`]), l)
	regex.match(`http\.Redirect\s*\(`, concat("\n", array.slice(lines, j, min([count(lines), j + 12]))))
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
