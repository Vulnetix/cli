# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_419

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-419",
	"name": "Unprotected Primary Channel",
	"description": "An administrative or management interface is served over a plaintext listener reachable from the network, so its credentials and commands cross the wire unencrypted. Reported in Go: http.ListenAndServe(addr, handler) whose address or handler names an admin/management/mgmt interface; X.ListenAndServe() or X.Serve(ln) where X is named for one, or is an http.Server literal whose Addr or Handler is; net.Listen(\"tcp\", addr) with an admin address whose listener is not wrapped by tls.NewListener. In Java and Kotlin: new ServerSocket(...), ServerSocketChannel bind(...) (also ch.bind(...) on a channel opened earlier in the file) and com.sun.net.httpserver HttpServer.create(...) whose variable (also on the declaration line it continues), port or address names an admin/management interface; Go call arguments split over the next lines are read with the call. Not reported: ListenAndServeTLS, ServeTLS, tls.Listen, SSLServerSocket, HttpsServer, a listener bound to the loopback interface (127.0.0.1, localhost, [::1], getLoopbackAddress(), or in Go an address variable or constant whose every assignment in the file is such a literal, including a flag.String default) or a Unix socket (including srv.Serve(ln) where ln came from net.Listen(\"unix\", ...) or tls.Listen), a net.Listen beside a gRPC server built with grpc.Creds(...), calls written inside string literals, listeners that do not name an administrative interface, test files and comments. Whether the admin handler also requires authentication is not judged here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-419/",
	"languages": ["go", "java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [419],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["unprotected-primary-channel", "cleartext", "admin-interface", "cwe-419"],
}

_admin := `(?i)admin|mgmt|management`

_loopback := `127\.0\.0\.1|\blocalhost\b|\[::1\]|getLoopbackAddress|LOOPBACK|InetAddress\.getByName\(\s*"(?:127\.|localhost|::1)`

_mask(s) := regex.replace(s, `//.*$`, "")

# String literals emptied: a call written inside a message is not a call.
_strip(s) := regex.replace(s, concat("", [`"(?:[^"\\]|\\.)*"|`, "`[^`]*`"]), `""`)

# A call whose arguments run onto the next lines is read with them.
_go_code(lines, i) := c if {
	l := _mask(lines[i])
	count(regex.find_n(`\(`, l, -1)) > count(regex.find_n(`\)`, l, -1))
	c := concat(" ", [_mask(x) | some x in array.slice(lines, i, min([count(lines), i + 4]))])
} else := _mask(lines[i])

# srv.Serve(ln) where ln is a Unix-socket or TLS listener.
_safe_listener(lines, i, code) if {
	m := regex.find_all_string_submatch_n(`\.Serve\s*\(\s*([A-Za-z_]\w*)\s*\)`, code, 1)
	count(m) > 0
	v := m[0][1]
	some j in numbers.range(max([0, i - 60]), i)
	regex.match(concat("", [`\b`, v, `\b[^=]*?:?=\s*(?:net\.Listen\s*\(\s*"unix|tls\.(?:Listen|NewListener)\s*\()`]), lines[j])
}

# The admin name is on the line, or on the declaration it continues.
_jvm_admin(_, _, code) if regex.match(_admin, code)

_jvm_admin(lines, i, _) if {
	i > 0
	prev := _mask(lines[i - 1])
	endswith(trim_space(prev), "=")
	regex.match(_admin, prev)
	not regex.match(_loopback, prev)
}


# http.ListenAndServe(addr, handler) naming an admin interface.
_go_admin_plaintext(_, _, code) if {
	m := regex.find_all_string_submatch_n(`\bhttp\.ListenAndServe\s*\(([^;]*)\)`, code, 1)
	count(m) > 0
	regex.match(_admin, m[0][1])
}

# adminSrv.ListenAndServe() / s.admin.Serve(ln)
_go_admin_plaintext(_, _, code) if {
	m := regex.find_all_string_submatch_n(`([A-Za-z_][\w\.]*)\.(?:ListenAndServe|Serve)\s*\(`, code, 1)
	count(m) > 0
	m[0][1] != "http"
	regex.match(_admin, m[0][1])
}

# srv := &http.Server{Addr: cfg.AdminAddr, ...}; srv.ListenAndServe()
_go_admin_plaintext(lines, i, code) if {
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.])([A-Za-z_]\w*)\.(?:ListenAndServe|Serve)\s*\(`, code, 1)
	count(m) > 0
	v := m[0][1]
	v != "http"
	not regex.match(_admin, v)
	_server_literal_is_admin(lines, i, v)
}

_server_literal_is_admin(lines, i, v) if {
	some j in numbers.range(max([0, i - 60]), i)
	regex.match(concat("", [`\b`, v, `\s*:?=\s*&?http\.Server\s*\{`]), lines[j])
	w := concat("\n", array.slice(lines, j, min([count(lines), j + 10])))
	regex.match(concat("", [`(?m)^[^/]*\b(?:Addr|Handler)\s*:\s*[^,\n]*(?:`, _admin, `)`]), w)
	not regex.match(concat("", [`(?m)^[^/]*\bAddr\s*:\s*[^,\n]*(?:`, _loopback, `)`]), w)
}

# ln, err := net.Listen("tcp", adminAddr) not wrapped in TLS.
_go_admin_plaintext(lines, i, code) if {
	m := regex.find_all_string_submatch_n(`\bnet\.Listen\s*\(\s*"tcp[46]?"\s*,([^)]*)\)`, code, 1)
	count(m) > 0
	regex.match(_admin, m[0][1])
	not _tls_wrapped(lines, i)
}

# A gRPC server built with TLS transport credentials serves this listener.
_tls_wrapped(lines, i) if {
	w := helpers.code_window(lines, i, 15, 15)
	regex.match(`\bgrpc\.Creds\s*\(`, w)
}

_tls_wrapped(lines, i) if {
	v := helpers.assigned_first(lines[i])
	w := helpers.code_window(lines, i, 0, 15)
	regex.match(concat("", [`tls\.(?:NewListener|Server)\s*\(\s*`, v, `\b|\b`, v, `\s*=\s*tls\.`]), w)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(_admin, content)
	regex.match(`ListenAndServe\(|\.Serve\(|net\.Listen\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`ListenAndServe\(|\.Serve\(|net\.Listen\(`, line)
	not helpers.is_comment_line(line)
	regex.match(`ListenAndServe\(|\.Serve\(|net\.Listen\(`, _strip(_mask(line)))
	code := _go_code(lines, i)
	not regex.match(_loopback, code)
	_go_admin_plaintext(lines, i, code)
	not _safe_listener(lines, i, code)
	not _loopback_var(content, code)
	finding := _finding(path, i, line)
}

# The address is a variable or constant whose every assignment in this file is
# a loopback literal: adminAddr := "localhost:6060", const a = "[::1]:7000",
# a := flag.String("admin-addr", "127.0.0.1:9001", ...).
_addr_var(code) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`\bhttp\.ListenAndServe\s*\(\s*\*?([A-Za-z_]\w*)\s*,`, code, 1)
	count(m) > 0
} else := m[0][1] if {
	m := regex.find_all_string_submatch_n(`\bnet\.Listen\s*\(\s*"tcp[46]?"\s*,\s*\*?([A-Za-z_]\w*)\s*\)`, code, 1)
	count(m) > 0
}

_loopback_var(content, code) if {
	v := _addr_var(code)
	all := regex.find_n(concat("", [`(?m)^\s*(?:const\s+|var\s+)?`, v, `(?:\s+string)?\s*:?=[^=].*$`]), content, -1)
	count(all) > 0
	every a in all {
		regex.match(`=\s*(?:flag\.String\(\s*"[^"]*"\s*,\s*)?"(?:127\.|localhost|\[::1\])`, a)
	}
}

# ── Java / Kotlin ────────────────────────────────────────────────────────

_jvm_listen := `\bnew\s+ServerSocket\s*\(|(?:^|[^\w.])ServerSocket\s*\(|\bServerSocketChannel\.open\s*\(\s*\)\s*\.bind\s*\(|\.socket\s*\(\s*\)\s*\.bind\s*\(|(?:^|[^\w.])HttpServer\.create\s*\(`

findings contains finding if {
	some path, content in input.file_contents
	some ext in {".java", ".kt"}
	endswith(path, ext)
	regex.match(_admin, content)
	regex.match(`ServerSocket|HttpServer\.create`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`ServerSocket|HttpServer\.create`, line)
	not helpers.is_comment_line(line)
	code := _mask(line)
	regex.match(_jvm_listen, _strip(code))
	not regex.match(`SSLServerSocket|HttpsServer`, code)
	_jvm_admin(lines, i, code)
	not regex.match(_loopback, code)
	finding := _finding(path, i, line)
}

# ServerSocketChannel ch = ServerSocketChannel.open(); ... ch.bind(addr)
findings contains finding if {
	some path, content in input.file_contents
	some ext in {".java", ".kt"}
	endswith(path, ext)
	regex.match(_admin, content)
	contains(content, "ServerSocketChannel.open")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".bind")
	not helpers.is_comment_line(line)
	code := _mask(line)
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\.bind\s*\(`, code, 1)
	count(m) > 0
	v := m[0][1]
	regex.match(concat("", [`\b`, v, `\s*=\s*(?:Asynchronous)?ServerSocketChannel\.open\s*\(`]), content)
	regex.match(_admin, code)
	not regex.match(_loopback, code)
	finding := _finding(path, i, line)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "An administrative interface is served over a plaintext listener on the network: admin credentials and commands travel unencrypted and can be read or replayed. Serve it with TLS (ListenAndServeTLS, tls.NewListener, SSLServerSocket, HttpsServer) or bind it to the loopback interface or a Unix socket",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
