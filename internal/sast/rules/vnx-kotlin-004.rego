package vulnetix.rules.vnx_kotlin_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-KOTLIN-004",
	"name": "Kotlin unencrypted plain socket (cleartext transmission)",
	"description": "A plain TCP socket is opened to, or listens for, a non-loopback peer in a file that never applies TLS, so whatever crosses it can be read and altered on the network. Reported in Kotlin (.kt, .kts): java.net.Socket(host, port, ...) constructors; an unconnected Socket() or SocketChannel.open() later connected with connect(InetSocketAddress(host, port)), by variable or inside apply/also/run/let/use; SocketFactory.getDefault().createSocket(host, port), directly or through a variable the file assigns SocketFactory.getDefault() once; SocketChannel.open(InetSocketAddress(host, port)); ServerSocket(port[, backlog[, address]]), a ServerSocket() or ServerSocketChannel bound with bind(InetSocketAddress(...)); and Ktor raw sockets aSocket(selector).tcp().connect(...) / .bind(...). Not reported: peers and bind addresses on loopback (localhost, 127.x, ::1, InetAddress.getLoopbackAddress(), getLocalHost(), the Android emulator host 10.0.2.2), written in the call, in a variable assigned a few lines above or in a constant the file assigns once; reachability probes that connect and close a socket (use { } or close()) without reading or writing it; any file that layers TLS (SSLSocketFactory, SSLServerSocketFactory, SSLContext, SSLSocket, SSLEngine, startHandshake, Ktor .tls(), Netty SslHandler), which covers STARTTLS upgrades and proxies that wrap the raw socket; unconnected Socket()/Socket(proxy) objects and Socket subclasses; LocalSocket, Bluetooth, WebSocket and UDP DatagramSocket; test code; and the calls in comments or string literals. Whether the data sent is sensitive is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-kotlin-004/",
	"languages": ["kotlin"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [319],
	"capec": ["CAPEC-157"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["network", "tls", "cleartext", "kotlin"],
}

_client_msg := "Plain (unencrypted) socket connects to a remote peer; use SSLSocketFactory (or Ktor .tls()) so data in transit is encrypted"

_server_msg := "Plain (unencrypted) server socket listens on a non-loopback address; use SSLServerSocketFactory (or Ktor .tls()) or bind to loopback behind a TLS proxy"

_is_kotlin(path) if endswith(path, ".kt")

_is_kotlin(path) if endswith(path, ".kts")

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)src/[A-Za-z]*[Tt]est[A-Za-z]*/`, path)

_is_test(path) if regex.match(`(Test|Tests|Spec|IT)\.kts?$`, path)

_is_test(path) if regex.match(`(^|/)([\w.]+[-_])?test(s|ing)?([-_][\w.-]+)?/`, path)

# A file that applies TLS anywhere: the raw socket is upgraded (STARTTLS) or
# tunnelled, or the plain one is a deliberate sibling of the secure one.
_tls_file(content) if regex.match(`SSL(Socket|ServerSocket|Context|Engine)|startHandshake|\.tls\s*\(|SslHandler|SslContext`, content)

# String-literal contents blanked, trailing comment cut.
_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

# Line i and the next two non-comment lines, raw, for wrapped arguments.
_joined(lines, i) := concat(" ", [l | some l in array.slice(lines, i, i + 3); not helpers.is_comment_line(l)])

_loopback(txt) if regex.match(`getLoopbackAddress|getLocalHost|"localhost"|"127\.|"::1"|"0:0:0:0:0:0:0:1"|"10\.0\.2\.2"|LOCALHOST|LOOPBACK`, txt)

# The first argument of a call opened just before `rest`, when the call has a
# second argument. A nested call such as InetAddress.getByName("h") counts as
# one argument.
_first_of_two(rest) := a if {
	m := regex.find_all_string_submatch_n(`^\s*([^,()]*(?:\([^()]*\))?[^,()]*?)\s*,`, rest, 1)
	count(m) > 0
	a := m[0][1]
	trim_space(a) != ""
}

_after(txt, re) := r if {
	m := regex.find_all_string_submatch_n(concat("", [re, `(.*)$`]), txt, 1)
	count(m) > 0
	r := m[0][1]
}

# The argument text of a call whose opening parenthesis ends just before
# `rest`, up to its matching close (two levels of nesting).
_args(rest) := a if {
	m := regex.find_all_string_submatch_n(`^((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`, rest, 1)
	count(m) > 0
	a := m[0][1]
}

_assign_re(id) := concat("", [`\b`, id, `\s*(?::\s*[\w.?]+)?\s*=\s*[^=]`])

# The receiver was assigned `rhs_re` at its nearest assignment above.
_assigned_near(lines, i, recv, rhs_re) if {
	js := [k |
		some k in numbers.range(max([0, i - 20]), i - 1)
		contains(lines[k], recv)
		not helpers.is_comment_line(lines[k])
		regex.match(_assign_re(recv), lines[k])
	]
	count(js) > 0
	regex.match(concat("", [`\b`, recv, `\s*(?::\s*[\w.?]+)?\s*=\s*`, rhs_re]), lines[max(js)])
}

# The receiver of a connect()/bind() call is an object of `kind`: a variable
# assigned one, or `it`/`this`/no receiver inside kind.apply/also/run/let { }.
_holds(lines, i, recv, kind) if {
	not recv in {"", "it", "this"}
	_assigned_near(lines, i, recv, kind)
}

_holds(lines, i, recv, kind) if {
	recv in {"", "it", "this"}
	some k in numbers.range(max([0, i - 3]), i)
	regex.match(concat("", [kind, `\s*\.\s*(apply|run|also|let|use)\s*\{`]), lines[k])
}

# A connectivity probe: the socket is connected and closed (use { } or
# close()) with nothing read or written, so no data crosses it.
_probe(lines, i) if {
	regex.match(`\.use\s*\{|\.close\s*\(\s*\)`, concat("\n", array.slice(lines, max([0, i - 1]), i + 4)))
	w := concat("\n", array.slice(lines, i, i + 4))
	not regex.match(`(?i)stream|channel\b|openRead|openWrite|write|read|send|print|sink|source|return\b|=\s*(?:java\.net\.)?Socket\s*\(`, w)
}

# The address is loopback, written in the call or in a variable the call
# names that was assigned a few lines above.
_loopback_arg(_, _, args) if _loopback(args)

_loopback_arg(lines, i, args) if {
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\b`, args, -1)
	id := m[1]
	some k in numbers.range(max([0, i - 10]), i - 1)
	contains(lines[k], id)
	regex.match(_assign_re(id), lines[k])
	_loopback_line(lines, lines[k])
}

# ... or a constant the file assigns exactly once (a top-level const val
# far above the call).
_loopback_arg(lines, i, args) if {
	some m in regex.find_all_string_submatch_n(`\b([A-Z_][A-Z0-9_]*)\b`, args, -1)
	_loopback(_single_assignment(lines, m[1]))
}

# An assignment line whose value is loopback, directly or through a
# once-assigned constant (InetAddress.getByName(BRIDGE_HOST)).
_loopback_line(_, line) if _loopback(line)

_loopback_line(lines, line) if {
	some m in regex.find_all_string_submatch_n(`\b([A-Z_][A-Z0-9_]*)\b`, regex.replace(line, `^[^=]*=`, ""), -1)
	_loopback(_single_assignment(lines, m[1]))
}

_single_assignment(lines, id) := js[0] if {
	re := _assign_re(id)
	js := [l | some l in lines; contains(l, id); regex.match(re, l)]
	count(js) == 1
}

# ── Clients ──────────────────────────────────────────────────────────────

_socket_ctor := `(?:^|[^\w.])(?:java\.net\.)?Socket\s*\(`

_unconnected := `(?:(?:java\.net\.)?Socket\s*\(\s*\)|(?:java\.nio\.channels\.)?(?:Asynchronous)?SocketChannel\s*\.\s*open\s*\(\s*\))`

# Socket(host, port, ...)
_client(lines, i, code) if {
	regex.match(_socket_ctor, code)
	host := _first_of_two(_after(_joined(lines, i), _socket_ctor))
	not _loopback_arg(lines, i, host)
}

# SocketFactory.getDefault().createSocket(host, port)
_client(lines, i, code) if {
	re := `(?:^|[^\w.])(?:javax\.net\.)?SocketFactory\s*\.\s*getDefault\s*\(\s*\)\s*\.\s*createSocket\s*\(`
	regex.match(re, code)
	host := _first_of_two(_after(_joined(lines, i), re))
	not _loopback_arg(lines, i, host)
}

# factory.createSocket(host, port) on a variable holding SocketFactory.getDefault()
_client(lines, i, code) if {
	contains(code, "createSocket")
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*\.\s*createSocket\s*\(`, code, 1)
	count(m) > 0
	recv := m[0][1]
	recv != "getDefault"
	a := _single_assignment(lines, recv)
	regex.match(`\bSocketFactory\s*\.\s*getDefault\s*\(\s*\)\s*$`, regex.replace(a, `\s*(//.*)?$`, ""))
	host := _first_of_two(_after(_joined(lines, i), `\bcreateSocket\s*\(`))
	not _loopback_arg(lines, i, host)
}

# SocketChannel.open(InetSocketAddress(host, port))
_client(lines, i, code) if {
	re := `(?:^|[^\w.])(?:java\.nio\.channels\.)?SocketChannel\s*\.\s*open\s*\(\s*InetSocketAddress\s*\(`
	regex.match(re, code)
	host := _first_of_two(_after(_joined(lines, i), re))
	not _loopback_arg(lines, i, host)
}

# s.connect(address) on a Socket() / SocketChannel.open() /
# AsynchronousSocketChannel.open(), by variable or in a scope function
_client(lines, i, code) if {
	contains(code, "connect")
	m := regex.find_all_string_submatch_n(`(?:\b([A-Za-z_]\w*)\s*\.\s*)?\bconnect\s*\(`, code, 1)
	count(m) > 0
	_holds(lines, i, m[0][1], _unconnected)
	args := _args(_after(_joined(lines, i), `\bconnect\s*\(`))
	trim_space(args) != ""
	not _loopback_arg(lines, i, args)
}

# Ktor aSocket(selector).tcp().connect(host, port) / connect(InetSocketAddress(...))
_client(lines, i, code) if {
	contains(code, "tcp")
	j := regex.replace(_joined(lines, i), `\s+`, " ")
	re := `\btcp\s*\(\s*\)\s*\.\s*connect\s*\(\s*(?:InetSocketAddress\s*\(\s*)?`
	regex.match(re, j)
	host := _first_of_two(_after(j, re))
	not _loopback_arg(lines, i, host)
}

# ── Servers ──────────────────────────────────────────────────────────────

_server_ctor := `(?:^|[^\w.])(?:java\.net\.)?ServerSocket\s*\(`

_unbound := `(?:(?:java\.net\.)?ServerSocket\s*\(\s*\)|(?:java\.nio\.channels\.)?(?:Asynchronous)?ServerSocketChannel\s*\.\s*open\s*\(\s*\))`

# ServerSocket(port[, backlog[, address]]) with a non-loopback address
_server(lines, i, code) if {
	regex.match(concat("", [_server_ctor, `\s*[^\s)]`]), code)
	args := _args(_after(_joined(lines, i), _server_ctor))
	not _loopback_arg(lines, i, args)
}

# server.bind(address) on a ServerSocket() / (Asynchronous)ServerSocketChannel.open(),
# by variable or in a scope function
_server(lines, i, code) if {
	contains(code, "bind")
	m := regex.find_all_string_submatch_n(`(?:\b([A-Za-z_]\w*)\s*\.\s*)?\bbind\s*\(`, code, 1)
	count(m) > 0
	_holds(lines, i, m[0][1], _unbound)
	args := _args(_after(_joined(lines, i), `\bbind\s*\(`))
	not _loopback_arg(lines, i, args)
}

# (Asynchronous)ServerSocketChannel.open().bind(...)
_server(lines, i, code) if {
	re := `(?:^|[^\w.])(?:java\.nio\.channels\.)?(?:Asynchronous)?ServerSocketChannel\s*\.\s*open\s*\(\s*\)\s*\.\s*bind\s*\(`
	regex.match(re, code)
	args := _args(_after(_joined(lines, i), re))
	not _loopback_arg(lines, i, args)
}

# Ktor aSocket(selector).tcp().bind(...)
_server(lines, i, code) if {
	contains(code, "tcp")
	j := regex.replace(_joined(lines, i), `\s+`, " ")
	re := `\btcp\s*\(\s*\)\s*\.\s*bind\s*\(`
	regex.match(re, j)
	args := _args(_after(j, re))
	not _loopback_arg(lines, i, args)
}

_messages := {"client": _client_msg, "server": _server_msg}

_shape("client", lines, i, code) if {
	_client(lines, i, code)
	not _probe(lines, i)
}

_shape("server", lines, i, code) if _server(lines, i, code)

findings contains finding if {
	some path, content in input.file_contents
	_is_kotlin(path)
	contains(content, "Socket")
	not _is_test(path)
	not _tls_file(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`ocket|\.connect|tcp|\.bind`, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	some key, msg in _messages
	_shape(key, lines, i, code)
	finding := _finding(path, i, line, msg)
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
