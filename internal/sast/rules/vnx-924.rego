# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_924

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-924",
	"name": "Plain TCP socket to a remote peer: no message integrity in transit",
	"description": "Java code opens a raw TCP connection or listener with no TLS, so anyone on the path can alter (or read) the bytes undetected (CWE-924). Reported: new Socket(host, port) / new java.net.Socket(...) with a destination, new ServerSocket(port...), connect(new InetSocketAddress(...)) or bind(new InetSocketAddress(...)) on a socket or channel created in the file with new Socket(), new ServerSocket(), SocketChannel.open(), ServerSocketChannel.open() or the Asynchronous variants, ServerSocketChannel.open().bind(new InetSocketAddress(...)) chained, SocketChannel.open(new InetSocketAddress(...)), and createSocket/createServerSocket on the non-TLS SocketFactory.getDefault()/ServerSocketFactory.getDefault(); arguments on the next line of an open call are read. Not reported: SSLSocketFactory/SSLServerSocketFactory sockets, a plain socket the same file upgrades with createSocket(plain, host, port, true) (STARTTLS), loopback peers and bindings (\"localhost\", \"127.0.0.1\", \"::1\", InetAddress.getLoopbackAddress()), new Socket(proxy), Unix-domain channels, UDP DatagramSocket, Kotlin, the Socket type in declarations, test files, comments and strings. Whether the protocol on top adds its own MAC or signature is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-924/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [924],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["msg-integrity", "cleartext-socket", "cwe-924"],
}

_loopback := `(?i)"localhost"|"127\.0\.0\.1"|"::1"|getLoopbackAddress\(|getByName\(\s*"localhost"|InetAddress\.getByName\(\s*null\s*\)`

_ctor := `\bnew\s+(?:java\.net\.)?(?:Server)?Socket\s*\(`

_factory := `(?:^|[^\w\.])(?:SocketFactory\.getDefault\(\)\.createSocket|ServerSocketFactory\.getDefault\(\)\.createServerSocket)\s*\(`

_channel := `\bSocketChannel\.open\s*\(\s*new\s+InetSocketAddress\s*\(`

# The call's arguments: the rest of the line, plus the next line when the
# call is left open.
_args(lines, i, line, re) := a if {
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	rest := substring(line, indexof(line, m[0][0]) + count(m[0][0]), -1)
	a := _more(lines, i, rest)
}

_more(lines, i, rest) := rest if trim_space(rest) != ""

_more(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

_upgraded(content, line) if {
	v := helpers.assigned_first(line)
	regex.match(concat("", [`createSocket\(\s*`, v, `\s*,`]), content)
}

_plain(lines, i, line, _) if {
	a := _args(lines, i, line, _ctor)
	not regex.match(`^\s*\)`, a)
	not regex.match(`^\s*(?:\w+\.)?(?:proxy|Proxy\.NO_PROXY)\s*\)`, a)
	not regex.match(_loopback, a)
}

_plain(lines, i, line, _) if {
	a := _args(lines, i, line, _factory)
	not regex.match(`^\s*\)`, a)
	not regex.match(_loopback, a)
}

_plain(lines, i, line, _) if {
	a := _args(lines, i, line, _channel)
	not regex.match(_loopback, a)
}

_plain(lines, i, line, unconnected) if {
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\.(?:connect|bind)\s*\(\s*new\s+InetSocketAddress\s*\(([^;]*)`, line, 1)
	count(m) > 0
	m[0][1] in unconnected
	not regex.match(_loopback, m[0][2])
}

# ServerSocketChannel.open().bind(new InetSocketAddress(port))
_plain(lines, i, line, _) if {
	m := regex.find_all_string_submatch_n(`\b(?:Asynchronous)?ServerSocketChannel\.open\s*\(\s*\)\s*\.bind\s*\(\s*new\s+InetSocketAddress\s*\(([^;]*)`, line, 1)
	count(m) > 0
	not regex.match(_loopback, m[0][1])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "Socket")
	regex.match(`\bnew\s+(?:java\.net\.)?(?:Server)?Socket\s*\(|SocketFactory\.getDefault\(\)|SocketChannel\.open\s*\(`, content)
	unconnected := {m[1] | some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*(?:new\s+(?:java\.net\.)?(?:Server)?Socket\s*\(\s*\)|(?:Server|Asynchronous|AsynchronousServer)?SocketChannel\.open\s*\(\s*\))`, content, -1)}
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Socket")
	not helpers.is_comment_line(line)
	code := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `"s"`)
	regex.match(`\bnew\s+(?:java\.net\.)?(?:Server)?Socket\s*\(|SocketFactory\.getDefault\(\)|SocketChannel\.open|\.(?:connect|bind)\s*\(`, code)
	_plain(lines, i, line, unconnected)
	not _upgraded(content, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Plain TCP socket to or from a remote peer: the bytes have no integrity protection and can be altered in transit. Use SSLSocketFactory/SSLServerSocketFactory (TLS) or authenticate each message",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
