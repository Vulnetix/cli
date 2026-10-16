# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_348

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-348",
	"name": "Use of Less Trusted Source",
	"description": "The client address is taken from a request header the client writes itself, in preference to the socket address the server actually saw. Reported: a read of X-Forwarded-For, X-Real-IP, X-Client-IP, True-Client-IP, CF-Connecting-IP or X-Cluster-Client-IP (as a quoted header name, or the CGI/WSGI/PHP form HTTP_X_FORWARDED_FOR, HTTP_CLIENT_IP and friends), or Flask/werkzeug request.access_route (the X-Forwarded-For list), that falls back, on the same line or within the next ten lines, to the connection's own address (REMOTE_ADDR, remote_addr, remoteAddress, getRemoteAddr()/remoteAddr, RemoteAddr, RemoteIpAddress, UserHostAddress, Rails remote_ip, req.ip / `?? ip`, Laravel $request->ip(), Symfony getClientIp()), in Python, JavaScript/TypeScript, Go, Java, Kotlin, PHP, Ruby and C#. That fallback is the mark of code that does not know whether a proxy is in front of it, so any client can choose the address an allowlist, rate limit or audit log records. Not reported: the rightmost hop (split(...)[-1], rsplit, .pop()), a header read guarded by a trusted-proxy check in the three lines above, a proxy setting or appending the header for the next hop, a header that is only logged or forwarded, a header name used as a dict/object/hash key (outbound or test-client headers), a constant that only names the header (const HeaderXFF = \"X-Forwarded-For\"), test files, reads with no socket-address fallback, comments and prose. A rate limiter key function that reads the header (keyGenerator, key_func, keyResolver on the read line or up to two lines above it) in Python, Java or JavaScript/TypeScript is reported by VNX-290, which names the brute-force consequence.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-348/",
	"languages": ["csharp", "go", "java", "kotlin", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [348],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["ip-source", "cwe-348"],
}

_exts := {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".java", ".kt", ".php", ".rb", ".cs"}

_gate_words := {"access_route", "orwarded-", "FORWARDED_FOR", "eal-IP", "eal-Ip", "real-ip", "REAL_IP", "lient-IP", "lient-Ip", "client-ip", "CLIENT_IP", "onnecting-IP", "onnecting-Ip", "connecting-ip", "CONNECTING_IP"}

_gated(content) if {
	some w in _gate_words
	contains(content, w)
}

# A quoted client-supplied address header.
_header_re := `(?i)["'](?:HTTP_)?(?:X[-_]FORWARDED[-_]FOR|X[-_]REAL[-_]IP|X[-_]CLIENT[-_]IP|CLIENT[-_]IP|TRUE[-_]CLIENT[-_]IP|CF[-_]CONNECTING[-_]IP|X[-_]CLUSTER[-_]CLIENT[-_]IP)["']`

# The header is being written (a proxy adding the next hop), not read.
_write_re := `(?i)(?:set|add|append)Header\s*\(\s*["']|\.(?:Set|Add|Del)\(\s*["']|\[\s*["'][^"']+["']\s*\]\s*=[^=]|proxy_set_header`

# The socket address the server actually observed.
_socket_re := `REMOTE_ADDR|\bremote_addr\b|\bremoteAddress\b|getRemoteAddr\s*\(|\.RemoteAddr\b|\.remoteAddr\b|\bremote_ip\b|RemoteIpAddress|UserHostAddress|\b(?:req|request)\.ip\b|(?:\?\?|\|\||\bor\b)\s*ip\b|\$request->ip\(\)|->getClientIp\(\)`

# The rightmost hop was taken: that entry was written by the nearest proxy.
_rightmost_re := `\[\s*-1\s*\]|\brsplit\s*\(|\.pop\(\)|\.at\(\s*-1\s*\)|lastIndexOf\s*\(|\.Last\(\)|LastIndex\s*\(`

# A header read: the quoted name not used as a dict/object/hash key (that
# builds outbound or test-client headers), or werkzeug's access_route, which
# is the X-Forwarded-For list.
_reads_header(line) if {
	regex.match(_header_re, line)
	not regex.match(concat("", [_header_re, `\s*(?::[^:]|:$|=>)`]), line)
}

_reads_header(line) if regex.match(`\brequest\.access_route\b`, line)

# A constant naming the header (const HeaderXFF = "X-Forwarded-For") reads
# nothing.
_names_header(line) if regex.match(concat("", [`(?:=|:=)\s*`, _header_re, `\s*;?\s*$`]), line)

# A rate limiter's key function reading the header (keyGenerator ({ headers,
# ip }) { return headers['X-Forwarded-For'] ?? ip }) in Python, Java or
# JavaScript/TypeScript is reported by VNX-290, which names the brute-force
# consequence; this rule leaves that line to it. The key function sits on
# the header line or up to two lines above it, as VNX-290 looks for it.
_vnx290_exts := {".py", ".java", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}

_vnx290_header_re := `(?i)["'](x-forwarded-for|x-real-ip|x-client-ip|x-originating-ip|true-client-ip|x-cluster-client-ip|cf-connecting-ip|x-remote-(addr|ip)|http_x_forwarded_for|http_x_real_ip|http_x_client_ip|http_x_originating_ip|http_true_client_ip|http_cf_connecting_ip|http_x_cluster_client_ip)["']`

_rate_key_re := `\b(keyGenerator|key_?[Ff]unc|keyResolver|key_?[Gg]enerator|getKey|identifier)\b`

_rate_limit_key(path, lines, i) if {
	some e in _vnx290_exts
	endswith(path, e)
	regex.match(_vnx290_header_re, lines[i])
	some k in numbers.range(max([0, i - 2]), i)
	regex.match(_rate_key_re, lines[k])
	not helpers.is_comment_line(lines[k])
}

_trust_re :=`(?i)trust(?:ed)?[_ ]?prox|trusted_?(?:hosts|ips|networks)|\bin\s+TRUSTED|isTrusted`

findings contains finding if {
	some path, content in input.file_contents
	some e in _exts
	endswith(path, e)
	not helpers.is_test_path(path)
	_gated(content)
	lines := split(content, "\n")
	some i, line in lines
	_reads_header(line)
	not helpers.is_comment_line(line)
	not regex.match(_write_re, line)
	not _names_header(line)
	not regex.match(`(?i)\b(?:log(?:ger)?|console|logging)\.\w+\s*\(`, line)
	window := helpers.code_window(lines, i, 0, 10)
	regex.match(_socket_re, window)
	not regex.match(_rightmost_re, window)
	not regex.match(`(?i)(?:set|add)Header\s*\(\s*["']X-Forwarded-For`, window)
	not regex.match(_trust_re, helpers.code_window(lines, i, 3, 0))
	not _rate_limit_key(path, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The client address is read from a header the client controls, falling back to the socket address; any client can spoof the address an allowlist, rate limit or audit log sees. Use the socket address, or the rightmost hop added by a proxy you trust",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
