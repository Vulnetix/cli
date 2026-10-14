package vulnetix.rules.vnx_sec_017

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-SEC-017",
	"name": "Plaintext protocol URL",
	"description": "Reports a connection URL written into code or configuration with a cleartext scheme (redis://, amqp://, ftp://, telnet://, ldap://) that points at a remote host: a host name with a dot (a domain) or an IP address other than loopback, or any non-loopback host when the URL carries a user:password pair. Such a connection sends its credentials and data unencrypted; the TLS variants are rediss://, amqps://, ftps:// or sftp://, ssh:// and ldaps://. Not reported: the TLS schemes, loopback hosts (localhost, 127.x, ::1, 0.0.0.0), a single-label container or service name with no credentials (redis://redis:6379 on a compose network), placeholder hosts (host, hostname, server, example.com/.org/.net, <host>, ${HOST}), a bare scheme string used in a prefix check, comment lines, Markdown and text files, lock and minified files, and test paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-017/",
	"languages": [],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [319],
	"capec": ["CAPEC-157"],
	"attack_technique": ["T1040"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cleartext", "encryption", "network"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")
_skip(path) if endswith(path, ".txt")
_skip(path) if endswith(path, ".rst")
_skip(path) if helpers.is_test_path(path)
_skip(path) if regex.match(`(^|/)[A-Za-z]*Test/`, path)

# A scheme that is not the tail of a longer word (sftp://, tftp://), then
# optional user[:password]@, then the host.
_url_re := `(?i)(?:^|[^A-Za-z0-9+.-])(redis|amqp|ftp|telnet|ldap)://(?:([^\s/@:"'<>]*)(:[^\s/@"'<>]*)?@)?(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9_.-]+)`

_loopback(host) if regex.match(`(?i)^(localhost|localhost\.localdomain|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1?\]|::1)$`, host)

_placeholder(host) if regex.match(`(?i)^(host|hostname|server|servername|myhost|your[-_]?\w*|some[-_]?\w*|xxx+|ip|addr|domain|\w+_host)$`, host)

_placeholder(host) if regex.match(`(?i)(^|\.)example\.(com|org|net)$|\.example$|\.invalid$|\.test$`, host)

# A dotted name or an address: the connection leaves the host or the pod.
_remote(host, _) if contains(host, ".")

_remote(host, _) if startswith(host, "[")

# A single-label host still counts when a password travels in the clear.
_remote(_, pw) if pw != ""

_hit(line) if {
	some m in regex.find_all_string_submatch_n(_url_re, line, -1)
	host := m[4]
	not _loopback(host)
	not _placeholder(host)
	not regex.match(`^[.\-_]|[.\-_]$`, host)
	regex.match(`[A-Za-z0-9]`, host)
	_remote(host, m[3])
}

findings contains finding if {
	some path, content in input.file_contents
	not _skip(path)
	contains(content, "://")
	_scheme(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "://")
	regex.match(`(?i)(?:redis|amqp|ftp|telnet|ldap)://`, line)
	not helpers.is_comment_line(line)
	_hit(line)
	finding := {
		"rule_id": metadata.id,
		"message": "Cleartext protocol URL to a remote host; use the TLS variant (rediss://, amqps://, ftps:// or sftp://, ssh://, ldaps://) so credentials and data are encrypted in transit",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_scheme(content) if {
	some s in ["redis://", "amqp://", "ftp://", "telnet://", "ldap://", "REDIS://", "AMQP://", "FTP://", "TELNET://", "LDAP://"]
	contains(content, s)
}
