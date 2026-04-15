package vulnetix.rules.vnx_kotlin_004

import rego.v1

metadata := {
	"id": "VNX-KOTLIN-004",
	"name": "Kotlin unencrypted plain socket (cleartext transmission)",
	"description": "A plain java.net.Socket or java.net.ServerSocket is used for network communication without TLS/SSL. Data transmitted over unencrypted sockets can be intercepted and modified by network attackers. Use SSLSocketFactory or SSLServerSocketFactory to establish encrypted connections.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-kotlin-004/",
	"languages": ["kotlin"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [319],
	"capec": ["CAPEC-157"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["network", "tls", "cleartext", "kotlin"],
}

_is_kotlin(path) if endswith(path, ".kt")

_is_kotlin(path) if endswith(path, ".kts")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_kotlin(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`=\s*Socket\s*\(`, line)
	not contains(line, "SSL")
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Plain (unencrypted) Socket used for network I/O; replace with SSLSocketFactory.getDefault().createSocket() to encrypt data in transit",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_kotlin(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`=\s*ServerSocket\s*\(`, line)
	not contains(line, "SSL")
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Plain (unencrypted) ServerSocket used; replace with SSLServerSocketFactory for encrypted server-side socket connections",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
