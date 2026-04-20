# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_322

import rego.v1

metadata := {
	"id": "VNX-322",
	"name": "Key exchange without entity authentication",
	"description": "The code configures anonymous Diffie-Hellman (ADH) cipher suites or disables peer authentication during a key exchange. Without entity authentication the connection is vulnerable to man-in-the-middle attacks even when the channel is encrypted.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-322/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [322],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["tls", "dh", "anonymous", "key-exchange", "mitm"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

_anon_dh_patterns := {
	# OpenSSL cipher strings including anonymous DH
	"ADH-",
	"aNULL",
	"eNULL",
	"NULL-SHA",
	"EXP-",
	# Java JSSE
	"TLS_DH_anon",
	"SSL_DH_anon",
	# Python SSL
	"PROTOCOL_SSLv2",
	"PROTOCOL_SSLv3",
	# General: disabling auth
	"auth: none",
	`"auth": "none"`,
	"setWantClientAuth(false",
	"setNeedClientAuth(false",
	# Go TLS — anonymous DH via ClientAuth
	"tls.NoClientCert",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _anon_dh_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Anonymous or unauthenticated key exchange detected (pattern: %s); use cipher suites that include mutual authentication and avoid anonymous DH", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
