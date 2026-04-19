# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_295

import rego.v1

metadata := {
	"id": "VNX-295",
	"name": "Improper certificate validation",
	"description": "SSL/TLS certificate verification is disabled, allowing man-in-the-middle attacks. Disabling certificate checks removes the only guarantee that a connection reaches the intended server.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-295/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["tls", "ssl", "certificate", "mitm", "verify"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

_cert_bypass_patterns := {
	# Python
	"verify=False",
	"ssl._create_unverified_context(",
	"ssl.CERT_NONE",
	"check_hostname = False",
	"check_hostname=False",
	# JavaScript / Node.js
	"rejectUnauthorized: false",
	"rejectUnauthorized:false",
	`NODE_TLS_REJECT_UNAUTHORIZED`,
	# Java — TrustManager that blindly accepts
	"X509TrustManager",
	"checkServerTrusted",
	"return null; // accept all",
	# PHP
	"CURLOPT_SSL_VERIFYPEER, false",
	"CURLOPT_SSL_VERIFYPEER, 0",
	"CURLOPT_SSL_VERIFYHOST, 0",
	"CURLOPT_SSL_VERIFYHOST, false",
	# Ruby
	"VERIFY_NONE",
	"verify_mode: OpenSSL::SSL::VERIFY_NONE",
	"verify_mode=OpenSSL::SSL::VERIFY_NONE",
	# Go
	"InsecureSkipVerify: true",
	"InsecureSkipVerify:true",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _cert_bypass_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("TLS/SSL certificate verification disabled (pattern: %s); always validate certificates in production code", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
