# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_921

import rego.v1

metadata := {
	"id": "VNX-921",
	"name": "Storage of sensitive data without access control",
	"description": "Storing sensitive data (passwords, tokens, PII) in world-readable locations such as /tmp, browser localStorage, or world-readable files exposes it to other processes or users on the same system.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-921/",
	"languages": ["python", "java", "php", "ruby", "node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [921],
	"capec": ["CAPEC-37"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["sensitive-data", "access-control", "storage"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_patterns := {
	"localStorage.setItem('password",
	"localStorage.setItem(\"password",
	"localStorage.setItem('token",
	"localStorage.setItem(\"token",
	"localStorage.setItem('secret",
	"localStorage.setItem(\"secret",
	"sessionStorage.setItem('password",
	"sessionStorage.setItem(\"password",
	"open('/tmp/",
	"open(\"/tmp/",
	"fopen('/tmp/",
	"fopen(\"/tmp/",
	"File.write('/tmp/",
	"File.write(\"/tmp/",
	"MODE_WORLD_READABLE",
	"getSharedPreferences(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _patterns
	contains(line, p)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Sensitive data storage risk: '%v' may store sensitive information in an insecure or world-readable location", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
