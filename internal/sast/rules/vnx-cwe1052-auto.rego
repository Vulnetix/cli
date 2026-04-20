# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1052

import rego.v1

metadata := {
	"id": "VNX-1052",
	"name": "Excessive Use of Hard-coded Literals in Initialization",
	"description": "The code uses many magic numbers or string literals in initialization code rather than named constants. Magic numbers obscure intent, make security configurations hard to review (e.g. is 86400 a session timeout or a rate limit?), and are frequently misconfigured when copy-pasted.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1052/",
	"languages": ["go", "java", "python", "node", "php"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1052],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["magic-numbers", "hard-coded-literals", "code-quality", "configuration", "cwe-1052"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Security-relevant magic numbers in initialization contexts
_security_magic_numbers := {
	"= 86400",
	"= 3600",
	"= 31536000",
	"= 2592000",
	"= 604800",
	"= 900",
	"= 1800",
	"= 7776000",
}

# Port numbers hardcoded
_hardcoded_ports := {
	"= 8080",
	"= 3306",
	"= 5432",
	"= 6379",
	"= 27017",
	"= 1433",
	"= 9200",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _security_magic_numbers
	contains(line, p)
	not _is_constant_def(line)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "#")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Hard-coded time literal '%s' used directly; define a named constant (e.g. SESSION_TIMEOUT_SECONDS = 3600) so the value's intent is clear during security reviews", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _hardcoded_ports
	contains(line, p)
	not _is_constant_def(line)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "#")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Hard-coded port number '%s'; define a named constant or load from configuration so the service endpoint can be changed without code modification", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_is_constant_def(line) if {
	upper(trim_space(line)) == trim_space(line)
	contains(line, " = ")
}

_is_constant_def(line) if contains(line, "const ")
_is_constant_def(line) if contains(line, "CONST ")
_is_constant_def(line) if contains(line, "final ")
_is_constant_def(line) if contains(line, "FINAL ")
