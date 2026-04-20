# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1041

import rego.v1

metadata := {
	"id": "VNX-1041",
	"name": "Use of Redundant Code",
	"description": "Duplicate or redundant security checks indicate copy-paste errors that may result in one copy being updated while the other is not, creating inconsistent security enforcement. Redundant checks can also indicate dead code paths where the check is never actually reached.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1041/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1041],
	"capec": ["CAPEC-204"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["redundant-code", "duplicate-check", "code-quality", "cwe-1041"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Duplicate authentication/authorization check identifiers (same check appearing twice in proximity)
_security_check_patterns := {
	"checkPermission(",
	"isAuthenticated(",
	"isAuthorized(",
	"hasPermission(",
	"requireLogin(",
	"verifyToken(",
	"validateToken(",
	"checkAuth(",
	"authorize(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _security_check_patterns
	contains(line, p)
	# Check if the exact same line appears again within 10 lines
	some j
	j > i
	j <= i + 10
	j < count(lines)
	line == lines[j]
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "#")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Duplicate security check '%s' appears identically at nearby lines; this likely indicates a copy-paste error. Consolidate the check into a single function to ensure consistent enforcement", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
