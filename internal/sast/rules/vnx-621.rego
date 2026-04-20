# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_621

import rego.v1

metadata := {
	"id": "VNX-621",
	"name": "Variable Extraction Error (PHP extract Injection)",
	"description": "PHP's extract() function imports array keys as variable names into the current symbol table. Calling extract() on superglobals ($_GET, $_POST, $_REQUEST) allows attackers to overwrite arbitrary variables, including those used for authentication checks, file paths, and SQL queries.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-621/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [621],
	"capec": ["CAPEC-77"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["php", "extract", "variable-injection", "cwe-621"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_patterns := {
	"extract($_GET",
	"extract($_POST",
	"extract($_REQUEST",
	"extract($_COOKIE",
	"extract($_FILES",
	"extract($_SERVER",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _patterns
	contains(line, p)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "#")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PHP extract() called on user-controlled superglobal '%s'; this allows attackers to overwrite arbitrary variables. Never pass superglobals to extract(); use explicit variable assignments instead", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
