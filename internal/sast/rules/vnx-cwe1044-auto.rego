# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1044

import rego.v1

metadata := {
	"id": "VNX-1044",
	"name": "Architecture with Number of Horizontal Layers Outside of Expected Range",
	"description": "The software architecture has too many or too few horizontal layers (e.g. presentation, business logic, data access). An excessive number of layers increases attack surface and complexity, making security reviews harder. Too few layers lead to mixing concerns such as business logic and data access in a single location, making it easier to introduce injection vulnerabilities.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1044/",
	"languages": ["java", "python", "node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1044],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["architecture", "layering", "code-quality", "cwe-1044"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Detect direct database calls in controller/view files (missing separation of layers)
_controller_db_patterns := {
	"SELECT ",
	"INSERT INTO",
	"UPDATE ",
	"DELETE FROM",
}

_controller_indicators := {
	"Controller",
	"controller",
	"View",
	"view",
	"Handler",
	"handler",
	"Route",
	"route",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	# Check filename suggests controller/view layer
	some ind in _controller_indicators
	contains(path, ind)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _controller_db_patterns
	contains(line, p)
	_has_string_concat(line)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "#")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Raw SQL pattern '%s' in what appears to be a controller/view layer file; direct database queries in controllers violate layer separation and increase injection risk. Use a repository or data-access layer", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_has_string_concat(line) if contains(line, " + ")
_has_string_concat(line) if contains(line, "f\"")
_has_string_concat(line) if contains(line, "f'")
_has_string_concat(line) if contains(line, "fmt.Sprintf")
