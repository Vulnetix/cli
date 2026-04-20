# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1043

import rego.v1

metadata := {
	"id": "VNX-1043",
	"name": "Data Element Aggregating an Excessively Large Number of Non-Primitive Elements",
	"description": "A data structure or object aggregates an excessive number of complex (non-primitive) elements without bounds. This can lead to unbounded memory growth, denial-of-service via resource exhaustion, or difficulty auditing all fields for sensitive data exposure.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1043/",
	"languages": ["java", "python", "node", "go"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1043],
	"capec": ["CAPEC-130"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["data-aggregation", "excessive-fields", "code-quality", "cwe-1043"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

# Python dataclass or dict with many nested object fields
_python_aggregate_patterns := {
	"class Meta:",
	"dataclass",
	"TypedDict",
	"NamedTuple",
}

# Java class with many List/Map fields (indication of over-aggregation)
_java_collection_field := {
	"List<List<",
	"Map<String, Map<",
	"Map<String, List<",
	"List<Map<",
	"Map<Map<",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _java_collection_field
	contains(line, p)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Nested collection type '%s' creates a data structure with unbounded complexity; consider flattening the data model or adding size bounds to prevent resource exhaustion", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
