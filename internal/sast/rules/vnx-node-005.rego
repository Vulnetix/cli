package vulnetix.rules.vnx_node_005

import rego.v1

metadata := {
	"id": "VNX-NODE-005",
	"name": "innerHTML or dangerouslySetInnerHTML usage",
	"description": "Setting innerHTML or using dangerouslySetInnerHTML with user-controlled data enables cross-site scripting (XSS).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-005/",
	"languages": ["node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["xss", "web", "react"],
}

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".jsx")
_is_js(path) if endswith(path, ".tsx")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "dangerouslySetInnerHTML")
	finding := {
		"rule_id": metadata.id,
		"message": "dangerouslySetInnerHTML can lead to XSS; sanitize content with DOMPurify or similar",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.innerHTML\s*=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "innerHTML assignment can lead to XSS; use textContent or sanitize input",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
