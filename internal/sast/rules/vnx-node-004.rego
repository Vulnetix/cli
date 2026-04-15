package vulnetix.rules.vnx_node_004

import rego.v1

metadata := {
	"id": "VNX-NODE-004",
	"name": "Express app without helmet",
	"description": "Express applications without helmet middleware are missing important HTTP security headers (CSP, HSTS, X-Frame-Options, etc.).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-004/",
	"languages": ["node"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [693],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["express", "config", "security-headers"],
}

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	content := input.file_contents[path]
	contains(content, "express()")
	not contains(content, "helmet")
	finding := {
		"rule_id": metadata.id,
		"message": "Express app created without helmet middleware; add helmet() for security headers",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
	}
}
