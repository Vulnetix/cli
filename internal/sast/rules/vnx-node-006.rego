package vulnetix.rules.vnx_node_006

import rego.v1

metadata := {
	"id": "VNX-NODE-006",
	"name": "Prototype pollution via merge",
	"description": "Deep-merge operations (lodash _.merge, _.defaultsDeep, _.set) with user-controlled input can inject properties into Object.prototype, leading to denial of service or remote code execution.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-NODE-006",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [915],
	"capec": ["CAPEC-180"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["prototype-pollution", "lodash", "injection"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_merge_indicators := {
	"_.merge(",
	"_.defaultsDeep(",
	"_.set(",
	"lodash.merge(",
	"merge(target, req.body",
	"merge(target, req.query",
	"Object.assign({}, req.body",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _merge_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Potential prototype pollution via %s with user input; validate or sanitize input keys", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
