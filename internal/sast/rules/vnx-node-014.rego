package vulnetix.rules.vnx_node_014

import rego.v1

metadata := {
	"id": "VNX-NODE-014",
	"name": "NoSQL injection in MongoDB",
	"description": "Passing unsanitized user input (req.body, req.query) directly to MongoDB query methods enables NoSQL injection, allowing attackers to bypass authentication or extract data.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-014/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [943],
	"capec": ["CAPEC-676"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["nosql", "mongodb", "injection", "database"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_nosql_indicators := {
	".find(req.body",
	".find(req.query",
	".findOne(req.body",
	".findOne(req.query",
	".findOneAndUpdate(req.body",
	".findOneAndUpdate(req.query",
	".updateOne(req.body",
	".updateOne(req.query",
	".deleteOne(req.body",
	".deleteOne(req.query",
	".deleteMany(req.body",
	".deleteMany(req.query",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _nosql_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input passed directly to MongoDB query; validate input types and use query operators explicitly",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
