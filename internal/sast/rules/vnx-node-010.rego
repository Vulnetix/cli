package vulnetix.rules.vnx_node_010

import rego.v1

metadata := {
	"id": "VNX-NODE-010",
	"name": "Node.js path traversal",
	"description": "Using user input (req.params, req.query) to construct file paths with fs.readFile, createReadStream, or path.join enables path traversal attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-010/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": ["CAPEC-126"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["path-traversal", "file-access", "lfi"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_path_indicators := {
	"fs.readFile(req.params",
	"fs.readFile(req.query",
	"fs.readFileSync(req.params",
	"fs.readFileSync(req.query",
	"fs.createReadStream(req.params",
	"fs.createReadStream(req.query",
	"path.join(req.params",
	"path.join(req.query",
	"path.resolve(req.params",
	"path.resolve(req.query",
	"res.sendFile(req.params",
	"res.sendFile(req.query",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _path_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input used in file path; validate and sanitize the path to prevent directory traversal",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
