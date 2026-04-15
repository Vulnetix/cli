package vulnetix.rules.vnx_node_009

import rego.v1

metadata := {
	"id": "VNX-NODE-009",
	"name": "Node.js server-side request forgery",
	"description": "Using user input (req.query, req.body) to construct HTTP requests with fetch, axios, or http.get enables SSRF, allowing attackers to access internal services or cloud metadata.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-009/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [918],
	"capec": ["CAPEC-664"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ssrf", "web", "cloud"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_ssrf_indicators := {
	"fetch(req.query",
	"fetch(req.body",
	"fetch(req.params",
	"axios.get(req.query",
	"axios.get(req.body",
	"axios.post(req.query",
	"axios(req.query",
	"http.get(req.query",
	"got(req.query",
	"request(req.query",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _ssrf_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input used to construct server-side HTTP request; validate against an allowlist of permitted hosts",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
