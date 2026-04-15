package vulnetix.rules.vnx_rust_002

import rego.v1

metadata := {
	"id": "VNX-RUST-002",
	"name": "Rust unwrap may panic",
	"description": "Using .unwrap() or .expect() on Result/Option types can cause panics in production. Use proper error handling with match, if let, or the ? operator instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-002/",
	"languages": ["rust"],
	"severity": "low",
	"level": "warning",
	"kind": "open",
	"cwe": [248],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["error-handling", "panic", "robustness"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rs")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.(unwrap|expect)\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": ".unwrap()/.expect() can panic at runtime; use proper error handling (match, if let, or ? operator)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
