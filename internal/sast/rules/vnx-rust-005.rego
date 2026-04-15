package vulnetix.rules.vnx_rust_005

import rego.v1

metadata := {
	"id": "VNX-RUST-005",
	"name": "panic!() or unwrap()/expect() in function that returns Result",
	"description": "Calling panic!(), unwrap(), or expect() inside a function whose return type is Result propagates an unrecoverable panic instead of returning an Err. This prevents callers from handling the error gracefully and can crash the entire process.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-005/",
	"languages": ["rust"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [755],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["rust", "panic", "error-handling", "result"],
}

_skip(path) if endswith(path, ".lock")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rs")
	content := input.file_contents[path]
	lines := split(content, "\n")
	some i, line in lines
	# Inside a fn that declares -> Result
	# We detect the opening of a Result-returning fn via context window
	regex.match(`->\s*(Result|std::result::Result)\s*[<(]`, content)
	# Line itself calls panic!, unwrap, or expect
	regex.match(`\b(panic!|\.unwrap\(\)|\.expect\()`, line)
	not regex.match(`#\[cfg\(test\)\]`, content)
	not regex.match(`^\s*//`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "panic!()/unwrap()/expect() inside a Result-returning function aborts the process; use the ? operator or return Err(...) to propagate errors to the caller",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
