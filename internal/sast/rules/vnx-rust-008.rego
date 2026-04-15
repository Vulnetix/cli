package vulnetix.rules.vnx_rust_008

import rego.v1

metadata := {
	"id": "VNX-RUST-008",
	"name": "Rust path traversal in Actix-web or Axum file-serving handler",
	"description": "A web handler constructs a filesystem path by joining a base directory with a user-supplied path parameter without validating that the resolved path stays within the base directory. An attacker can supply '../' sequences to read arbitrary files on the server.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-008/",
	"languages": ["rust"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [22],
	"capec": ["CAPEC-126"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["path-traversal", "rust", "actix", "axum"],
}

_skip(path) if endswith(path, ".lock")

_request_path_params := {
	"Path(",
	"path_param",
	"params.get(",
	"info.0",
	"info.into_inner",
	"extract::Path",
	"axum::extract::Path",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rs")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not regex.match(`^\s*//`, line)
	# Path joining in a handler context
	regex.match(`Path(Buf)?::new|\.join\s*\(|path::Path::new`, line)
	# Check for request path params in surrounding context
	window_start := max([0, i - 15])
	window_end := min([count(lines) - 1, i + 5])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	some src in _request_path_params
	contains(window, src)
	# Not already validated with canonicalize or starts_with check
	not contains(window, "canonicalize")
	not contains(window, "starts_with")
	finding := {
		"rule_id": metadata.id,
		"message": "Web handler joins a base directory with a user-supplied path component without validation; call path.canonicalize() and verify the result starts_with the base directory to prevent path traversal",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
