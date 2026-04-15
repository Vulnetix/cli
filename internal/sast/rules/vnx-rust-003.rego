package vulnetix.rules.vnx_rust_003

import rego.v1

metadata := {
	"id": "VNX-RUST-003",
	"name": "Rust unsafe block",
	"description": "An unsafe block or unsafe function is used. Unsafe Rust bypasses memory safety guarantees and can introduce vulnerabilities such as buffer overflows, use-after-free, and undefined behaviour. Unsafe code requires careful manual review.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-003/",
	"languages": ["rust"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [119],
	"capec": ["CAPEC-100"],
	"attack_technique": ["T1211"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["rust", "unsafe", "memory-safety"],
}

_is_rust(path) if endswith(path, ".rs")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_rust(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s*unsafe\s*\{`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unsafe block found; review this code carefully for memory safety issues — document why unsafe is necessary and verify all invariants are upheld",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_rust(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s*pub unsafe fn|^\s*unsafe fn`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unsafe function declaration found; document the safety contract callers must uphold and consider whether a safe wrapper is feasible",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
