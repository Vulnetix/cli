package vulnetix.rules.vnx_go_019

import rego.v1

metadata := {
	"id": "VNX-GO-019",
	"name": "Go server binding to all interfaces (0.0.0.0) without explicit authentication",
	"description": "A TCP listener is bound to 0.0.0.0 or an empty address which exposes the service on all network interfaces including public ones. Services that handle sensitive data or administrative operations should be bound to localhost or a specific private interface.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-019/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [200],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1046"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["network", "binding", "go"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_go(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(net\.Listen|tls\.Listen)\s*\(`, line)
	regex.match(`"0\.0\.0\.0:|":|":`, line)
	not regex.match(`^\s*//`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Server listening on 0.0.0.0 (all interfaces); bind to a specific interface (e.g., '127.0.0.1:PORT') or ensure authentication middleware is enforced before this service is reachable from untrusted networks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# http.ListenAndServe with 0.0.0.0 or :port
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_go(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`http\.ListenAndServe(TLS)?\s*\(`, line)
	regex.match(`"0\.0\.0\.0:|":|":`, line)
	not regex.match(`^\s*//`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "http.ListenAndServe binding on all interfaces (0.0.0.0 or :PORT); for admin or debug endpoints, bind to localhost; ensure authentication middleware protects all routes when binding publicly",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
