package vulnetix.rules.vnx_gql_002

import rego.v1

metadata := {
	"id": "VNX-GQL-002",
	"name": "GraphQL query batching or no depth limit (DoS)",
	"description": "Apollo Server is configured with allowBatchedHttpRequests: true or without depth/complexity limits. This allows deeply nested or batched queries that can cause denial of service by consuming excessive server resources.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-gql-002/",
	"languages": ["javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [770],
	"capec": ["CAPEC-469"],
	"attack_technique": ["T1499"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["graphql", "dos", "resource-exhaustion"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`allowBatchedHttpRequests\s*:\s*true`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GraphQL query batching enabled; this allows attackers to send many operations per request, bypassing rate limiting — disable unless specifically required",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
