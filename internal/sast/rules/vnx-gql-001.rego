package vulnetix.rules.vnx_gql_001

import rego.v1

metadata := {
	"id": "VNX-GQL-001",
	"name": "GraphQL introspection enabled in production",
	"description": "GraphQL introspection is explicitly enabled in Apollo Server or GraphiQL is enabled in express-graphql. Introspection exposes the entire API schema to attackers, enabling reconnaissance of queries, mutations, types, and fields.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-gql-001/",
	"languages": ["javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [200],
	"capec": ["CAPEC-116"],
	"attack_technique": ["T1590"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["graphql", "information-disclosure", "misconfiguration"],
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
	regex.match(`introspection\s*:\s*true`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GraphQL introspection is enabled; disable it in production to prevent schema reconnaissance — set introspection: false or remove the option",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`graphiql\s*:\s*true`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GraphiQL IDE is enabled; disable it in production (graphiql: false) to prevent unauthorized schema exploration and query execution",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
