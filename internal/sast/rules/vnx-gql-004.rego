package vulnetix.rules.vnx_gql_004

import rego.v1

metadata := {
	"id": "VNX-GQL-004",
	"name": "GraphQL field suggestion disclosure enabled",
	"description": "GraphQL field suggestion (also called schema suggestion or did-you-mean) is enabled, revealing internal schema structure to attackers through error messages like 'Did you mean field X?'. This leaks private field names that are not exposed through introspection. Disable suggestions in production by setting the suggestions option to false in Apollo Server or equivalent.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-gql-004/",
	"languages": ["javascript", "typescript"],
	"severity": "low",
	"level": "warning",
	"kind": "open",
	"cwe": [200],
	"capec": ["CAPEC-118"],
	"attack_technique": ["T1592"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["graphql", "information-disclosure", "schema"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Apollo Server with no explicit suggestions: false — only flag when in a server config context
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`new ApolloServer\s*\(`, line)
	not regex.match(`suggestions\s*:\s*false`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GraphQL field suggestions are not explicitly disabled; error messages may leak private schema field names — set suggestions: false in ApolloServer config for production",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# graphql-yoga or other servers with hideSchemaIssues / maskedErrors not set
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`createYoga\s*\(|GraphQLServer\s*\(`, line)
	not regex.match(`maskedErrors\s*:\s*true`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GraphQL server created without maskedErrors: true; error messages may leak schema field names — enable maskedErrors in production to hide internal schema details",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
