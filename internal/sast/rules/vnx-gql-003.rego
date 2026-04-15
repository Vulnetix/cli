package vulnetix.rules.vnx_gql_003

import rego.v1

metadata := {
	"id": "VNX-GQL-003",
	"name": "GraphQL query string injection via string concatenation",
	"description": "A GraphQL operation document is built by concatenating or interpolating user-controlled input directly into the query string. This allows attackers to inject arbitrary fields, aliases, or directives into the operation, potentially accessing unauthorized resolvers or altering server-side behavior. Use static operation documents with bound variables maps instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-gql-003/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["graphql", "injection", "query-injection"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Template literal with request body/params interpolated into a query/mutation/subscription
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match("(?i)(query|mutation|subscription)\\s*[{`].*\\$\\{", line)
	regex.match(`\$\{.*(req\.|request\.|body\.|params\.|query\.|args\.)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GraphQL query injection: user input interpolated into operation string — use static documents with variables map instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# String concatenation building a query/mutation field list from user input
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`["']\s*(query|mutation|subscription)\s*\{.*["']\s*\+`, line)
	regex.match(`\+\s*(req\.|request\.|body\.|params\.|userInput|fragment|field)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GraphQL query injection: user input concatenated into operation string — use static documents with variables map instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Python f-string / format building query from variable
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`f["'].*?(query|mutation|subscription).*\{.*\{`, line)
	regex.match(`(?i)(user|request|input|param|arg|field)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GraphQL query injection: user input interpolated into operation string via f-string — use static documents with variable bindings instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
