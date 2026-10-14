package vulnetix.rules.vnx_gql_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GQL-002",
	"name": "GraphQL query batching enabled without a limit (DoS)",
	"description": "A GraphQL server turns on unbounded operation batching with a literal true: Apollo Server allowBatchedHttpRequests: true, graphql-yoga batching: true, Mercurius allowBatchedQueries: true (JavaScript/TypeScript, in a file that builds one of those servers), or batch=True inside a GraphQLView (or GraphQLView subclass) .as_view(...) call in a Python file that imports graphene, flask_graphql, graphql_server or graphql. One HTTP request can then carry an arbitrary number of operations, multiplying resolver cost and defeating per-request rate limits and brute-force counters. Not reported: false or an environment-derived value, a bounded batching object (batching: { limit: 5 }), the same option on a non-GraphQL object, comments, strings and test files. The absence of a depth or complexity limit is deliberately not reported: it cannot be judged from one file.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-gql-002/",
	"languages": ["javascript", "typescript", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [770],
	"capec": ["CAPEC-469"],
	"attack_technique": ["T1499"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["graphql", "dos", "resource-exhaustion"],
}

_is_js(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)

_is_py(path) if endswith(path, ".py")

# Each option only means batching on its own server; `batching: true` on a
# message producer is something else.
_js_opt := `(^|[{,(])\s*['"]?(allowBatchedHttpRequests|batching|allowBatchedQueries)['"]?\s*:\s*true\b`

_js_server("allowBatchedHttpRequests") := `ApolloServer|@apollo/server|apollo-server`

_js_server("batching") := `createYoga|graphql-yoga`

_js_server("allowBatchedQueries") := `mercurius`

_py_kw := `(^|[(,])\s*batch\s*=\s*True\b`

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not helpers.is_test_path(path)
	regex.match(`(allowBatchedHttpRequests|batching|allowBatchedQueries)['"]?\s*:\s*true`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_js_opt, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_js_opt, line, 1)
	regex.match(_js_server(m[0][2]), content)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GraphQL query batching is enabled without a limit (%s: true); one request can carry unbounded operations, bypassing rate limits. Disable it, or bound the batch size", [m[0][2]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	_is_py(path)
	not helpers.is_test_path(path)
	regex.match(`batch\s*=\s*True`, content)
	regex.match(`(?m)^\s*(from|import)\s+(graphene\w*|flask_graphql\w*|graphql_server\w*|graphql)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_py_kw, line)
	not helpers.is_comment_line(line)

	# Inside a view constructor: GraphQLView.as_view(...) or a subclass's.
	regex.match(`\.as_view\s*\(|GraphQLView\s*\(`, helpers.code_window(lines, i, 12, 0))
	finding := {
		"rule_id": metadata.id,
		"message": "GraphQLView is mounted with batch=True; one request can carry unbounded operations, bypassing rate limits. Disable batching or enforce a batch limit",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
