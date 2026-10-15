package vulnetix.rules.vnx_gql_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GQL-002",
	"name": "GraphQL query batching enabled without a limit (DoS)",
	"description": "A GraphQL server turns on unbounded operation batching with a literal true: Apollo Server allowBatchedHttpRequests: true, graphql-yoga batching: true, Mercurius allowBatchedQueries: true (JavaScript/TypeScript, in a file that builds one of those servers), or, in a Python file, batch=True as an argument of a still-open GraphQLView(...) or .as_view(...) call (including a GraphQLView subclass's) or as a class attribute of a GraphQLView subclass, in a file that imports graphene, flask_graphql, graphql_server or graphql. One HTTP request can then carry an arbitrary number of operations, multiplying resolver cost and defeating per-request rate limits and brute-force counters. Not reported: false or an environment-derived value, a bounded batching object (batching: { limit: 5 }), the same option on a non-GraphQL object or nested inside another key's object (transport: { batching: true }), batch=True passed to another call near a view (DataLoader(fn, batch=True)), comments, strings and test files. The absence of a depth or complexity limit is deliberately not reported: it cannot be judged from one file.",
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

# Every server option above is top level. The same key inside another key's
# object (`transport: { batching: true }`, or on the line after `transport: {`)
# configures something else.
_nested_in_other_key(_, _, line) if {
	prefix := regex.split(`['"]?(allowBatchedHttpRequests|batching|allowBatchedQueries)['"]?\s*:\s*true\b`, line)[0]
	regex.match(`[\w$]['"]?\s*:\s*\{[^}]*$`, prefix)
}

_nested_in_other_key(lines, i, _) if {
	i > 0
	regex.match(`^\s*['"]?[\w$]+['"]?\s*:\s*\{\s*$`, lines[i - 1])
}

_view_open := `\.as_view\s*\(|GraphQLView\s*\(`

# batch=True is an argument of a still-open GraphQLView(...) / .as_view(...)
# call that starts on this line or up to 12 lines above: the call's opening
# parenthesis has not been closed before the keyword. A batch=True of another
# call near a view (DataLoader(fn, batch=True)) is not.
_in_py_view(_, _, line) if {
	regex.match(_view_open, line)
	parts := regex.split(_view_open, line)
	tail := parts[count(parts) - 1]
	before := regex.split(`\bbatch\s*=\s*True`, tail)[0]
	regex.match(`\bbatch\s*=\s*True`, tail)
	_unclosed(before)
}

_in_py_view(lines, i, line) if {
	some j in numbers.range(max([0, i - 12]), i - 1)
	regex.match(_view_open, lines[j])
	parts := regex.split(_view_open, lines[j])
	tail := parts[count(parts) - 1]
	middle := [lines[k] | some k in numbers.range(j + 1, i - 1); k > j; k < i; not helpers.is_comment_line(lines[k])]
	head := regex.split(`\bbatch\s*=\s*True`, line)[0]
	_unclosed(concat("\n", array.concat(array.concat([tail], middle), [head])))
}

# A class attribute of a GraphQLView subclass: `batch = True` in the body of
# `class BatchView(GraphQLView):`.
_in_py_view(lines, i, line) if {
	regex.match(`^\s+batch\s*=\s*True\s*(#.*)?$`, line)
	some j in numbers.range(max([0, i - 12]), i - 1)
	regex.match(`^\s*class\s+\w+\s*\([^)]*GraphQLView\s*\)\s*:`, lines[j])
	_indent(lines[j]) < _indent(line)
}

_unclosed(text) if count(split(text, ")")) <= count(split(text, "("))

_indent(line) := count(line) - count(trim_left(line, " \t"))

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
	not _nested_in_other_key(lines, i, line)
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

	_in_py_view(lines, i, line)
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
