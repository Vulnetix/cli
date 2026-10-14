package vulnetix.rules.vnx_gql_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GQL-001",
	"name": "GraphQL introspection enabled in production",
	"description": "A GraphQL server configuration hard-codes schema exposure on: in JavaScript/TypeScript an object key introspection: true, graphiql: true or playground: true in a file that builds a GraphQL server (Apollo Server, express-graphql, graphql-http, graphql-yoga, Mercurius, NestJS GraphQLModule/GqlOptionsFactory); in Python graphiql=True or introspection=True in a file that mounts a GraphQL view (flask-graphql/graphene GraphQLView, Strawberry GraphQLRouter, Ariadne GraphQL). Introspection and the in-browser IDEs expose the whole schema for reconnaissance. Not reported: a value computed from the environment (introspection: isDev, graphiql: process.env.NODE_ENV === 'development'), a literal true on a line that itself tests the environment, false, the same key in a file that does not build a GraphQL server, comments, string literals and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-gql-001/",
	"languages": ["javascript", "typescript", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [200],
	"capec": ["CAPEC-116"],
	"attack_technique": ["T1590"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["graphql", "information-disclosure", "misconfiguration"],
}

_is_js(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)

_is_py(path) if endswith(path, ".py")

_js_server := `ApolloServer|graphqlHTTP|graphql-http|createYoga|mercurius|GraphQLModule|GqlOptionsFactory|GqlModuleOptions|ApolloDriverConfig|ApolloDriver`

_py_server := `GraphQLView|GraphQLRouter|GraphQLApp|ariadne|strawberry|graphene`

# The key at the start of the line or after `{` / `,`: an object member, not
# prose inside a string.
_js_key := `(^|[{,(])\s*['"]?(introspection|graphiql|playground)['"]?\s*:\s*true\b`

_py_kw := `(^|[(,])\s*(graphiql|introspection)\s*=\s*True\b`

# A literal true on a line that tests the environment is a dev-only branch.
_env_gated(line) if regex.match(`(?i)(NODE_ENV|isDev\b|isDevelopment|__DEV__|isProd|isProduction|FLASK_ENV|DEBUG\s*(and|\?|&&))`, line)

_message("introspection") := "GraphQL introspection is enabled unconditionally; disable it in production (introspection: false, or gate it on the environment) to prevent schema reconnaissance"

_message("graphiql") := "The GraphiQL IDE is enabled unconditionally; disable it in production (graphiql: false, or gate it on the environment) to prevent schema exploration"

_message("playground") := "GraphQL Playground is enabled unconditionally; disable it in production (playground: false, or gate it on the environment) to prevent schema exploration"

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not helpers.is_test_path(path)
	regex.match(`(introspection|graphiql|playground)['"]?\s*:\s*true`, content)
	regex.match(_js_server, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_js_key, line)
	not helpers.is_comment_line(line)
	not _env_gated(line)
	m := regex.find_all_string_submatch_n(_js_key, line, 1)
	finding := {
		"rule_id": metadata.id,
		"message": _message(m[0][2]),
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
	regex.match(`(graphiql|introspection)\s*=\s*True`, content)
	regex.match(_py_server, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_py_kw, line)
	not helpers.is_comment_line(line)
	not _env_gated(line)
	m := regex.find_all_string_submatch_n(_py_kw, line, 1)
	finding := {
		"rule_id": metadata.id,
		"message": _message(m[0][2]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
