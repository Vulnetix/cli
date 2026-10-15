package vulnetix.rules.vnx_gql_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GQL-001",
	"name": "GraphQL introspection enabled in production",
	"description": "A GraphQL server configuration hard-codes schema exposure on: in JavaScript/TypeScript an object key introspection: true, graphiql: true or playground: true in a file that builds a GraphQL server (Apollo Server, express-graphql, graphql-http, graphql-yoga, Mercurius, NestJS GraphQLModule/GqlOptionsFactory); in Python graphiql=True or introspection=True in a file that mounts a GraphQL view (flask-graphql/graphene GraphQLView, Strawberry GraphQLRouter, Ariadne GraphQL). Introspection and the in-browser IDEs expose the whole schema for reconnaissance. Not reported: a value computed from the environment (introspection: isDev, graphiql: process.env.NODE_ENV === 'development'), a literal true that is itself conditional (the arm of a ternary or && spread such as ...(isDev ? { introspection: true } : {}), or Python True if DEBUG else False), a literal true inside an if a few lines above that tests the environment (if (process.env.NODE_ENV !== 'production') {, if settings.DEBUG:), false, the same key in a file that does not build a GraphQL server, comments, string literals and test files.",
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

# A literal true that is itself conditional is a dev-only branch: the object
# is the arm of a ternary or a short-circuit spread (`...(isDev ? { ... } : {})`,
# `...(flag && { ... })`), or the Python value is `True if DEBUG else False`.
# An environment test elsewhere on the line (`introspection: true, debug:
# !isProd`) does not make the literal conditional.
_conditional(line) if regex.match(`(\?|&&|\|\|)\s*\{[^}]*\b(introspection|graphiql|playground)['"]?\s*:\s*true\b`, line)

_conditional(line) if regex.match(`\b(graphiql|introspection)\s*=\s*True\s+if\b`, line)

_env_term := `(NODE_ENV|\bisDev\w*|\bisDevelopment|__DEV__|\bisProd\w*|\bDEBUG\b|FLASK_ENV|DJANGO_ENV|\bENVIRONMENT\b|process\.env\.|os\.environ|getenv|\bdevelopment\b)`

# The line sits inside an `if` a few lines above that tests the environment
# (`if (process.env.NODE_ENV !== 'production') {`, `if settings.DEBUG:`),
# recognised by that `if` being less indented than the line.
_in_env_if(lines, i) if {
	some j in numbers.range(max([0, i - 4]), i - 1)
	cond := lines[j]
	regex.match(`^\s*(\}\s*)?(else\s+)?(if|elif)\b`, cond)
	regex.match(_env_term, cond)
	_indent(cond) < _indent(lines[i])
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

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
	not _conditional(line)
	not _in_env_if(lines, i)
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
	not _conditional(line)
	not _in_env_if(lines, i)
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
