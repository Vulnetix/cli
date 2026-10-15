package vulnetix.rules.vnx_gql_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GQL-004",
	"name": "GraphQL field suggestion disclosure enabled",
	"description": "A JavaScript/TypeScript GraphQL server is constructed (new ApolloServer(...) or new ApolloServer<Context>(...), createYoga(...), GraphQLModule.forRoot(...), graphqlHTTP(...), register(mercurius, ...)) in a project that nowhere suppresses graphql-js field suggestions. These servers return validation errors such as 'Cannot query field \"pasword\". Did you mean \"password\"?' by default, which lets an attacker enumerate the schema even with introspection disabled. A project counts as mitigated when any of its files sets hideSchemaDetailsFromClientErrors: true (Apollo Server), uses GraphQL Armor (ApolloArmor, EnvelopArmor, blockFieldSuggestions), a disable-suggestions plugin, or a formatError/maskError that rewrites 'Did you mean' messages. Reported once per constructor call; test files, comments and string literals are not reported. Servers in other languages are not covered.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-gql-004/",
	"languages": ["javascript", "typescript"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [200],
	"capec": ["CAPEC-118"],
	"attack_technique": ["T1592"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["graphql", "information-disclosure", "schema"],
}

_is_js(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)

_gate(content) if contains(content, "ApolloServer")

_gate(content) if contains(content, "createYoga")

_gate(content) if contains(content, "GraphQLModule")

_gate(content) if contains(content, "graphqlHTTP")

_gate(content) if contains(content, "mercurius")

# The constructor call itself, not an import, a type or the name in a string.
_ctor := `(^|[^"'\x60\w.])(new\s+ApolloServer\s*(<[^>]*>)?\s*\(|createYoga\s*(<[^>]*>)?\s*\(|GraphQLModule\.forRoot(Async)?\s*(<[^>]*>)?\s*\(|graphqlHTTP\s*\()|\.register\(\s*mercurius\b`

_ctor_core := `new\s+ApolloServer\s*(<[^>]*>)?\s*\(|createYoga\s*(<[^>]*>)?\s*\(|GraphQLModule\.forRoot(Async)?\s*(<[^>]*>)?\s*\(|graphqlHTTP\s*\(|\.register\(\s*mercurius\b`

# The first constructor on the line sits inside a string literal (an odd
# number of one quote kind before it) or after a trailing // comment.
_in_string_or_comment(line) if {
	prefix := regex.split(_ctor_core, line)[0]
	some q in ["'", "\"", "`"]
	count(indexof_n(prefix, q)) % 2 == 1
}

_in_string_or_comment(line) if {
	prefix := regex.split(_ctor_core, line)[0]
	contains(prefix, "//")
}

_mitigation :=`hideSchemaDetailsFromClientErrors\s*:\s*true|blockFieldSuggestion|graphql-armor|ApolloArmor|EnvelopArmor|[Dd]isableSuggestions|Did you mean|didYouMean|suggestions\s*:\s*false`

# A mitigation anywhere in the project protects every server in it.
_mitigated if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(_mitigation, content)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not helpers.is_test_path(path)
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_ctor, line)
	not helpers.is_comment_line(line)
	not _in_string_or_comment(line)
	not _mitigated
	finding := {
		"rule_id": metadata.id,
		"message": "GraphQL server leaks schema field names through 'Did you mean ...?' validation errors; disable field suggestions in production (Apollo hideSchemaDetailsFromClientErrors: true, or GraphQL Armor blockFieldSuggestions)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
