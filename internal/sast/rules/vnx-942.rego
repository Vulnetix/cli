# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_942

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-942",
	"name": "Permissive cross-origin (CORS) policy in a Node.js server",
	"description": "A Node.js/TypeScript server lets any website read its responses. Reported: the Access-Control-Allow-Origin response header set to '*' (res.setHeader/res.header/res.set/ctx.set/writeHead or a headers object literal); the header set to the request's own Origin (req.headers.origin, req.get('origin'), req.header('origin'), ctx.get('origin'), ctx.request.headers.origin), directly or through a variable assigned from it in the 8 lines above, with no allowlist test (includes/indexOf/has/test/===) in between; the cors package called with no options (cors() allows every origin), with origin: true / origin: '*', or with an origin callback that always answers cb(null, true); Fastify register(cors) / register(require('@fastify/cors')) with no options (the plugin defaults to '*') or with origin: true / '*'; and NestJS app.enableCors() with no options or NestFactory.create(..., { cors: true }). Not reported: a specific origin or an allowlist, a reflected origin checked against an allowlist first, the header sent by client code (setRequestHeader, fetch/axios request headers), test files, comments and string literals that merely mention the header. This rule owns CORS in JavaScript/TypeScript servers; the same weakness in other languages, server configuration and the AWS CDK construct is VNX-SEC-012.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-942/",
	"languages": ["node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [942],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cors", "cwe-942"],
}

_ext_re := `\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(^|/)node_modules/|\.min\.js$`, path)

_gate(content) if contains(lower(content), "access-control-allow-origin")

_gate(content) if contains(content, "ors(")

_gate(content) if contains(content, "@fastify/cors")

_gate(content) if {
	contains(content, "NestFactory")
	regex.match(`\bcors\s*:\s*true`, content)
}

# The header name followed by its value, in a call or an object literal.
_acao_value(line) := v if {
	m := regex.find_all_string_submatch_n(`(?i)["'\x60]access-control-allow-origin["'\x60]\s*\]?\s*[,:=]\s*(.*)$`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_client(line) if regex.match(`setRequestHeader\s*\(|\bfetch\s*\(|\baxios\b|\$\.ajax|\bhttp\.(get|post|put|request)\s*\(`, line)

_client_nearby(lines, i) if {
	some j in numbers.range(max([0, i - 4]), i)
	_client(lines[j])
}

_origin_src := `(?i)\b(req|request|ctx|ctx\.request|event)\.(headers\s*(\.origin\b|\[\s*["']origin["']\s*\])|get\(\s*["']origin["']\s*\)|header\(\s*["']origin["']\s*\)|origin\b)`

_guard_re := `(\.includes\(|\.indexOf\(|\.has\(|\.test\(|===|!==|==|\.some\(|\.find\(|allow\w*\s*\[)`

_is_wildcard(v) if regex.match(`^["'\x60]\*["'\x60]`, trim_space(v))

# '*'
_problem("wildcard", lines, i, line) if {
	v := _acao_value(line)
	_is_wildcard(v)
	not _client_nearby(lines, i)
}

# the request's own Origin, inline
_problem("reflect", lines, i, line) if {
	v := _acao_value(line)
	regex.match(_origin_src, v)
	not _client_nearby(lines, i)
}

# the request's own Origin, through a variable, with no allowlist test between
_problem("reflect", lines, i, line) if {
	v := _acao_value(line)
	not regex.match(_origin_src, v)
	some j in numbers.range(max([0, i - 8]), i - 1)
	not helpers.is_comment_line(lines[j])
	regex.match(_origin_src, lines[j])
	name := helpers.assigned_first(lines[j])
	regex.match(concat("", [`^\s*`, name, `\b`]), v)
	not _guarded(lines, j, i, name)
}

_guarded(lines, j, i, name) if {
	some k in numbers.range(j, i)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(_guard_re, l)
	regex.match(concat("", [`\b`, name, `\b`]), l)
	k != j
}

_guarded(lines, j, _, name) if {
	# assignment itself is a lookup: const o = allowed.includes(req.headers.origin) ? ... : ...
	regex.match(_guard_re, lines[j])
}

# cors() with no options
_problem("cors-default", lines, i, line) if {
	regex.match(`(^|[^\w.])cors\(\s*\)`, line)
}

# NestJS enableCors() with no options
_problem("cors-default", lines, i, line) if {
	regex.match(`\.enableCors\(\s*\)`, line)
}

# Fastify: register(cors) with no options (@fastify/cors defaults to origin '*')
_problem("cors-default", lines, i, line) if {
	regex.match(`\.register\(\s*(cors|fastifyCors|require\(\s*["']@fastify/cors["']\s*\))\s*\)`, line)
}

# NestFactory.create(AppModule, { cors: true }) is enableCors() with no options
_problem("nest-cors-true", lines, i, line) if {
	regex.match(`\bNestFactory\s*\.\s*create\w*\s*(<[^>]*>)?\s*\([^)]*\bcors\s*:\s*true\b`, line)
}

# cors({ origin: true }) / origin: '*'
_problem("cors-any", lines, i, line) if {
	regex.match(`\borigin\s*:\s*(true\b|["'\x60]\*["'\x60])`, line)
	some j in numbers.range(max([0, i - 8]), i)
	regex.match(`(^|[^\w.])cors\(|\.enableCors\(|register\(\s*(cors|fastifyCors|require\(\s*["']@fastify/cors["']\s*\))\s*[,)]|\bcorsOptions\s*=|\bcorsConfig\s*=`, lines[j])
}

# cors({ origin: (o, cb) => cb(null, true) }): a callback that accepts every origin
_problem("cors-any", lines, i, line) if {
	regex.match(`(?:^|[\s{,])origin\s*:\s*(?:async\s+)?(?:\([^)]*\)\s*=>|function\s*\w*\s*\([^)]*\))\s*\{?\s*(?:return\s+)?\w+\(\s*null\s*,\s*true\s*\)`, line)
	some j in numbers.range(max([0, i - 8]), i)
	regex.match(`(^|[^\w.])cors\(|\.enableCors\(|register\(\s*(cors|fastifyCors|require\(\s*["']@fastify/cors["']\s*\))\s*[,)]|\bcorsOptions\s*=|\bcorsConfig\s*=`, lines[j])
}

_messages := {
	"wildcard": "Access-Control-Allow-Origin is '*': any website may read this response. Name the trusted origins instead",
	"reflect": "Access-Control-Allow-Origin echoes the request's Origin header without an allowlist check, so every website is trusted (with credentials, if allowed)",
	"cors-default": "CORS middleware enabled with no options allows every origin. Pass an explicit origin allowlist",
	"nest-cors-true": "NestJS created with cors: true allows every origin. Pass an options object with an explicit origin allowlist",
	"cors-any": "CORS configured with origin: true or '*' trusts every requesting website. Pass an explicit origin allowlist",
}

_uses_cors_pkg(content) if regex.match(`(require\(\s*["'](cors|@fastify/cors|@koa/cors|kcors)["']\s*\)|from\s+["'](cors|@fastify/cors|@koa/cors|kcors)["']|enableCors\()`, content)

findings contains finding if {
	some path, content in input.file_contents
	regex.match(_ext_re, path)
	not _skip(path)
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)access-control-allow-origin|ors\(|origin\s*:|\bcors\s*:|register\(`, line)
	not helpers.is_comment_line(line)
	some kind in {"wildcard", "reflect", "cors-default", "cors-any", "nest-cors-true"}
	_problem(kind, lines, i, line)
	_kind_ok(kind, content)
	finding := {
		"rule_id": metadata.id,
		"message": _messages[kind],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_kind_ok("wildcard", _)

_kind_ok("reflect", _)

_kind_ok("nest-cors-true", _)

_kind_ok("cors-default", content) if _uses_cors_pkg(content)

_kind_ok("cors-any", content) if _uses_cors_pkg(content)
