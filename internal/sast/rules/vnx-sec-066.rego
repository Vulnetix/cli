package vulnetix.rules.vnx_sec_066

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-066",
	"name": "HTTP bearer authentication header",
	"description": "Reports a literal HTTP Bearer token: the string \"Bearer <token>\" (an Authorization header in a request file or YAML, a curl -H argument, a headers dict/object, a Header.Set call, a template literal, a constant, or the two-argument .NET AuthenticationHeaderValue(\"Bearer\", \"...\")) whose token is at least 20 characters of token alphabet, contains a digit or is a JWT, and has high entropy, in code, scripts, config and .http/.rest files. The token is masked in the snippet. Not reported: a header built from variables (\"Bearer \" + token, f-strings, ${VAR}, $(...), {{ }}), low-entropy or placeholder values (invalid_token_format, YOUR_ACCESS_TOKEN, xxxx..., the jwt.io sample token), comment lines, Markdown/reStructuredText/AsciiDoc and *.example/*.sample files, and test, fixture, vendored and generated files. Provider-specific token rules report many of the same tokens by their prefix.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-066/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secrets", "http", "bearer", "credentials"],
}

_doc_suffix := [".md", ".markdown", ".rst", ".adoc", ".example", ".sample", ".template", ".dist", ".tmpl"]

_skip(path) if {
	low := lower(path)
	some s in _doc_suffix
	endswith(low, s)
}

# "Bearer " followed by a token that ends the value.
_bearer := `(?i)\bbearer\s+([A-Za-z0-9._~+/-]{20,}=*)(?:['"\x60\s,;)\\]|$)`

# Scheme and parameter as two arguments: .NET AuthenticationHeaderValue("Bearer", "...").
_bearer_pair := `(?i)['"]bearer['"]\s*,\s*['"]([A-Za-z0-9._~+/-]{20,}=*)['"]`

_bearer_patterns := [_bearer, _bearer_pair]

_weak(tok) if secrets.is_placeholder(tok)

_weak(tok) if regex.match(`(?i)your|replace|placeholder|example|redacted|token_?here|access_?token|invalid|dummy|sample`, tok)

# The jwt.io sample token ({"sub":"1234567890","name":"John Doe",...}).
_weak(tok) if contains(tok, "eyJzdWIiOiIxMjM0NTY3ODkw")

_shaped(tok) if regex.match(`[0-9]`, tok)

_shaped(tok) if startswith(tok, "eyJ")

_tokens(line) := {tok |
	some p in _bearer_patterns
	some m in regex.find_all_string_submatch_n(p, line, -1)
	tok := m[1]
	_shaped(tok)
	not _weak(tok)
	secrets.high_entropy(tok, 3.5)
}

# Case-insensitive "bearer" without lowering the whole file.
_mentions(content) if contains(content, "earer ")

_mentions(content) if contains(content, "EARER ")

_mentions(content) if contains(content, "AuthenticationHeaderValue")

findings contains finding if {
	some path, content in input.file_contents
	_mentions(content)
	regex.match(`(?i)bearer(?:\s+|['"]\s*,\s*['"])[A-Za-z0-9._~+/-]{20}`, content)
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(lower(line), "bearer")
	not helpers.is_comment_line(line)
	some tok in _tokens(line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hard-coded HTTP Bearer token; revoke it with the issuing service and read the token at runtime from a secret store or environment variable",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": replace(line, tok, "***"),
	}
}
