package vulnetix.rules.vnx_sec_011

import rego.v1

import data.vulnetix.helpers
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-011",
	"name": "Hardcoded JWT token",
	"description": "A signed JSON Web Token is written into a file outside tests: three base64url segments whose header and payload decode to JSON objects, the header naming a signing algorithm other than none and the signature at least 16 characters long, in any file type. A committed bearer token authenticates as its subject until it expires, and its claims are readable by anyone with the repository. Not reported: tokens whose exp claim is already in the past, the public jwt.io sample token (sub 1234567890, John Doe), Supabase anon keys (role anon, public by design; VNX-SEC-493 reports them) and the Supabase CLI local demo keys (iss supabase-demo), unsigned alg none tokens, strings that only look like a JWT but do not decode, test, spec, fixture and mock paths (including .NET, Swift and Kotlin *Tests projects and files), lock files, minified bundles and prose files (Markdown, reStructuredText, AsciiDoc, plain text). Provider-specific JWT rules (VNX-SEC-211, VNX-SEC-482, VNX-SEC-492 and others) report the same token with a provider-specific message.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-011/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secrets", "jwt", "token", "credentials"],
}

_skip(path) if secrets.skip_path(path)

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(?i)\.(md|markdown|rst|adoc|txt)$`, path)

# .NET, Swift and Kotlin test projects (Api.Tests/, AppTests/, FooTests.cs).
_skip(path) if regex.match(`(^|/)[\w.]*Tests?/|Tests?\.(cs|swift|kt)$`, path)

# Header and payload are JSON objects, so both open with eyJ ("{\"").
_token_re := `(?:^|[^A-Za-z0-9_\-])(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,})`

# The jwt.io sample token, quoted in documentation and tutorials everywhere.
_sample(payload) if {
	payload.sub == "1234567890"
	payload.name == "John Doe"
}

# Supabase anon keys ship to browsers by design.
_public(payload) if payload.role == "anon"

# The Supabase CLI's local-stack demo keys (iss supabase-demo) are published
# in its documentation and work only against a developer's own machine.
_public(payload) if payload.iss == "supabase-demo"

_expired(payload) if {
	is_number(payload.exp)
	payload.exp * 1000000000 < time.now_ns()
}

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "eyJ")
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".eyJ")
	some m in regex.find_all_string_submatch_n(_token_re, line, -1)
	token := m[1]
	[header, payload, _] := io.jwt.decode(token)
	is_string(header.alg)
	lower(header.alg) != "none"
	is_object(payload)
	not _sample(payload)
	not _public(payload)
	not _expired(payload)
	finding := {
		"rule_id": metadata.id,
		"message": "Signed JWT committed to the repository; revoke or rotate the signing key so the token stops being accepted, and load tokens from the environment or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
