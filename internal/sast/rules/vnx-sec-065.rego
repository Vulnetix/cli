package vulnetix.rules.vnx_sec_065

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-065",
	"name": "HTTP basic authentication header",
	"description": "Reports a literal HTTP Basic credential: the string \"Basic <base64>\" (an Authorization or Proxy-Authorization header in a request file, a curl -H argument, a headers dict/object, a Header.Set call, a constant, or the two-argument .NET AuthenticationHeaderValue(\"Basic\", \"...\")) whose base64 decodes to a printable user:password pair with a non-empty password, in code, scripts, config and .http/.rest files. The decoded password is never printed. Not reported: a header built from variables (\"Basic \" + token, f-strings, ${VAR}, $(...)), text that is not a decodable user:password pair (\"Basic authentication\", \"Basic realm\"), default or placeholder pairs (admin:password, user:pass, a password equal to the user, changeme, example...), comment lines, Markdown/reStructuredText/AsciiDoc and *.example/*.sample files, and test, fixture, vendored and generated files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-065/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secrets", "http", "basic-auth", "credentials"],
}

_doc_suffix := [".md", ".markdown", ".rst", ".adoc", ".example", ".sample", ".template", ".dist", ".tmpl"]

_skip(path) if {
	low := lower(path)
	some s in _doc_suffix
	endswith(low, s)
}

# "Basic " followed by a base64 token that ends the value (quote, space,
# backslash continuation, comma or end of line).
_basic := `(?i)\bbasic\s+([A-Za-z0-9+/]{8,}={0,2})(?:['"\x60\s,;)\\]|$)`

# Scheme and parameter as two arguments: .NET AuthenticationHeaderValue("Basic", "...").
_basic_pair := `(?i)['"]basic['"]\s*,\s*['"]([A-Za-z0-9+/]{8,}={0,2})['"]`

_basic_patterns := [_basic, _basic_pair]

_defaults := {
	"password", "passwd", "pass", "pwd", "secret", "changeme", "change_me", "test",
	"testing", "example", "admin", "root", "guest", "default", "123456", "1234",
	"12345678", "password123", "pass123", "mypassword", "foo", "bar", "qwerty",
}

_weak(user, pw) if lower(user) == lower(pw)

_weak(_, pw) if _defaults[lower(pw)]

_weak(_, pw) if regex.match(`(?i)your|placeholder|redacted|changeme|example|<|\$\{`, pw)

_weak(user, _) if regex.match(`(?i)^(your[_-]?)?(user(name)?|login)$`, user)

_weak(_, pw) if secrets.is_placeholder(pw)

_credentials(line) := {[m[1], user] |
	some p in _basic_patterns
	some m in regex.find_all_string_submatch_n(p, line, -1)
	base64.is_valid(m[1])
	decoded := base64.decode(m[1])
	regex.match(`^[\x21-\x7e]+:[\x20-\x7e]+$`, decoded)
	idx := indexof(decoded, ":")
	user := substring(decoded, 0, idx)
	pw := substring(decoded, idx + 1, -1)
	not _weak(user, pw)
}

# Case-insensitive "basic" without lowering the whole file.
_mentions(content) if contains(content, "asic ")

_mentions(content) if contains(content, "ASIC ")

_mentions(content) if contains(content, "AuthenticationHeaderValue")

findings contains finding if {
	some path, content in input.file_contents
	_mentions(content)
	regex.match(`(?i)basic(?:\s+|['"]\s*,\s*['"])[A-Za-z0-9+/]{8}`, content)
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(lower(line), "basic")
	not helpers.is_comment_line(line)
	some cred in _credentials(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Hard-coded HTTP Basic credential for user %q; rotate the password and build the header at runtime from a secret store or environment variable", [cred[1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": replace(line, cred[0], "***"),
	}
}
