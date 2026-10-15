package vulnetix.rules.vnx_sec_063

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-063",
	"name": "MongoDB connection string with credentials",
	"description": "Reports a MongoDB connection URL that embeds a literal password: mongodb://user:password@host (including replica-set host lists) or mongodb+srv://user:password@cluster, in code, config, .env and compose files. The password is masked in the snippet. Not reported: a password that is interpolated or templated (${VAR}, $VAR, {{ }}, %s, <password>, f-string or template-literal fields, string concatenation), a default or placeholder word (password, root, changeme, mongo, example, the user name itself...), a server on localhost/127.0.0.1/::1 or a documentation host (example.com, *.test, *.invalid, a bare host or hostname), URLs without a password, Markdown/reStructuredText/AsciiDoc and *.example/*.sample/*.template files, and test, fixture, vendored and generated files. VNX-SEC-008 reports the same URLs for every database scheme.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-063/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "mongodb", "database", "credentials", "connection-string"],
}

# The scheme(s) this rule owns, with an optional driver suffix
# (mongodb+srv) and an optional jdbc: prefix.
_schemes := `mongodb`

# scheme://user:password@host  (groups: user, password, host)
_url := concat("", [
	"(?i)(?:^|[^a-z0-9+])(?:jdbc:)?", _schemes, "(?:\\+[a-z0-9]+)?://",
	"([^\\s:@/'\"`<>]*):([^\\s@/'\"`<>]+)@(\\[[0-9a-f:]+\\]|[a-z0-9_.-]+)",
])


_doc_suffix := [".md", ".markdown", ".rst", ".adoc", ".example", ".sample", ".template", ".dist", ".tmpl"]

_skip(path) if {
	low := lower(path)
	some s in _doc_suffix
	endswith(low, s)
}

_skip(path) if regex.match(`(?i)\.(example|sample|template)\.[a-z0-9]+$`, path)

_defaults := {
	"password", "passwd", "pass", "pwd", "pw", "secret", "changeme", "change_me",
	"postgres", "postgresql", "root", "mysql", "mariadb", "admin", "administrator",
	"test", "testing", "example", "user", "username", "guest", "default", "redis",
	"mongo", "mongodb", "sa", "dbpass", "dbpassword", "db_password", "mypassword",
	"pass123", "password123", "123456", "secretpassword", "mysecretpassword",
}

_weak_password(user, pw) if lower(pw) == lower(user)

_weak_password(_, pw) if _defaults[lower(pw)]

# Interpolation and templating: ${X}, $X, {{ x }}, <password>, %s, %(x)s,
# *** and ... masks.
_weak_password(_, pw) if regex.match(`[$\{\}<>*]|%[sdvq(]|\.\.\.|^:`, pw)

_weak_password(_, pw) if secrets.is_placeholder(pw)

_weak_password(_, pw) if regex.match(`(?i)your|placeholder|redacted|changeme`, pw)

_loopback(host) if regex.match(`(?i)^(localhost|127\.[0-9.]+|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal)$`, host)

# Documentation hosts: RFC 2606/6761 names (example.com, *.test, *.invalid) and
# the generic words a usage string puts where the host goes (host, hostname).
_loopback(host) if regex.match(`(?i)^(host|hostname|server|servername|dbhost|db_host|db-host|your[a-z0-9_.-]*|([a-z0-9-]+\.)*example(\.(com|org|net))?|[a-z0-9.-]+\.(test|invalid))$`, host)

_url_creds(line) := {[m[2], m[3]] |
	some m in regex.find_all_string_submatch_n(_url, line, -1)
	not _weak_password(m[1], m[2])
	not _loopback(m[3])
}


# Whole-file gate: the full URL expression, run once per file.
_candidate(content) if regex.match(concat("", ["(?m)", _url]), content)


# Cheap literal pre-gate (the URL regex itself is case-insensitive).
_names_scheme(s) if contains(s, "mongodb")

_names_scheme(s) if contains(s, "MongoDB")

_names_scheme(s) if contains(s, "MONGODB")

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "://")
	_names_scheme(content)
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	not _skip(path)
	_candidate(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "://")
	some cred in _url_creds(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MongoDB connection string for %s embeds a password; rotate the password and supply the URL (or just the password) from the environment or a secrets manager", [cred[1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": replace(line, cred[0], "***"),
	}
}
