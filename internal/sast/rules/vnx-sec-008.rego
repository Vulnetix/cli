package vulnetix.rules.vnx_sec_008

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-008",
	"name": "Database connection string with credentials",
	"description": "Reports a database connection URL that embeds a literal password: scheme://user:password@host for PostgreSQL, MySQL/MariaDB, MongoDB (including mongodb+srv), Redis (redis/rediss, including an empty user), SQL Server (mssql/sqlserver) and CockroachDB, with an optional driver suffix (postgresql+psycopg2, mysql+pymysql) or jdbc: prefix, a JDBC URL with a password= parameter, and a Go go-sql-driver/mysql DSN (user:password@tcp(host:port)/db), in code, config, .env and compose files. Not reported: a password that is interpolated or templated (${VAR}, $VAR, {{ }}, %s, <password>), a default or placeholder word (password, postgres, root, changeme, the user name itself…), a database on localhost/127.0.0.1/::1, URLs without a password, Markdown/reStructuredText/AsciiDoc and *.example/*.sample/*.template files, and test, fixture, vendored and generated files. Key=value connection strings (Server=…;Password=…) are VNX-SEC-598.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-008/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "database", "credentials", "connection-string"],
}

_schemes := `(?:postgres(?:ql)?|mysql|mariadb|mongodb|rediss?|mssql|sqlserver|cockroachdb)`

# scheme://user:password@host  (groups: user, password, host)
_url := concat("", [
	"(?i)(?:^|[^a-z0-9+])(?:jdbc:)?", _schemes, "(?:\\+[a-z0-9]+)?://",
	"([^\\s:@/'\"`<>]*):([^\\s@/'\"`<>]+)@(\\[[0-9a-f:]+\\]|[a-z0-9_.-]+)",
])

# jdbc:<vendor>://host...?password=...  (groups: host, password)
_jdbc := "(?i)jdbc:[a-z0-9]+:(?://)?([^/:;?\\s'\"`]+)[^\\s'\"`]*?[?&;](?:password|pwd)=([^&;\\s'\"`]+)"

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

_url_creds(line) := {[m[2], m[3]] |
	some m in regex.find_all_string_submatch_n(_url, line, -1)
	not _weak_password(m[1], m[2])
	not _loopback(m[3])
}

_jdbc_creds(line) := {[m[2], m[1]] |
	some m in regex.find_all_string_submatch_n(_jdbc, line, -1)
	not _weak_password("", m[2])
	not _loopback(m[1])
}

# Go's go-sql-driver/mysql DSN has no scheme: user:password@tcp(host:port)/db
# (or @unix(/path)). Groups: user, password, host.
_go_mysql := "(?:^|[\\s\"'`=,(])([A-Za-z0-9_.-]+):([^\\s@/'\"`:]+)@(?:tcp|unix)\\(([^:)\\s]+)"

_go_mysql_creds(line) := {[m[2], m[3]] |
	contains(line, "@tcp(")
	some m in regex.find_all_string_submatch_n(_go_mysql, line, -1)
	not _weak_password(m[1], m[2])
	not _loopback(m[3])
}

# Whole-file gate: the full URL (or JDBC) expression, run once per file, after
# a cheap literal check that the file holds a credential-shaped URL at all.
_candidate(content) if {
	contains(content, "://")
	regex.match(`://[^\s@/]*:[^\s@/]+@`, content)
	regex.match(concat("", ["(?m)", _url]), content)
}

_candidate(content) if {
	contains(content, "jdbc:")
	regex.match(_jdbc, content)
}

_candidate(content) if {
	contains(content, "@tcp(")
	regex.match(_go_mysql, content)
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not _test_path(path)
	not _skip(path)
	_candidate(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`://|@tcp\(`, line)
	some cred in (_url_creds(line) | _jdbc_creds(line)) | _go_mysql_creds(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Database connection string for %s embeds a password; rotate the database password and supply the URL (or just the password) from the environment or a secrets manager", [cred[1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": replace(line, cred[0], "***"),
	}
}

# Test code beyond helpers.is_test_path: Jest __mocks__ directories and Xcode
# test targets (AppTests/, FooTests.swift), which hold fake credentials.
_test_path(path) if helpers.is_test_path(path)

_test_path(path) if regex.match(`(^|/)(__mocks__|[A-Za-z0-9_]*Tests)/|Tests?\.swift$`, path)
