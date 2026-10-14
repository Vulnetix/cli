# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1052

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1052",
	"name": "Hard-coded Endpoint Literal in Datastore Client Initialization",
	"description": "A database, cache or message-broker client is initialised with a hard-coded network endpoint: a non-loopback IP address or a real host name written as a literal (CWE-1052, a hard-coded literal that is not a simple constant used in initialization). Reported in Go, Java, JavaScript/TypeScript, PHP and Python: a connection URI literal (mysql://, postgres://, mongodb://, redis://, amqp://, jdbc:...://, jdbc:oracle:thin:@), a key=value DSN with host= or server= (PDO 'mysql:host=...', libpq 'host=...'), a host/addr/server field or keyword argument holding the literal inside a client constructor (redis.NewClient(&redis.Options{Addr: ...}), psycopg2.connect(host=...), mysql.createPool({host: ...}), 'host' => ... near new PDO), and the literal as the first argument of new Jedis/MongoClient/mysqli, mysqli_connect, redis.Redis, grpc.Dial. The endpoint then cannot change without a code change, ships the network layout in the source and is usually where credentials sit beside it. Not reported: localhost, 127.x, 0.0.0.0, ::1 and placeholder domains (example.com, .test, .invalid, .local, .localhost); a literal on a line that reads the environment or configuration (os.Getenv, process.env, getenv, env(), config(), a fallback default); a URI inside a longer message; comments; test files. Credentials inside such strings are reported by the connection-string rules (VNX-SEC-008, VNX-SEC-061), not here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1052/",
	"languages": ["go", "java", "python", "node", "php"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1052],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["hard-coded-literals", "hard-coded-endpoint", "configuration", "database", "code-quality", "cwe-1052"],
}

_exts := [".go", ".java", ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".php"]

_lang_ok(path) if {
	some ext in _exts
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

_vendored(path) if regex.match(`(^|/)(node_modules|bower_components|vendor|third_party|site-packages|\.venv|\.yarn|dist|build)/`, path)

# an IPv4 address or a dotted host name with an alphabetic top-level label
_host := `((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,})`

_schemes := `(?:mysql|mariadb|postgres|postgresql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps|mssql|sqlserver|cassandra|nats|memcached|clickhouse|neo4j|bolt|jdbc:[a-z0-9]+(?::[a-z0-9]+)?)`

# A. a connection URI that starts the string literal
_uri_re := concat("", ["[\"'`]", _schemes, `://(?:[^/@'"\x60\s]*@)?`, _host, `(?:[:/;?,'"\x60]|$)`])

# A'. Oracle thin driver
_ora_re := concat("", [`["']jdbc:oracle:thin:[^@'"]*@(?://)?`, _host, `[:/'"]`])

# B. key=value DSN inside a literal
_dsn_re := concat("", [`["'][^"'\n]*\b(?:host|server|Server|Host)=`, _host, `(?:[;\s,'"]|$)`])

# C. a host field or keyword argument in a client constructor
_field_re := concat("", [`(?:^|[\s{(,])["']?(?:host|hostname|Host|HostName|server|Server|addr|Addr|address|Address|Addrs|servers|brokers|nodes)["']?\s*(?::|=>|=)\s*(?:\[\s*|\[\]string\{\s*)?["'\x60]`, _host, `(?::\d+)?["'\x60]`])

_client_re := `(?i)(redis\.(new\w*client|redis|strictredis|createclient|cluster)|create(connection|pool|client)\b|new\s+(redis|pool|client|sequelize|mongoclient|jedis|jedispool|mysqli|pdo|memcached|kafka|cluster|knex)\b|knex\(|\bconnect\(|\.connect\(|options\s*\{|clusteroptions|universaloptions|mysqli_connect|pg_connect|pymysql|psycopg|mysql\.connector|elasticsearch\(|sequelize\(|amqp|nats\.|kafka|config\.(addr|host)|dataSource|hikariconfig|setservername|sethost|setjdbcurl|create_engine|motor|aioredis|mongoclient|'mysql'\s*=>|'pgsql'\s*=>|'redis'\s*=>|connections)`

# D. the host as the first positional argument
_pos_re := concat("", [`(?:new\s+(?:Jedis|JedisPool|MongoClient|mysqli|Memcached|Redis)|mysqli_connect|redis\.(?:Redis|StrictRedis)|pymysql\.connect|MongoClient|grpc\.Dial|grpc\.DialContext|grpc\.NewClient|net\.Dial)\s*\(\s*(?:ctx,\s*)?(?:"tcp",\s*)?["']`, _host, `(?::\d+)?["']`])

# a line that reads configuration: the literal there is a fallback default
_config_read := `(?i)(getenv|environ|process\.env|system\.getproperty|\benv\(|\$_env|\$_server|\bconfig\(|viper\.|os\.lookupenv|settings\.|import\.meta\.env)`

_placeholder(h) if regex.match(`^(127\.\d+\.\d+\.\d+|0\.0\.0\.0|255\.255\.255\.255)$`, h)

_placeholder(h) if regex.match(`(?i)(^|\.)(localhost|example\.(com|org|net)|example|test|invalid|local|localdomain|internal\.example)$`, h)

# version numbers and other dotted digits that are not addresses
_placeholder(h) if {
	regex.match(`^(\d{1,3}\.){3}\d{1,3}$`, h)
	some p in split(h, ".")
	to_number(p) > 255
}

_hosts(line) := {h |
	some re in [_uri_re, _ora_re, _dsn_re, _pos_re]
	some m in regex.find_all_string_submatch_n(re, line, -1)
	h := m[1]
}

_field_hosts(lines, i, line) := {h |
	regex.match(_field_re, line)
	regex.match(_client_re, helpers.code_window(lines, i, 8, 0))
	some m in regex.find_all_string_submatch_n(_field_re, line, -1)
	h := m[1]
}

findings contains finding if {
	some path, content in input.file_contents
	_lang_ok(path)
	not _vendored(path)
	not helpers.is_test_path(path)
	regex.match(`(?i)(://|host|addr|server|connect|mysqli|jedis|mongo|redis|dial)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9-]\.[A-Za-z]{2,}`, line)
	count(line) < 400
	not helpers.is_comment_line(line)
	not regex.match(_config_read, line)
	hosts := _hosts(line) | _field_hosts(lines, i, line)
	real := sort([h | some h in hosts; not _placeholder(h)])
	count(real) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Datastore or broker client initialised with the hard-coded endpoint '%s'; read the address from configuration or the environment so it can change without a code change and the network layout stays out of the source", [real[0]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
