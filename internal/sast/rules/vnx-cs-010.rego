package vulnetix.rules.vnx_cs_010

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CS-010",
	"name": "C# hardcoded connection string with credentials",
	"description": "C# source carries a database or cache connection string whose password is a literal: a string literal (regular, verbatim or interpolated, whole or one part of a concatenation) holding a Password= or Pwd= key (also Jet OLEDB:Database Password=, or a StackExchange.Redis ,password= option) with a literal value, in a string that is recognisably a connection string (another connection key such as Server, Data Source, Host, Database, Initial Catalog, User Id, Uid or Port in it or in the concatenation around it, a host:port Redis endpoint, or a SqlConnection/NpgsqlConnection/UseSqlServer/UseNpgsql/ConnectionMultiplexer.Connect/ConnectionString sink on the line); or a literal assigned to the Password property or [\"Password\"] indexer of a *ConnectionStringBuilder, a StackExchange.Redis ConfigurationOptions or a RabbitMQ ConnectionFactory, by assignment or in its object initializer. Not reported: a password taken from configuration, the environment or a variable (string.Format {0} holes, interpolation holes, concatenation), an empty value, placeholders (<password>, [password], myPassword, YOUR_PASSWORD, ***, #{Token}#, $(Var), $VAR, %VAR%, __TOKEN__, REPLACE_ME, TODO, @param), SQL text that compares or sets a Password column, code that redacts a connection string, Integrated Security or managed-identity strings, comments, test projects, and configuration files such as appsettings.json or Web.config (other rules cover passwords in configuration). URI-form strings (postgres://user:pass@host) are left to VNX-SEC-008, Azure AccountKey/SharedAccessKey values to the generated secret rules, and a plain password variable to VNX-259; a connection string spread over the lines of one multi-line verbatim literal is not seen.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-010/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["hardcoded-credentials", "secrets", "csharp"],
}

# Every reported shape has a password key followed by "=" (possibly after `"]`).
_gate_re := `(?i)(?:password|pwd)"?\]?\s*=`

# A password pair inside a connection-string literal: at the start of the
# literal or after a ; or , separator.
_pair_re := `(?i)(?:^|[;,])\s*(?:jet oledb:(?:new )?database )?(?:password|pwd)\s*=\s*([^;"]*)`

# Another connection-string key, at a literal or pair boundary.
_conn_key_re := `(?i)(?:^|[";,])\s*(?:server|data source|datasource|host|hostname|address|addr|network address|database|initial catalog|user id|userid|user|username|uid|port|provider|driver|dsn|ssl ?mode|ssl|encrypt|trusted_connection|integrated security|persist security info|abortconnect|allowadmin|connecttimeout|connect timeout|connection timeout|service name|protocol|pooling|charset|authsource|authentication)\s*=`

# host:port, at the start of a StackExchange.Redis configuration string.
_redis_endpoint_re := `^[A-Za-z0-9_.\-]+:\d{2,5},`

_sink_re := `\bnew\s+(?:[\w.]+\.)?\w*(?:Connection|ConnectionStringBuilder|MongoClient)\s*\(|\.Use(?:SqlServer|Npgsql|MySql|MySQL|Oracle|Sqlite|SQLite|Firebird|Jet)\s*\(|\bConnectionMultiplexer\.Connect(?:Async)?\s*\(|\bConnectionString\s*=`

# SQL text: a Password column compared or set, not a connection string.
_sql_re := `(?i)^\s*(?:select|update|insert|delete|merge|exec)\b|\b(?:where|set|values|and|or)\s`

_placeholder_re := `(?i)^(?:<.*>|\[.*|\$\(.*\)|%.*%|#\{.*\}#?|__.*__|\$\$.*\$\$|\$(?-i:[A-Z_][A-Z0-9_]*)|(?:replace|fill|set|update)[_\- ]?(?:me|this|it)|todo|tbd|fixme|\*+|x+|\.+|\?+|-+|@\w+|:\w+|my_?(?:password|passwd|pass|pwd|secret)|your[_\- ]?.*|enter[_\- ].*|insert[_\- ].*|(?:db_?|sql_?)?(?:password|passwd|pwd)|secret|changeme|change_?me|placeholder|redacted|none|null|empty)$`

_literal_value(v) if {
	t := trim(trim_space(v), `'"`)
	t != ""
	not contains(t, "{")
	not regex.match(_placeholder_re, t)
}

_literals(line) := [m[1] | some m in regex.find_all_string_submatch_n(`"((?:[^"\\]|\\.)*)"`, line, -1)]

# A literal password pair in one of the line's string literals.
_literal_pair(line) if {
	some lit in _literals(line)
	some m in regex.find_all_string_submatch_n(_pair_re, lit, -1)
	_literal_value(m[1])
	not regex.match(_sql_re, lit)
}

# The literal is recognisably a connection string.
_conn_context(lines, i, line) if {
	some lit in _literals(line)
	regex.match(_redis_endpoint_re, lit)
}

_conn_context(_, _, line) if regex.match(_sink_re, line)

_conn_context(lines, i, _) if {
	regex.match(_conn_key_re, helpers.code_window(lines, i, 3, 1))
}

# Objects that assemble a connection from properties: ADO.NET
# *ConnectionStringBuilder, StackExchange.Redis ConfigurationOptions and the
# RabbitMQ ConnectionFactory.
_builder_types := `(?:\w*ConnectionStringBuilder|ConfigurationOptions|ConnectionFactory)`

_builder_new_re := concat("", [`\bnew\s+(?:[\w.]+\.)?`, _builder_types, `\b`])

# Builder variables declared in the file.
_builder_vars(content) := {m[1] |
	regex.match(_builder_types, content)
	some re in [
		concat("", [`(?:\bvar|\b`, _builder_types, `)\s+([A-Za-z_]\w*)\s*=\s*(?:new\s+(?:[\w.]+\.)?`, _builder_types, `\b|ConfigurationOptions\.Parse\s*\()`]),
		concat("", [`\b`, _builder_types, `\s+([A-Za-z_]\w*)\s*=\s*new\s*\(`]),
	]
	some m in regex.find_all_string_submatch_n(re, content, -1)
}

# builder.Password = "literal";  /  builder["Password"] = "literal";
_builder_hit(_, _, line, bvars) if {
	some m in regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:\.\s*Password|\[\s*"(?i:password|pwd)"\s*\])\s*=\s*"((?:[^"\\]|\\.)*)"`, line, 1)
	m[1] in bvars
	_literal_value(m[2])
}

# new XConnectionStringBuilder { ..., Password = "literal", ... } on one line.
_builder_hit(_, _, line, _) if {
	regex.match(concat("", [_builder_new_re, `[^{]*\{`]), line)
	some m in regex.find_all_string_submatch_n(`[{,]\s*Password\s*=\s*"((?:[^"\\]|\\.)*)"`, line, -1)
	_literal_value(m[1])
}

# Password = "literal", inside an object initializer opened by a
# ConnectionStringBuilder a few lines above.
_builder_hit(lines, i, line, _) if {
	some m in regex.find_all_string_submatch_n(`^\s*Password\s*=\s*"((?:[^"\\]|\\.)*)"\s*,?\s*(?://.*)?$`, line, 1)
	_literal_value(m[1])
	i > 0
	some k in numbers.range(max([0, i - 12]), i - 1)
	regex.match(_builder_new_re, lines[k])
	not _left_initializer(lines, k, i)
}

_left_initializer(lines, k, i) if {
	k + 1 <= i - 1
	some m in helpers.span(k + 1, i - 1)
	_closes_or_opens(lines[m])
}

_closes_or_opens(l) if startswith(trim_space(l), "}")

_closes_or_opens(l) if regex.match(`\bnew\s+\w`, l)

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)[\w.]*\.(?:Unit|Integration|Functional|Acceptance|E2E)?Tests?/`, path)

_is_test(path) if regex.match(`(^|/)(?:Unit|Integration|Functional)Tests?/`, path)

_is_test(path) if regex.match(`(^|/|[a-z0-9])Tests?\.cs$`, path)

_hit(lines, i, line, _) if {
	_literal_pair(line)
	_conn_context(lines, i, line)
}

_hit(lines, i, line, bvars) if _builder_hit(lines, i, line, bvars)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	regex.match(_gate_re, content)
	not _is_test(path)
	bvars := _builder_vars(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate_re, line)
	not helpers.is_comment_line(line)
	_hit(lines, i, line, bvars)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded password in a connection string: anyone with the source or the compiled assembly has the database credentials, and they cannot be rotated without a release. Read the connection string from configuration backed by Azure Key Vault, AWS Secrets Manager or user secrets, or use Integrated Security / a managed identity",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
