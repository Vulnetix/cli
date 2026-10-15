# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1072

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1072",
	"name": "Data Resource Access without Use of Connection Pooling",
	"description": "Java production code that opens database connections without a pool: java.sql.DriverManager.getConnection(...) (also split across lines as DriverManager / .getConnection(...), and as a bare getConnection(...) after import static java.sql.DriverManager.getConnection), construction of Spring's non-pooling DataSources (new DriverManagerDataSource, new SimpleDriverDataSource), and construction of a vendor non-pooling DataSource (PGSimpleDataSource, MysqlDataSource, MariaDbDataSource, SQLServerDataSource, OracleDataSource, H2 JdbcDataSource) in a file that configures no pool. Each opens a new physical connection for every request; under load this exhausts database connection slots and makes every request pay the connection handshake. Not reported: a DataSource or pool (HikariCP, DBCP, c3p0, a container JNDI DataSource) handing out connections with getConnection(), a vendor DataSource handed to a pool in the same file (HikariConfig.setDataSource), other DriverManager calls (registerDriver, getDriver), other receivers named like a driver manager, test sources, comments (including a trailing comment on a code line) and string literals. A short-lived command-line tool that legitimately opens one connection is still reported; suppress it there.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1072/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1072],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["connection-pooling", "cwe-1072"],
}

_sink_re := `(?:^|[^\w.]|java\.sql\.)DriverManager\s*\.\s*getConnection\s*\(|\bnew\s+(?:[\w.]+\.)?(?:DriverManagerDataSource|SimpleDriverDataSource)\s*\(`

# Vendor DataSource classes that open a new physical connection per
# getConnection(); they are fine as the target a pool wraps, so they count
# only in a file that configures no pool.
_vendor_re := `\bnew\s+(?:[\w.]+\.)?(?:PGSimpleDataSource|MysqlDataSource|MariaDbDataSource|SQLServerDataSource|OracleDataSource|JdbcDataSource)\s*\(`

_pool_re := `Hikari|BasicDataSource|ComboPooledDataSource|PoolingDataSource|PoolDataSource|ConnectionPool|\.setDataSource\s*\(|DataSourceProperties`

_gate_re := `DriverManager|DriverManagerDataSource|SimpleDriverDataSource|PGSimpleDataSource|MysqlDataSource|MariaDbDataSource|SQLServerDataSource|OracleDataSource|JdbcDataSource`

# The line with string literals blanked and a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

_sink(_, _, _, code) if regex.match(_sink_re, code)

_sink(content, _, _, code) if {
	regex.match(_vendor_re, code)
	not regex.match(_pool_re, content)
}

# `import static java.sql.DriverManager.getConnection;` then a bare
# getConnection(...) call (not a method declaration of that name).
_sink(content, _, _, code) if {
	regex.match(`(?m)^\s*import\s+static\s+java\.sql\.DriverManager\.(?:getConnection|\*)\s*;`, content)
	regex.match(`(?:^|[^\w.$])getConnection\s*\(`, code)
	not _declares_get_connection(code)
}

# `DriverManager` at the end of one line, `.getConnection(` on the next.
_sink(_, lines, i, code) if {
	regex.match(`^\s*\.\s*getConnection\s*\(`, code)
	i > 0
	regex.match(`(?:^|[^\w.]|java\.sql\.)DriverManager\s*$`, _code(lines[i - 1]))
}

_declares_get_connection(code) if {
	some m in regex.find_all_string_submatch_n(`([\w$>\]]+)\s+getConnection\s*\(`, code, -1)
	m[1] != "return"
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	code := _code(line)
	_sink(content, lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": "Database connection opened without a pool; obtain connections from a pooled DataSource (HikariCP, the container's JNDI pool) instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
