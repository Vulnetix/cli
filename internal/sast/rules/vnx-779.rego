# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_779

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-779",
	"name": "Logging of Excessive Data",
	"description": "Production code or configuration logs far more than an operator needs, burying the events that matter and filling the log with secrets: the root logger at DEBUG, TRACE or ALL, wire-level HTTP or SQL-parameter logging, or a whole environment dump. Reported: Python logging.basicConfig(level=DEBUG/\"DEBUG\"/10) (also split over lines) and root-logger setLevel(DEBUG), a dictConfig or Django LOGGING \"root\" entry at DEBUG (outside local/dev settings files), and http.client HTTPConnection.debuglevel set above 0; Java root-logger setLevel(Level.DEBUG/TRACE/ALL) and Configurator.setRootLevel of those; OkHttp HttpLoggingInterceptor.Level.BODY set in Java or Kotlin; logging.level.root=DEBUG/TRACE/ALL, log4j rootLogger and rootLogger.level of those, Hibernate bind-parameter loggers (org.hibernate.type, org.hibernate.orm.jdbc.bind, org.hibernate.SQL) at TRACE/DEBUG, spring.jpa.show-sql/hibernate.show_sql=true in .properties, the same root and show-sql keys in YAML, and <root level=\"debug|trace|all\"> in logback/log4j2 XML; and a log call whose argument is the whole environment (Python os.environ or dict(os.environ), JavaScript process.env or JSON.stringify(process.env), Java System.getenv() or System.getProperties()). Not reported: levels chosen by a debug/verbose flag or a ternary, code under if __name__ == '__main__', BuildConfig.DEBUG, dev/local/test profile files (application-dev.properties, logback-test.xml) and dev/local/test profile sections of a multi-document YAML file, named application loggers at DEBUG, single environment variables, key names or counts (Object.keys(process.env), System.getenv().size()), test files, comments and strings. Logging whole HTTP requests is VNX-15's concern; volume inside loops is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-779/",
	"languages": ["java", "kotlin", "python", "node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [779],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["excessive-logging", "debug-logging", "cwe-779"],
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(^|/)(conftest\.py|setupTests\.[jt]sx?|jest\.setup\.[jt]s)$`, path)

# Gradle/Kotlin Multiplatform source sets (src/jvmTest, src/androidTest, src/integrationTest).
_skip(path) if regex.match(`(^|/)src/\w*[tT]est\w*/|Tests?\.kts?$`, path)

# A debug/verbose switch on the line or the two code lines above.
_guarded(lines, i) if {
	window := helpers.code_window(lines, i, 2, 0)
	regex.match(`(?i)\b(?:if|when)\b[^\n]*(?:debug|verbose|quiet|test|dev|__main__|-v\b)`, window)
}

_guarded(lines, i) if regex.match(`(?i)\bif\b.*\belse\b|\?.*:|(?:debug|verbose)\s*(?:\?|&&|\bif\b)`, lines[i])

_msg_level := "Root logging at DEBUG/TRACE/ALL (or wire/SQL-parameter logging) in production floods the log and records secrets; log at INFO and raise individual loggers only while diagnosing"

_msg_env := "The whole environment is written to the log, burying useful events and recording every secret it holds; log the specific settings that matter"

# ── Python ───────────────────────────────────────────────────────────────

_py_debug := `(?:logging\.)?DEBUG\b|"DEBUG"|'DEBUG'|\b10\b`

_py_bad(lines, i, line) if {
	regex.match(`\blogging\.basicConfig\(`, _code(line))
	end := min([count(lines) - 1, i + 6])
	call := concat(" ", [lines[k] | some k in numbers.range(i, end)])
	m := regex.find_all_string_submatch_n(`basicConfig\(((?:[^()]|\([^()]*\))*)\)`, call, 1)
	count(m) > 0
	regex.match(concat("", [`\blevel\s*=\s*(?:`, _py_debug, `)\s*(?:,|$)`]), trim_space(m[0][1]))
}

_py_bad(_, _, line) if regex.match(concat("", [`\b(?:logging\.root|logging\.getLogger\(\s*\))\.setLevel\(\s*(?:`, _py_debug, `)\s*\)`]), line)

_py_bad(_, _, line) if regex.match(`\bHTTPConnection\.debuglevel\s*=\s*[1-9]`, _code(line))

# dictConfig / Django LOGGING: the "root" entry at DEBUG, on one line or as
# the "level" key of a multi-line "root": { ... } block.
_py_dict_root(_, _, line) if regex.match(`["']root["']\s*:\s*\{[^}]*["']level["']\s*:\s*(?:["']DEBUG["']|logging\.DEBUG\b)`, line)

_py_dict_root(lines, i, line) if {
	regex.match(`^\s*["']level["']\s*:\s*(?:["']DEBUG["']|logging\.DEBUG\b)`, line)
	ind := _indent(line)
	parents := [j |
		some j in numbers.range(max([0, i - 12]), i - 1)
		trim_space(lines[j]) != ""
		_indent(lines[j]) < ind
	]
	count(parents) > 0
	regex.match(`^\s*["']root["']\s*:\s*\{\s*$`, lines[max(parents)])
}

_py_dev_settings(path) if regex.match(`(?i)(?:^|/)(?:local_settings|settings[-_](?:dev|local|test|debug)\w*|(?:dev|local|development|debug|test)(?:_settings)?)\.py$`, path)

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not _skip(path)
	not _py_dev_settings(path)
	regex.match(`["']root["']\s*:\s*\{`, content)
	contains(content, "DEBUG")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "DEBUG")
	not helpers.is_comment_line(line)
	_py_dict_root(lines, i, line)
	not _guarded(lines, i)
	f := _finding(path, i, line, _msg_level)
}

_py_env(line) if {
	regex.match(`\b(?:logging|\w*log\w*|\w*LOG\w*)\.(?:debug|info|warning|warn|error|exception|critical|log)\(`, _code(line))
	regex.match(`(?:^|[^\w.])(?:dict\(\s*)?os\.environ(?:\s*\))?\s*(?:[,)}!]|$)`, _py_unquote_fields(line))
}

# Keep f-string fields, blank the literal text around them.
_py_unquote_fields(line) := concat(" ", [m[1] | some m in regex.find_all_string_submatch_n(`\{([^{}]*)\}`, line, -1)]) if regex.match(`\bf["']`, line)

_py_unquote_fields(line) := _code(line) if not regex.match(`\bf["']`, line)

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not _skip(path)
	regex.match(`basicConfig\(|\.setLevel\(|debuglevel|os\.environ`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`basicConfig|setLevel|debuglevel`, line)
	not helpers.is_comment_line(line)
	_py_bad(lines, i, line)
	not _guarded(lines, i)
	f := _finding(path, i, line, _msg_level)
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not _skip(path)
	contains(content, "os.environ")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "os.environ")
	not helpers.is_comment_line(line)
	_py_env(line)
	f := _finding(path, i, line, _msg_env)
}

# ── Java / Kotlin ────────────────────────────────────────────────────────

_jvm_ext := {".java", ".kt", ".kts"}

_java_root := `(?:getRootLogger\(\)|getLogger\(\s*(?:""|Logger\.ROOT_LOGGER_NAME|LogManager\.ROOT_LOGGER_NAME)\s*\))`

_jvm_level(line) if regex.match(concat("", [_java_root, `\s*\.setLevel\(\s*(?:[\w.]*\.)?Level\.(?:DEBUG|TRACE|ALL|FINEST|FINER)\s*\)`]), line)

_jvm_level(line) if regex.match(`\bConfigurator\.setRootLevel\(\s*(?:[\w.]*\.)?Level\.(?:DEBUG|TRACE|ALL)\s*\)`, line)

_jvm_level(line) if regex.match(`(?:\.setLevel\(|\blevel\s*=)\s*(?:HttpLoggingInterceptor\.)?Level\.BODY\b`, line)

_jvm_env(line) if {
	regex.match(`\b\w*(?:log|Log|LOG)\w*\.(?:trace|debug|info|warn|error|fatal)\(`, line)
	regex.match(`\bSystem\.(?:getenv|getProperties)\(\s*\)`, line)
	# a single key, a count or the key set reveals no values
	not regex.match(`\bSystem\.(?:getenv|getProperties)\(\s*\)\s*\.\s*(?:get|getProperty|containsKey|keySet|size|isEmpty)\b`, line)
}

findings contains f if {
	some path, content in input.file_contents
	some ext in _jvm_ext
	endswith(path, ext)
	not _skip(path)
	regex.match(`Level\.(?:DEBUG|TRACE|ALL|FINEST|FINER|BODY)|System\.(?:getenv|getProperties)\(\s*\)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Level\.|System\.get`, line)
	not helpers.is_comment_line(line)
	c := _code(line)
	some msg in _jvm_msgs(c)
	not _guarded(lines, i)
	not _debug_build(lines, i)
	f := _finding(path, i, line, msg)
}

_jvm_msgs(c) := {m |
	_jvm_level(c)
	m := _msg_level
} | {m |
	_jvm_env(c)
	m := _msg_env
}

_debug_build(lines, i) if regex.match(`BuildConfig\.DEBUG|isDebug|BuildType\.DEBUG`, helpers.code_window(lines, i, 2, 0))

# ── Logging configuration files ──────────────────────────────────────────

# dev, local and test profiles are where verbose logging belongs
_dev_profile(path) if regex.match(`(?i)(?:^|/)[^/]*[-_.](?:dev|develop|development|local|test|tests|debug)[-_.][^/]*$|(?i)(?:^|/)[^/]*-(?:dev|local|test|debug)\.\w+$`, path)

_props_bad(line) if regex.match(`^\s*(?:logging\.level\.root|log4j\.rootLogger|log4j\.rootCategory|rootLogger\.level|rootLogger)\s*[=:]\s*(?i:debug|trace|all)\s*(?:,|$)`, line)

_props_bad(line) if regex.match(`^\s*(?:logging\.level\.|log4j\.logger\.|logger\.\w+\.name\s*=\s*)?org\.hibernate\.(?:type(?:\.descriptor\.sql(?:\.BasicBinder)?)?|orm\.jdbc\.bind|SQL)\s*[=:]\s*(?i:trace|debug|all)\s*(?:,|$)`, line)

_props_bad(line) if regex.match(`^\s*(?:spring\.jpa\.show-sql|spring\.jpa\.properties\.hibernate\.show_sql|hibernate\.show_sql)\s*[=:]\s*true\s*$`, line)

_xml_bad(line) if regex.match(`<(?i:root)\b[^>]*\blevel\s*=\s*["'](?i:debug|trace|all)["']`, line)

_yaml_bad(lines, i) if {
	regex.match(`^\s+root\s*:\s*["']?(?i:debug|trace|all)["']?\s*$`, lines[i])
	_yaml_parent(lines, i) == "level"
}

_yaml_bad(lines, i) if {
	regex.match(`^\s+show-sql\s*:\s*true\s*$`, lines[i])
	_yaml_parent(lines, i) == "jpa"
}

_yaml_parent(lines, i) := key if {
	ind := _indent(lines[i])
	parents := [j |
		some j in numbers.range(max([0, i - 40]), i - 1)
		trim_space(lines[j]) != ""
		_indent(lines[j]) < ind
	]
	count(parents) > 0
	m := regex.find_all_string_submatch_n(`^\s*([\w.-]+)\s*:\s*$`, lines[max(parents)], 1)
	count(m) > 0
	key := m[0][1]
}

_indent(line) := count(line) - count(trim_left(line, " "))

_cfg_bad(path, _, _, line) if {
	endswith(path, ".properties")
	_props_bad(line)
}

_cfg_bad(path, _, _, line) if {
	endswith(path, ".xml")
	_xml_bad(line)
}

_cfg_bad(path, lines, i, _) if {
	regex.match(`\.ya?ml$`, path)
	_yaml_bad(lines, i)
	not _yaml_dev_document(lines, i)
}

# A multi-document Spring file: the `---` section the line is in activates
# a dev/local/test profile.
_yaml_dev_document(lines, i) if {
	seps := [j | some j in numbers.range(max([0, i - 200]), i); startswith(lines[j], "---")]
	count(seps) > 0
	start := max(seps)
	some k in numbers.range(start, i)
	regex.match(`(?i)^\s*(?:on-profile|profiles|spring\.profiles(?:\.active)?|spring\.config\.activate\.on-profile)\s*:\s*["']?(?:dev|develop|development|local|test|debug)\b`, lines[k])
}

findings contains f if {
	some path, content in input.file_contents
	regex.match(`\.(?:properties|xml|ya?ml)$`, path)
	not _skip(path)
	not _dev_profile(path)
	regex.match(`(?i)\b(?:debug|trace|all|true)\b`, content)
	regex.match(`(?i)root|hibernate|show-sql|show_sql`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)debug|trace|all|true`, line)
	not helpers.is_comment_line(line)
	_cfg_bad(path, lines, i, line)
	f := _finding(path, i, line, _msg_level)
}

# ── JavaScript / TypeScript: environment dumps ──────────────────────────

_js_ext := {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}

findings contains f if {
	some path, content in input.file_contents
	some ext in _js_ext
	endswith(path, ext)
	not _skip(path)
	contains(content, "process.env")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "process.env")
	not helpers.is_comment_line(line)
	regex.match(`\bconsole\.(?:log|info|debug|warn|error|dir|trace)\(|\b\w*(?:log|Log|LOG)\w*\.(?:debug|info|warn|error|trace|fatal|log|verbose|silly|http)\(`, line)
	# the key names (Object.keys(process.env)) reveal no values
	regex.match(`(?:^|[^\w.])process\.env\s*(?:[,)}]|$)`, _js_fields(regex.replace(line, `Object\.(?:keys|getOwnPropertyNames)\(\s*process\.env\s*\)`, "0")))
	f := _finding(path, i, line, _msg_env)
}

# Template-literal fields kept, other string text blanked.
_js_fields(line) := concat(" ", array.concat([_code(regex.replace(line, "`[^`]*`", "``"))], [m[1] | some m in regex.find_all_string_submatch_n(`\$\{((?:[^{}]|\{[^{}]*\})*)\}`, line, -1)]))
