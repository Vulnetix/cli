# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_778

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-778",
	"name": "Insufficient Logging",
	"description": "Production code or configuration switches logging or the audit trail off outright, so failed logins, access-control denials and attacks leave no record. Reported: Python logging.disable() with no level or a level of ERROR/CRITICAL (or 40/50 and above), a root, audit, security or auth logger set .disabled = True, and the root logger raised above CRITICAL; Java root-logger setLevel(Level.OFF) (log4j getRootLogger, java.util.logging getLogger(\"\"), Logger.ROOT_LOGGER_NAME), also through a variable assigned the root logger in the same file (root.setLevel(Level.OFF), Kotlin root.level = Level.OFF), Configurator.setRootLevel(Level.OFF), and LogManager.getLogManager().reset() in a file that installs no handler or configuration afterwards; Spring logging.level.root=OFF (or a security/audit logger) in .properties and root: OFF under logging.level in YAML, log4j rootLogger=OFF, and logback/log4j2 <root level=\"off\">; JavaScript/TypeScript winston createLogger({ silent: true }), logger.silent = true, pino({ level: 'silent' }) or pino({ enabled: false }), and console.log/info/warn/error replaced with an empty function; Terraform aws_cloudtrail with enable_logging = false. Not reported: switches guarded by a quiet/verbose/silent/test/debug condition on the line or just above (a CLI quiet mode), logging.disable(logging.NOTSET) (re-enabling), quietening a named third-party logger, `silent: true` outside a logger constructor, console methods emptied in browser code (a file that mounts React, Vue or Angular or touches document/window), test files and setup files, comments and string literals. Whether a specific security event is logged is not decidable line by line and is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-778/",
	"languages": ["python", "java", "kotlin", "node", "terraform"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [778],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["audit-logging", "logging-disabled", "cwe-778"],
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

# Test-support modules and Gradle test source sets (okhttp-testing-support,
# src/jvmTest, *TestRule.kt).
_skip(path) if regex.match(`(?i)(^|/)[\w-]*test(?:ing)?[-_](?:support|utils?|fixtures|kit|helpers?)[\w-]*/|(^|/)src/\w*[tT]est\w*/|(?:TestRule|Tests?|TestCase|Fixtures?)\.(?:kt|java)$`, path)

_skip(path) if regex.match(`(^|/)(conftest\.py|setupTests\.[jt]sx?|jest\.setup\.[jt]s|test_settings\.py|settings_test\.py)$`, path)

# A quiet/verbose/test switch on this line or the two code lines above.
_guarded(lines, i) if {
	window := helpers.code_window(lines, i, 2, 0)
	regex.match(`(?i)\b(?:if|unless|when)\b[^\n]*(?:quiet|silent|verbose|test|debug|mute|-q\b)`, window)
}

_guarded(lines, i) if regex.match(`(?i)(?:quiet|silent|verbose|testing|debug)\s*\?|if\s+.*(?:quiet|verbose|testing)`, lines[i])

_msg := "Logging is switched off outright: security events (failed logins, denials, attacks) will leave no record. Lower verbosity per logger instead of disabling the root or audit logger"

# ── Python ───────────────────────────────────────────────────────────────

_py_bad(line, _) if regex.match(`\blogging\.disable\(\s*\)`, line)

_py_bad(line, _) if regex.match(`\blogging\.disable\(\s*(?:level\s*=\s*)?(?:logging\.)?(?:CRITICAL|FATAL|ERROR|[4-9]\d|\d{3,})\b`, line)

_py_bad(line, _) if regex.match(`\blogging\.getLogger\(\s*(?:""|''|\)|(?:"|')(?:root|audit|security|auth)[\w.]*(?:"|'))\s*\)?\.disabled\s*=\s*True\b`, line)

_py_bad(line, _) if regex.match(`\blogging\.root\.disabled\s*=\s*True\b`, line)

_py_bad(line, _) if regex.match(`\b(?:logging\.root|logging\.getLogger\(\s*\))\.setLevel\(\s*(?:logging\.)?CRITICAL\s*\+|\b(?:logging\.root|logging\.getLogger\(\s*\))\.setLevel\(\s*(?:[6-9]\d|\d{3,})\s*\)`, line)

# `audit = logging.getLogger("audit")` ... `audit.disabled = True`
_py_bad(line, content) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\.disabled\s*=\s*True\b`, line, 1)
	count(m) > 0
	v := m[0][1]
	regex.match(concat("", [`(?m)^\s*`, v, `\s*=\s*logging\.getLogger\(\s*(?:\)|""|''|(?:"|')(?:root|audit|security|auth)[\w.]*(?:"|')\s*\))`]), content)
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not _skip(path)
	contains(content, "logging")
	regex.match(`logging\.disable\(|\.disabled\s*=\s*True|\.setLevel\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`disable|setLevel`, line)
	not helpers.is_comment_line(line)
	# the call is code, not text in a string; the logger name is read raw
	regex.match(`\blogging\.disable\(|\.disabled\s*=\s*True|\.setLevel\(`, _code(line))
	_py_bad(line, content)
	not _guarded(lines, i)
	f := _finding(path, i, line, _msg)
}

# ── Java ─────────────────────────────────────────────────────────────────

_java_root := `(?:getRootLogger\(\)|getLogger\(\s*(?:""|Logger\.ROOT_LOGGER_NAME|LogManager\.ROOT_LOGGER_NAME|"(?:ROOT|root)")\s*\)|getLogger\(\s*"[\w.]*(?:audit|security|Audit|Security)[\w.]*"\s*\))`

_java_bad(line, _) if regex.match(concat("", [_java_root, `\s*\.setLevel\(\s*(?:[\w.]*\.)?Level\.OFF\s*\)`]), line)

# `Logger root = Logger.getRootLogger();` ... `root.setLevel(Level.OFF);`
# (Kotlin: `root.level = Level.OFF`)
_java_bad(line, content) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:\.setLevel\(\s*|\.level\s*=\s*)(?:[\w.]*\.)?Level\.OFF\b`, line, 1)
	count(m) > 0
	v := m[0][1]
	regex.match(concat("", [`(?m)\b`, v, `\s*=\s*(?:\(\s*)?[\w.]*(?:getRootLogger\(\)|getLogger\(\s*(?:""|"(?:ROOT|root)"|[\w.]*ROOT_LOGGER_NAME)\s*\))`]), content)
}

_java_bad(line, _) if regex.match(`\bConfigurator\.setRootLevel\(\s*(?:[\w.]*\.)?Level\.OFF\s*\)`, line)

_java_bad(line, content) if {
	regex.match(`\bLogManager\.getLogManager\(\)\s*\.reset\(\)`, line)
	not regex.match(`\.addHandler\(|readConfiguration\(|updateConfiguration\(|SLF4JBridgeHandler`, content)
}

findings contains f if {
	some path, content in input.file_contents
	some ext in {".java", ".kt"}
	endswith(path, ext)
	not _skip(path)
	regex.match(`Level\.OFF|getLogManager\(\)\s*\.reset\(\)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Level\.OFF|\.reset\(\)`, line)
	not helpers.is_comment_line(line)
	regex.match(`Level\.OFF|\.reset\(\)`, _code(line))
	_java_bad(line, content)
	not _guarded(lines, i)
	f := _finding(path, i, line, _msg)
}

# ── Logging configuration files ──────────────────────────────────────────

_cfg_bad(path, line) if {
	endswith(path, ".properties")
	regex.match(`^\s*(?:logging\.level\.(?:root|[\w.]*(?:security|audit)[\w.]*)|log4j\.rootLogger|log4j\.rootCategory|rootLogger\.level|rootLogger)\s*[=:]\s*(?i:off)\s*(?:,|$)`, line)
}

_cfg_bad(path, line) if {
	some ext in {".xml"}
	endswith(path, ext)
	regex.match(`<(?i:root)\b[^>]*\blevel\s*=\s*["'](?i:off)["']`, line)
}

_cfg_bad(path, line) if {
	some ext in {".yml", ".yaml"}
	endswith(path, ext)
	regex.match(`^\s+root\s*:\s*["']?(?i:off)["']?\s*$`, line)
}

findings contains f if {
	some path, content in input.file_contents
	regex.match(`\.(?:properties|xml|ya?ml)$`, path)
	not _skip(path)
	regex.match(`(?i)[=:"']\s*off\b`, content)
	regex.match(`(?i)root`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)off`, line)
	not helpers.is_comment_line(line)
	_cfg_bad(path, line)
	_yaml_under_logging(path, lines, i)
	f := _finding(path, i, line, _msg)
}

# A YAML `root: OFF` must sit under logging.level (Spring) or a log config.
_yaml_under_logging(path, _, _) if not regex.match(`\.ya?ml$`, path)

_yaml_under_logging(path, lines, i) if {
	regex.match(`\.ya?ml$`, path)
	ind := _indent(lines[i])
	parents := [j |
		some j in numbers.range(max([0, i - 40]), i - 1)
		trim_space(lines[j]) != ""
		_indent(lines[j]) < ind
	]
	count(parents) > 0
	regex.match(`^\s*level\s*:\s*$`, lines[max(parents)])
}

_indent(line) := count(line) - count(trim_left(line, " "))

# ── JavaScript / TypeScript ──────────────────────────────────────────────

_js_ext := {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}

_js_bad(lines, i, c) if {
	regex.match(`^\s*silent\s*:\s*true\b`, c)
	window := helpers.code_window(lines, i, 6, 0)
	regex.match(`createLogger\s*\(|new\s+(?:winston\.)?Logger\s*\(|transports\.`, window)
}

_js_bad(_, _, c) if regex.match(`\bcreateLogger\s*\([^)]*\bsilent\s*:\s*true\b`, c)

_js_bad(_, _, c) if regex.match(`^\s*(?:this\.)?\w*(?:[lL]og|[lL]ogger)\w*\.silent\s*=\s*true\b`, c)

_js_bad(_, _, c) if regex.match(`^\s*(?:global(?:This)?\.|window\.)?console\.(?:log|info|warn|error)\s*=\s*(?:function\s*\w*\s*\(\s*\)\s*\{\s*\}|\(\s*\)\s*=>\s*(?:\{\s*\}|undefined|null|void 0)|noop\b|_\.noop\b)`, c)

_js_bad(lines, i, c) if {
	regex.match(`\blevel\s*:\s*'silent'|\blevel\s*:\s*"silent"|\benabled\s*:\s*false\b`, c)
	window := helpers.code_window(lines, i, 3, 0)
	regex.match(`\bpino\s*\(`, window)
}

findings contains f if {
	some path, content in input.file_contents
	some ext in _js_ext
	endswith(path, ext)
	not _skip(path)
	regex.match(`silent|console\.(?:log|info|warn|error)\s*=|enabled\s*:\s*false`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`silent|console\.|enabled`, line)
	not helpers.is_comment_line(line)
	_js_bad(lines, i, _js_code(line))
	not _browser_console(content, line)
	not _guarded(lines, i)
	f := _finding(path, i, line, _msg)
}

# Emptying console methods in browser code hides nothing from a server log.
_browser_console(content, line) if {
	contains(line, "console.")
	regex.match(`\bReactDOM\b|from\s+["']react["']|\bcreateApp\s*\(|new\s+Vue\s*\(|document\.getElementById\(|window\.addEventListener\(|\bplatformBrowserDynamic\b`, content)
}

# Strings blanked except the 'silent' level value the pino check reads.
_js_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'((?:\\.|[^'\\])*)'`, `'$1'`) if contains(line, "silent")

_js_code(line) := _code(line) if not contains(line, "silent")

# ── Terraform: CloudTrail with logging switched off ─────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".tf")
	contains(content, "aws_cloudtrail")
	contains(content, "enable_logging")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*enable_logging\s*=\s*false\b`, line)
	_in_cloudtrail(lines, i)
	f := _finding(path, i, line, "aws_cloudtrail enable_logging = false: the trail records no API activity")
}

_in_cloudtrail(lines, i) if {
	starts := [j | some j in numbers.range(max([0, i - 60]), i); startswith(lines[j], "resource ")]
	count(starts) > 0
	regex.match(`^resource\s+"aws_cloudtrail"`, lines[max(starts)])
}
