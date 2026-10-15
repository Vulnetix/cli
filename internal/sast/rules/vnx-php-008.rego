package vulnetix.rules.vnx_php_008

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-008",
	"name": "PHP phpinfo exposure",
	"description": "A call to PHP's phpinfo() function (any argument, namespaced \\phpinfo() included) in production PHP code. Served over the web it discloses the PHP version and build, loaded modules, configuration, file paths, environment variables and request headers, which assist reconnaissance and can leak secrets. .php and .phtml files are scanned. Not reported: a call guarded within the five lines above by a positive CLI check (php_sapi_name() / PHP_SAPI === 'cli'), a loopback-client check ($_SERVER['REMOTE_ADDR'] === '127.0.0.1' or '::1'), or a debug or local-environment condition (APP_DEBUG, WP_DEBUG, app()->isLocal(), environment('local'), app.debug); a call after an early bail in the 80 lines above (if (PHP_SAPI !== 'cli') or a loopback check that exits, dies, returns or throws within four lines); methods or functions merely named phpinfo; test and fixture code; the name inside a heredoc or nowdoc, comments or string literals ('phpinfo' as data or a menu label). A PHP_SAPI !== 'cli' condition that wraps the call itself is not a guard and is reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-008/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [200],
	"capec": ["CAPEC-54"],
	"attack_technique": ["T1592"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["information-disclosure", "reconnaissance", "php"],
}

_call_re := `(^|[^\w$>:\\])\\?phpinfo\s*\(`

_no_strings(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

# A guard that keeps the output off a production web response: the call runs
# only on the CLI, in debug or local mode, or for a loopback client.
_guard_re := `(?i)(php_sapi_name\s*\(\s*\)|\bPHP_SAPI\b)\s*===?\s*["']cli|["']cli["']\s*===?\s*(php_sapi_name\s*\(\s*\)|\bPHP_SAPI\b)|\b(APP_DEBUG|WP_DEBUG|YII_DEBUG|DEBUG_MODE)\b|->\s*isLocal\s*\(|environment\s*\(\s*["']local|["']app\.debug["']`

_loopback_re := `REMOTE_ADDR.*(127\.0\.0\.1|::1)`

# An early bail above the call: if (PHP_SAPI !== 'cli') { exit; } or a
# loopback-only check that exits for every other client.
_bail_re := `(?i)(php_sapi_name\s*\(\s*\)|\bPHP_SAPI\b)\s*!==?\s*["']cli|["']cli["']\s*!==?\s*(php_sapi_name\s*\(\s*\)|\bPHP_SAPI\b)|REMOTE_ADDR.*(127\.0\.0\.1|::1)`

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`\.(php\d?|phtml)$`, path)
	contains(content, "phpinfo")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "phpinfo")
	not helpers.is_comment_line(line)
	code := _no_strings(line)
	regex.match(_call_re, code)
	not regex.match(`\bfunction\s+&?phpinfo\s*\(`, code)
	not _guarded(lines, i)
	not _in_heredoc(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "phpinfo() exposes the PHP build, configuration, paths and environment; remove it from code that can be served",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_guarded(lines, i) if {
	some k in numbers.range(max([0, i - 5]), i)
	not helpers.is_comment_line(lines[k])
	regex.match(_guard_re, lines[k])
}

# if ($_SERVER['REMOTE_ADDR'] === '127.0.0.1') with no negation.
_guarded(lines, i) if {
	some k in numbers.range(max([0, i - 5]), i)
	not helpers.is_comment_line(lines[k])
	regex.match(_loopback_re, lines[k])
	not contains(lines[k], "!")
}

_guarded(lines, i) if {
	some k in numbers.range(max([0, i - 80]), i - 1)
	k < i
	regex.match(_bail_re, lines[k])
	not helpers.is_comment_line(lines[k])
	some n in numbers.range(k, min([i - 1, k + 4]))
	regex.match(`\b(exit|die|return|throw)\b`, lines[n])
}

# Inside a heredoc or nowdoc: the call is text being written, not run.
_in_heredoc(lines, i) if {
	some k in numbers.range(max([0, i - 30]), i - 1)
	k < i
	m := regex.find_all_string_submatch_n(`<<<\s*["']?([A-Za-z_]\w*)["']?\s*$`, lines[k], 1)
	count(m) > 0
	close := concat("", [`^\s*`, m[0][1], `\b`])
	not _closed_between(lines, k, i, close)
}

_closed_between(lines, k, i, close) if {
	some n in numbers.range(k + 1, i)
	n > k
	regex.match(close, lines[n])
}
