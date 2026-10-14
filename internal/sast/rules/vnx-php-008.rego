package vulnetix.rules.vnx_php_008

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-008",
	"name": "PHP phpinfo exposure",
	"description": "A call to PHP's phpinfo() function (any argument, namespaced \\phpinfo() included) in production PHP code. Served over the web it discloses the PHP version and build, loaded modules, configuration, file paths, environment variables and request headers, which assist reconnaissance and can leak secrets. Not reported: a call guarded within the five lines above by a CLI check (php_sapi_name() / PHP_SAPI compared with 'cli') or by a debug or local-environment condition (APP_DEBUG, WP_DEBUG, app()->isLocal(), environment('local'), app.debug), methods or functions merely named phpinfo, test and fixture code, and the name in comments or string literals ('phpinfo' as data or a menu label).",
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

# A guard that keeps the output off a production web response.
_guard_re := `(?i)(php_sapi_name\s*\(\s*\)|\bPHP_SAPI\b)\s*[!=]==?\s*["']cli|\b(APP_DEBUG|WP_DEBUG|YII_DEBUG|DEBUG_MODE)\b|->\s*isLocal\s*\(|environment\s*\(\s*["']local|["']app\.debug["']`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
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
