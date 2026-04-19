# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_98

import rego.v1

metadata := {
	"id": "VNX-98",
	"name": "PHP Remote File Inclusion",
	"description": "PHP include/require statements use user-controlled data as the file path. An attacker can supply a remote URL or crafted path to load and execute arbitrary PHP code from an external server.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-98/",
	"languages": ["php"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [98],
	"capec": ["CAPEC-253"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["rfi", "file-inclusion", "php", "cwe-98"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# PHP include/require patterns with user input superglobals
_rfi_patterns := {
	"include($_GET",
	"include($_POST",
	"include($_REQUEST",
	"include($_COOKIE",
	"include($_SERVER",
	"include_once($_GET",
	"include_once($_POST",
	"include_once($_REQUEST",
	"include_once($_COOKIE",
	"require($_GET",
	"require($_POST",
	"require($_REQUEST",
	"require($_COOKIE",
	"require_once($_GET",
	"require_once($_POST",
	"require_once($_REQUEST",
	"require_once($_COOKIE",
}

# Variable-based include — flag include/require with a simple variable (may be user-tainted)
_variable_include_patterns := {
	"include($",
	"include_once($",
	"require($",
	"require_once($",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _rfi_patterns
	contains(line, pattern)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PHP Remote File Inclusion: '%s' allows an attacker to load arbitrary remote files. Never use user-supplied data in include/require paths; use a hardcoded allowlist of permitted filenames", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Variable include without direct superglobal — still worth flagging
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _variable_include_patterns
	contains(line, pattern)
	# Exclude direct superglobals — already caught above
	not contains(line, "$_GET")
	not contains(line, "$_POST")
	not contains(line, "$_REQUEST")
	not contains(line, "$_COOKIE")
	# Exclude static string constants like __DIR__
	not contains(line, "__DIR__")
	not contains(line, "__FILE__")
	not contains(line, "dirname(")
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PHP '%s' uses a variable as the file path; trace whether this variable can be influenced by user input and replace with a static allowlist", [pattern]),
		"artifact_uri": path,
		"severity": "high",
		"level": "warning",
		"start_line": i + 1,
		"snippet": line,
	}
}

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
_is_comment_line(line) if startswith(trim_space(line), "#")
