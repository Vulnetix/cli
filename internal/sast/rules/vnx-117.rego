# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_117

import rego.v1

metadata := {
	"id": "VNX-117",
	"name": "Improper Output Neutralization for Logs",
	"description": "Detects source patterns associated with CWE-117 (Improper Output Neutralization for Logs). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-117/",
	"languages": ["java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [117],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["log-injection", "crlf", "logging", "cwe-117"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")
_skip(path) if endswith(path, ".min.html")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
_is_comment_line(line) if startswith(trim_space(line), "#")
_is_comment_line(line) if startswith(trim_space(line), "--")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "request")
	some _pat in {"log.info(", "log.warn(", "log.error(", "logger.info(", "logger.warn(", "logger.error("}
	contains(line, _pat)
	not contains(line, "StringEscapeUtils")
	not contains(line, "escape")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Java logger %s receives request data without CRLF escaping — log injection risk", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "request.")
	some _pat in {"logger.info(", "logger.warning(", "logger.error(", "logger.debug(", "logging.info(", "logging.error("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Python logger %s prints request data directly — sanitize newlines/control chars", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	some _ext in {".js", ".ts"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "req.")
	some _pat in {"console.log(", "console.error(", "logger.info("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Node logger %s logs request data directly — strip CRLF before logging", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
