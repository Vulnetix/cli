# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_260

import rego.v1

metadata := {
	"id": "VNX-260",
	"name": "Password in Configuration File",
	"description": "Detects source patterns associated with CWE-260 (Password in Configuration File). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-260/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [260],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["password-in-config", "cwe-260"],
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
	some _ext in {".yaml", ".yml", ".ini", ".conf", ".json", ".xml", ".properties"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"password:", "password =", "password=", "\"password\"", "passwd:"}
	contains(line, _pat)
	not contains(line, "${")
	not contains(line, "ENV[")
	not contains(line, "vault")
	finding := {
		"rule_id": metadata.id,
		"message": "Password appears in configuration file — move to a secret store",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
