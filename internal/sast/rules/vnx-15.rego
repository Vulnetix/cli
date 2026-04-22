# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_15

import rego.v1

metadata := {
	"id": "VNX-15",
	"name": "External Control of System or Configuration Setting",
	"description": "Detects source patterns associated with CWE-15 (External Control of System or Configuration Setting). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-15/",
	"languages": ["go", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [15],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["config", "external-control", "injection", "cwe-15"],
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
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "req.")
	some _pat in {"os.Setenv(", "os.Getenv(", "viper.Set("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("External request data influences configuration setting via %s; validate and restrict to expected values", [_pat]),
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
	some _pat in {"os.environ[", "os.putenv("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Environment/config setting %s bound to request input; untrusted input must not alter runtime config", [_pat]),
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
	contains(line, "process.env[")
	some _pat in {"req.body", "req.query", "req.params"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Node.js process.env[...] set from request data; external control of configuration settings",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
