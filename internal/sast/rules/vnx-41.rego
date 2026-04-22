# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_41

import rego.v1

metadata := {
	"id": "VNX-41",
	"name": "Improper Resolution of Path Equivalence",
	"description": "Detects source patterns associated with CWE-41 (Improper Resolution of Path Equivalence). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-41/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [41],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["path-equivalence", "traversal", "cwe-41"],
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
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "..")
	contains(line, "request")
	some _pat in {"open(", "os.path.join("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Path built from request data and '..' component without canonicalisation — path equivalence risk",
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
	some _pat in {"path.join(", "fs.readFile(", "fs.readFileSync("}
	contains(line, _pat)
	not contains(line, "path.resolve")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Node file API %s called with request data without path.resolve canonicalisation", [_pat]),
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
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "request.getParameter")
	some _pat in {"new File(", "Paths.get("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Java %s with request parameter — resolve canonical path before use", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
