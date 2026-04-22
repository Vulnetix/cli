# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_73

import rego.v1

metadata := {
	"id": "VNX-73",
	"name": "External Control of File Name or Path",
	"description": "Detects source patterns associated with CWE-73 (External Control of File Name or Path). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-73/",
	"languages": ["java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [73],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["path-traversal", "file", "injection", "cwe-73"],
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
	contains(line, "request.")
	some _pat in {"open(", "send_file(", "send_from_directory("}
	contains(line, _pat)
	not contains(line, "secure_filename")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Python file API %s bound to request data; apply werkzeug.utils.secure_filename or an allow-list", [_pat]),
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
	some _pat in {"new FileInputStream(", "new FileReader(", "Files.newInputStream("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Java %s with request parameter — normalize and constrain to an allow-listed directory", [_pat]),
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
	some _pat in {"fs.createReadStream(", "fs.readFile(", "res.sendFile("}
	contains(line, _pat)
	not contains(line, "path.resolve")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Node file API %s receives request data without path.resolve+prefix validation", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
