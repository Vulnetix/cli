# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_59

import rego.v1

metadata := {
	"id": "VNX-59",
	"name": "Improper Link Resolution Before File Access ('Link Following')",
	"description": "Detects source patterns associated with CWE-59 (Improper Link Resolution Before File Access ('Link Following')). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-59/",
	"languages": ["c", "cpp", "go", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [59],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["symlink", "tocttou", "file", "cwe-59"],
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
	some _ext in {".c", ".cpp"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"open(", "fopen(", "access("}
	contains(line, _pat)
	not contains(line, "O_NOFOLLOW")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("C/C++ %s without O_NOFOLLOW — symlink following may allow attackers to redirect file access", [_pat]),
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
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "os.Readlink(")
	finding := {
		"rule_id": metadata.id,
		"message": "os.Readlink used; if path is user-controlled, validate that resolved target stays within allowed root",
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
	some _pat in {"os.readlink(", "os.path.realpath("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Python %s: ensure symlinks cannot redirect access outside permitted directories", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
