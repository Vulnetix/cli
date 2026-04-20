# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1054

import rego.v1

metadata := {
	"id": "VNX-1054",
	"name": "Invokable Control Element with Excessive Volume of Commented-out Code",
	"description": "Large sections of commented-out code in security-critical functions indicate former implementations that may have been disabled rather than removed. These comments may contain sensitive logic, old credentials, deprecated security bypass patterns, or algorithms with known weaknesses that a developer could accidentally re-enable.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1054/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1054],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["commented-code", "dead-code", "code-quality", "secrets-in-comments", "cwe-1054"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Commented-out code patterns (comments containing code-like syntax)
_commented_code_indicators := {
	"// if ",
	"// for ",
	"// while ",
	"// return ",
	"// var ",
	"// let ",
	"// const ",
	"# if ",
	"# for ",
	"# while ",
	"# return ",
	"# import ",
	"// import ",
	"// require(",
	"// password",
	"// token",
	"// secret",
	"# password",
	"# token",
	"# secret",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _commented_code_indicators
	startswith(trim_space(line), p)
	# Check that there's a block of commented code (5+ consecutive comment lines)
	some j
	j > i
	j <= i + 5
	j < count(lines)
	_is_commented_line(lines[j])
	not _is_doc_comment(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Block of commented-out code starting with '%s'; commented-out code may contain old credentials, bypassed security checks, or deprecated logic. Remove it entirely rather than leaving it commented out", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_is_commented_line(line) if startswith(trim_space(line), "//")
_is_commented_line(line) if startswith(trim_space(line), "#")
_is_commented_line(line) if startswith(trim_space(line), "*")

_is_doc_comment(line) if contains(line, "TODO")
_is_doc_comment(line) if contains(line, "FIXME")
_is_doc_comment(line) if contains(line, "NOTE")
_is_doc_comment(line) if contains(line, "HACK")
_is_doc_comment(line) if contains(line, "@param")
_is_doc_comment(line) if contains(line, "@return")
