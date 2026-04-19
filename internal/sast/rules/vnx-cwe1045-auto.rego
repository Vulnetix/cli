# SPDX-License-Identifier: Apache-2.0
# VNX-1045 - File Upload without Type Restriction

package vulnetix.rules.vnx_1045

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-1045",
	"name": "File Upload without Type Restriction",
	"description": "Detects file upload without type restriction in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1045/",
	"languages": ['go', 'java', 'node', 'php', 'python'],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1045],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ['path-traversal'],
}

_skip(path) if helpers._should_skip(path)

_findings_core := {
		"python .save",
		"node upload",
		"go CreateFile",
		"java File.createTempFile",
		"php move_uploaded_file",
}

findings contains finding if {
	 some path in object.keys(helpers.input.file_contents)
	 not _skip(path)
	 lines := split(helpers.input.file_contents[path], "\n")
	 some i, line in lines
	 some indicator in _findings_core
	 contains(line, indicator)
	 not regex.match(`^\s*(//|/\*)`, line)
	 finding := helpers.generate_finding(
		"medium", "warning", metadata.id,
		sprintf("Detected pattern", []),
		helpers.input.artifact_uri,
		i + 1,
		line,
	 )
}
