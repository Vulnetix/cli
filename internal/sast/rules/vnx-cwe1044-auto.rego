// SPDX-License-Identifier: Apache-2.0
// VNX-1044 - File Upload without Size Limit

package vulnetix.rules.vnx_1044

import rego.v1
import vulnetix.helpers

metadata := {
	"id": "VNX-1044",
	"name": "File Upload without Size Limit",
	"description": "Detects file upload without size limit in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1044/".format(rid),
	"languages": ['go', 'java', 'node', 'php', 'python'],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1044],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ['path-traversal'],
}

_skip(path) if helpers._should_skip(path)

_findings_core := {
		"python open",
		"node fs.readFile",
		"go os.Open",
		"java FileInputStream",
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
