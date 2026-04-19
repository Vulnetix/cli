// SPDX-License-Identifier: Apache-2.0
// VNX-1052 - Excessive Resource Usage

package vulnetix.rules.vnx_1052

import rego.v1
import vulnetix.helpers

metadata := {
	"id": "VNX-1052",
	"name": "Excessive Resource Usage",
	"description": "Detects excessive resource usage in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1052/".format(rid),
	"languages": ['go', 'java', 'node', 'python'],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1052],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ['weak-crypto'],
}

_skip(path) if helpers._should_skip(path)

_findings_core := {
		"python time.sleep",
		"node setTimeout",
		"go time.Sleep",
		"java Thread.sleep",
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
