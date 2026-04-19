# SPDX-License-Identifier: Apache-2.0
# VNX-1043 - Non-Thread-Safe Lock

package vulnetix.rules.vnx_1043

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-1043",
	"name": "Non-Thread-Safe Lock",
	"description": "Detects non-thread-safe lock in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1043/",
	"languages": ['go', 'java', 'python'],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1043],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ['weak-crypto'],
}

_skip(path) if helpers._should_skip(path)

_findings_core := {
		"java synchronized",
		"python threading",
		"go Mutex",
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
