// SPDX-License-Identifier: Apache-2.0
// VNX-1004 - Excessive Use of Resource

package vulnetix.rules.vnx_1004

import rego.v1
import vulnetix.helpers

metadata := {
	"id": "VNX-1004",
	"name": "Excessive Use of Resource",
	"description": "Detects excessive use of resource in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1004/".format(rid),
	"languages": ['go', 'java', 'node', 'php', 'python', 'ruby'],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1004],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ['weak-crypto'],
}

_skip(path) if helpers._should_skip(path)

_findings_core := {
		"python import hashlib",
		"node require",
		"go crypto/",
		"java java.security",
		"ruby Digest::",
		"php hash_",
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
