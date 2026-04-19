// SPDX-License-Identifier: Apache-2.0
// VNX-1048 - Sensitive Data in Referrer

package vulnetix.rules.vnx_1048

import rego.v1
import vulnetix.helpers

metadata := {
	"id": "VNX-1048",
	"name": "Sensitive Data in Referrer",
	"description": "Detects sensitive data in referrer in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1048/".format(rid),
	"languages": ['go', 'java', 'node', 'php', 'python'],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1048],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ['information-disclosure'],
}

_skip(path) if helpers._should_skip(path)

_findings_core := {
		"python requests.get",
		"node fetch",
		"go http.NewRequest",
		"java HttpURLConnection",
		"php curl",
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
