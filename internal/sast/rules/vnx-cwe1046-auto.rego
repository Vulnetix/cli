// SPDX-License-Identifier: Apache-2.0
// VNX-1046 - Open Redirect to Untrusted Site

package vulnetix.rules.vnx_1046

import rego.v1
import vulnetix.helpers

metadata := {
	"id": "VNX-1046",
	"name": "Open Redirect to Untrusted Site",
	"description": "Detects open redirect to untrusted site in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1046/".format(rid),
	"languages": ['go', 'java', 'node', 'php', 'python'],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1046],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ['redirect'],
}

_skip(path) if helpers._should_skip(path)

_findings_core := {
		"python redirect",
		"node res.redirect",
		"go http.Redirect",
		"java sendRedirect",
		"php header",
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
