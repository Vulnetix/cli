// SPDX-License-Identifier: Apache-2.0
// VNX-1021 - Improper Restriction of Rendered UI Layers

package vulnetix.rules.vnx_1021

import rego.v1
import vulnetix.helpers

metadata := {
	"id": "VNX-1021",
	"name": "Improper Restriction of Rendered UI Layers",
	"description": "Detects improper restriction of rendered ui layers in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1021/".format(rid),
	"languages": ['java', 'node', 'php', 'python', 'ruby'],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1021],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ['xss'],
}

_skip(path) if helpers._should_skip(path)

_findings_core := {
		"node createElement",
		"python render_template",
		"java innerHTML",
		"ruby erb",
		"php echo",
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
