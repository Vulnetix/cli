# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_494

import rego.v1

metadata := {
	"id": "VNX-494",
	"name": "Download of code without integrity check",
	"description": "Downloading and immediately executing code from the internet without verifying a cryptographic checksum allows a compromised CDN, network attacker, or malicious maintainer to execute arbitrary code on every machine running the script.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-494/",
	"languages": ["python", "node", "bash"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [494],
	"capec": ["CAPEC-186"],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["supply-chain", "integrity", "remote-code-execution"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_patterns := {
	"curl | bash",
	"curl|bash",
	"curl | sh",
	"curl|sh",
	"wget | bash",
	"wget|bash",
	"wget | sh",
	"wget|sh",
	"curl -s | bash",
	"curl -fsSL | bash",
	"curl -fsSL | sh",
	"exec(urllib.urlopen(",
	"exec(requests.get(",
	"exec(urllib.request.urlopen(",
	"eval(urllib.urlopen(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _patterns
	contains(line, p)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Unsafe code download: '%v' downloads and executes code without integrity verification — verify checksums before execution", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
