# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_502

import rego.v1

metadata := {
	"id": "VNX-502",
	"name": "Deserialization of untrusted data",
	"description": "Deserializing untrusted data can allow attackers to execute arbitrary code, escalate privileges, or cause denial of service. Avoid unsafe deserialization functions and always validate/sanitize data before deserializing.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-502/",
	"languages": ["python", "java", "php", "ruby", "node", "go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["deserialization", "rce", "injection"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_patterns := {
	"pickle.loads(",
	"pickle.load(",
	"marshal.loads(",
	"yaml.load(",
	"ObjectInputStream(",
	"readObject()",
	"XStream.fromXML(",
	"unserialize(",
	"Marshal.load(",
	"YAML.load(",
	"node-serialize",
	"gob.NewDecoder(",
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
		"message": sprintf("Unsafe deserialization pattern detected: '%v' — deserializing untrusted data can lead to remote code execution", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
