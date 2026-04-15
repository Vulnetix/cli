package vulnetix.rules.vnx_go_004

import rego.v1

metadata := {
	"id": "VNX-GO-004",
	"name": "TLS InsecureSkipVerify enabled",
	"description": "Setting InsecureSkipVerify to true in tls.Config disables TLS certificate validation, enabling man-in-the-middle attacks.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-GO-004",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["tls", "certificate", "mitm", "transport-security"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`InsecureSkipVerify\s*:\s*true`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "InsecureSkipVerify disables TLS certificate validation; remove it to enable proper verification",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
