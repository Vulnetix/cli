package vulnetix.rules.vnx_sec_019

import rego.v1

metadata := {
	"id": "VNX-SEC-019",
	"name": "GCP service account key",
	"description": "A Google Cloud service account key JSON file was found in source code. Service account keys grant broad access to GCP resources and should never be committed to version control.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-019/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["secrets", "gcp", "google-cloud", "service-account"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`"type"\s*:\s*"service_account"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GCP service account key found; use workload identity federation or store keys in a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
