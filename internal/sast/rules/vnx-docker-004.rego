package vulnetix.rules.vnx_docker_004

import rego.v1

metadata := {
	"id": "VNX-DOCKER-004",
	"name": "Dockerfile ADD with remote URL",
	"description": "ADD with an HTTP/HTTPS URL downloads content without integrity verification. Use COPY with a separate RUN curl/wget that validates a checksum.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-004/",
	"languages": ["docker"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [829],
	"capec": ["CAPEC-185"],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "supply-chain", "integrity", "container"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, "Dockerfile")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s*ADD\s+https?://`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "ADD with a remote URL bypasses integrity verification; use COPY with a verified download instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
