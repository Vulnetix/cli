package vulnetix.rules.vnx_docker_002

import rego.v1

metadata := {
	"id": "VNX-DOCKER-002",
	"name": "Dockerfile FROM :latest tag",
	"description": "Using :latest (or no tag) in a FROM instruction makes builds non-reproducible and can silently pull breaking or compromised images.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-002/",
	"languages": ["docker"],
	"severity": "medium",
	"level": "warning",
	"kind": "oci",
	"cwe": [829],
	"capec": ["CAPEC-185"],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "supply-chain", "pinning"],
}

_is_dockerfile(path) if endswith(path, "Dockerfile")
_is_dockerfile(path) if endswith(path, ".dockerfile")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_dockerfile(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s*FROM\s+`, line)
	not regex.match(`^\s*FROM\s+scratch`, line)
	_is_latest_or_untagged(line)
	finding := {
		"rule_id": metadata.id,
		"message": "FROM uses :latest or no tag; pin to a specific version for reproducible builds",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_is_latest_or_untagged(line) if {
	contains(line, ":latest")
}

_is_latest_or_untagged(line) if {
	not contains(line, ":")
	not contains(line, "@sha256:")
}
