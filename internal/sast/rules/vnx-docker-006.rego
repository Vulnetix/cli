package vulnetix.rules.vnx_docker_006

import rego.v1

metadata := {
	"id": "VNX-DOCKER-006",
	"name": "Dockerfile uses ADD instead of COPY for local files",
	"description": "ADD is used to copy local files or directories. ADD has additional hidden behavior: it automatically extracts tar archives and can fetch remote URLs without integrity verification. Use COPY for all local file operations to make intent explicit and avoid unintended behaviors.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-006/",
	"languages": ["docker"],
	"severity": "low",
	"level": "warning",
	"kind": "oci",
	"cwe": [829],
	"capec": ["CAPEC-185"],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practice", "container"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, "Dockerfile")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s*ADD\s+`, line)
	not regex.match(`^\s*ADD\s+https?://`, line)
	not regex.match(`^\s*#`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "ADD used for local file copy: ADD has hidden behaviors (tar extraction, remote URL fetch) — use COPY for local files to make intent explicit",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
