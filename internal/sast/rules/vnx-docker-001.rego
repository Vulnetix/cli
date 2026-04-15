package vulnetix.rules.vnx_docker_001

import rego.v1

metadata := {
	"id": "VNX-DOCKER-001",
	"name": "Dockerfile missing USER directive",
	"description": "Without a USER directive the container runs as root, expanding the blast radius of any container escape or application compromise.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-001/",
	"languages": ["docker"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [250],
	"capec": ["CAPEC-69"],
	"attack_technique": ["T1611"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "least-privilege", "container"],
}

_is_dockerfile(path) if endswith(path, "Dockerfile")
_is_dockerfile(path) if endswith(path, ".dockerfile")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_dockerfile(path)
	content := input.file_contents[path]
	contains(content, "FROM ")
	not regex.match(`(?i)^\s*USER\s+`, content)
	not _has_user_line(content)
	finding := {
		"rule_id": metadata.id,
		"message": "Dockerfile has no USER directive; container will run as root",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
	}
}

_has_user_line(content) if {
	lines := split(content, "\n")
	some line in lines
	regex.match(`^\s*USER\s+\S`, line)
}
