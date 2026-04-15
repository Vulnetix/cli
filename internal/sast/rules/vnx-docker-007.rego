package vulnetix.rules.vnx_docker_007

import rego.v1

metadata := {
	"id": "VNX-DOCKER-007",
	"name": "Dockerfile missing HEALTHCHECK instruction",
	"description": "The Dockerfile does not include a HEALTHCHECK instruction. Without a health check, container orchestrators cannot detect when an application is running but unhealthy (deadlocked, OOM, stuck). Add a HEALTHCHECK instruction that probes the application's readiness endpoint or process.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-007/",
	"languages": ["docker"],
	"severity": "low",
	"level": "warning",
	"kind": "open",
	"cwe": [754],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practice", "availability", "container"],
}

_has_healthcheck(lines) if {
	some _, line in lines
	regex.match(`^\s*HEALTHCHECK\s+`, line)
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, "Dockerfile")
	lines := split(input.file_contents[path], "\n")
	not _has_healthcheck(lines)
	# Only flag if there's a CMD or ENTRYPOINT (i.e., it's a runtime image, not a base/builder stage only)
	some _, l in lines
	regex.match(`^\s*(CMD|ENTRYPOINT)\s+`, l)
	finding := {
		"rule_id": metadata.id,
		"message": "Dockerfile is missing a HEALTHCHECK instruction — add HEALTHCHECK to allow orchestrators to detect unhealthy containers",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": "No HEALTHCHECK instruction found",
	}
}
