package vulnetix.rules.vnx_docker_005

import rego.v1

metadata := {
	"id": "VNX-DOCKER-005",
	"name": "Dockerfile privileged container flag",
	"description": "A RUN, CMD, or ENTRYPOINT instruction uses --privileged or the compose/run flag is present in comments or inline shell. Running containers in privileged mode disables all security boundaries and grants full access to the host kernel. Remove --privileged and use specific Linux capabilities (--cap-add) only as needed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-005/",
	"languages": ["docker"],
	"severity": "critical",
	"level": "error",
	"kind": "oci",
	"cwe": [250],
	"capec": ["CAPEC-122"],
	"attack_technique": ["T1611"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["docker", "privilege-escalation", "container-escape"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, "Dockerfile")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "--privileged")
	finding := {
		"rule_id": metadata.id,
		"message": "Privileged container mode detected: --privileged disables all security boundaries — remove it and use specific --cap-add capabilities only as needed",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	regex.match(`docker-compose\.ya?ml$`, path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s*privileged\s*:\s*true`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Privileged container mode in docker-compose: privileged: true disables all container security — remove it and use specific cap_add capabilities instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
